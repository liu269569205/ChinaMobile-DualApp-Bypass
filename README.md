# MCHook

一个 Zygisk 模块：让 **中国移动**（`com.greenpoint.android.mc10086.activity`）在 **XSpace 双开空间（user 999）** 里正常启动，不再被壳的「应用多开提醒」弹窗 + 3 秒退出拦下。

> 纯 native 实现，不加载任何 Xposed / LSPosed 类。

---

## 背景

中国移动 APK 使用 **梆梆 SecNeo（`apkwrapper`）** 加固。逆向出它的环境检测链如下：

```
com.a.b.c.DeviceEnvironmentCheck.getCheckResult("appmo")
  └─ 反射 Class.forName("com.secneo.apkwrapper.H")
       └─ H.gha("appmo")          // public static native
            └─ 实现位于 libDexHelper.so（符号与字符串全表加密，动态注册）
                 └─ 返回 int，非 0 即判定有风险
                      └─ DECMsgDialog 弹「应用多开提醒」，等待 3 秒后退出
```

`gha(String key)` 的 key 包括 `emu` / `appmo` / `root` / `frida` / `hook` / `xposed` / `proxy` / `mitm` / `usb` / `signature` 等，返回 int 表示该维度的风险等级。

实测结论：

| 运行环境 | 进程 uid | 结果 |
|---|---|---|
| 主空间 | `u0_a553` | 正常 |
| XSpace 双开 | `u999_a553` | 弹「应用多开提醒」后退出 |
| 真实第二用户（`pm create-user`） | `u10_a553` | 同样弹窗后退出 |
| 卸掉 999 副本，只留 user 0 + 10 | `u10_a553` | **仍然退出** |

也就是说 `appmo` 的判据只有一条：**进程 uid 的用户部分 ≠ 0**，与装了几份、是不是 999 无关。

另外 `libdatajar.so` 中存在 `de.robv.android.xposed` 字符串，说明壳同时检测 Xposed 注入 —— 这就是 LSPosed 方案在**引导页**就崩的原因（比多开检测更早触发）。

## 原理

不去伪造 uid（会引发跨用户 `SecurityException`），也不去碰 ART 内部结构（Android 16 上极其脆弱），而是拦在 **JNI 动态注册** 这一层：

1. Zygisk 在本模块的 `postAppSpecialize` 阶段，把 `JNIEnv` 函数表里的 `RegisterNatives` 换成自己的实现（`mprotect` 放开函数表所在页的写权限后改指针）。
2. 壳随后调用 `RegisterNatives` 注册 `com.secneo.apkwrapper.H` 的方法时，我们检查方法名是否为 `gha`。
3. 命中则把该 `JNINativeMethod.fnPtr` 换成 `my_gha`，**原始函数指针先保存下来**。
4. `my_gha` 只在 key == `"appmo"` 时返回 `0`，其余 key 原样转发给壳的原始实现，把副作用降到最小。

整个链路零线程、零 Java 类加载、零 ART 内部结构依赖，所以不会出现「worker 线程卡在类初始化锁」或「hook ArtMethod 导致 ART 崩溃」这类问题。

### 为什么不用 Xposed

壳会扫 `de.robv.android.xposed`。任何 Xposed 类被加载进目标进程，壳在引导页就退出，根本轮不到多开检测。Zygisk 模块本身不引入这些符号。

## 编译

需要 Android NDK r26+：

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
./build.sh              # 编译 + 打包出 mchook.zip
./build.sh compile      # 只编译
```

或者手动：

```bash
aarch64-linux-android26-clang++ -shared -fPIC -O2 -std=c++17 \
    -I zygisk -o zygisk/arm64-v8a.so zygisk/module.cpp \
    -llog -static-libstdc++ -fvisibility=hidden
```

## 安装

要求：**Magisk / KernelSU + Zygisk（Zygisk Next 亦可）**，无需 LSPosed，无需勾选作用域。

1. 把 `mchook.zip` 刷入 Magisk / KernelSU。
2. 重启 zygote 或设备让模块加载（Zygisk 在开机时打开模块文件句柄，热重载需要重启 zygiskd）。
3. 正常打开双开空间里的中国移动即可。

## 验证

模块会在 logcat 打三条关键日志：

```bash
adb logcat -s MCHook
```

```
MCHook: target process matched: com.greenpoint.android.mc10086.activity
MCHook: RegisterNatives hooked, orig=0x73c9df82a0
MCHook: intercepted register of H.gha, orig=0x7337b3c7a4
```

看到 `intercepted register of H.gha` 就说明劫持成功。打开 App 后应能直接进入首页（`com.mc10086.cmcc.view.tabs.AppTabFragment`），不再出现 `DECMsgDialog`。

> ⚠️ 注意：**判断模块是否生效不能只看「App 没崩」**。Zygisk 守护进程启动之前 fork 出来的进程根本没有被注入，此时 App 可能因为别的原因暂时不崩，容易误判。请看上面的日志或对比进程启动时间。

## 已知限制

- **只针对 `appmo` 一个维度**：`root` / `frida` / `xposed` / `proxy` 等检测仍然正常工作。如果需要对目标 App 完全「隐身」，把 `my_gha` 里的 key 判断去掉即可（等于所有风险项都返回安全），但这会让壳的整套环境防护失效。
- **仅 arm64-v8a**：32 位需要在 `build.sh` 里增加 armv7 / x86_64 目标。
- 壳更新后如果 `H.gha` 改名或改签名，需要同步调整 `my_RegisterNatives` 里的匹配条件。
- 依赖 Zygisk 注入；部分设备上 Zygisk 与 LSPosed 共存时需注意模块加载顺序。

## 免责声明

本项目仅用于**个人设备上的兼容性研究**，目的是让已在主空间合法安装、正常使用的 App 能在系统自带的多开功能下继续使用。请勿用于绕过付费、风控或其他违反服务条款的场景。使用者需自行承担因使用本模块产生的全部后果。

## License

MIT
