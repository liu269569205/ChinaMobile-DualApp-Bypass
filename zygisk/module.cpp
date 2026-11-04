// MCHook - Zygisk module
// 目标: 中国移动 (com.greenpoint.android.mc10086.activity)
//
// 背景 (逆向结论):
//   壳 SecNeo 的环境检测链是:
//     com.a.b.c.DeviceEnvironmentCheck.getCheckResult(key)
//       -> 反射 Class.forName("com.secneo.apkwrapper.H")
//       -> H.gha(key)            // public static native, 实现在 libDexHelper.so
//       -> 返回 int, 非 0 即有风险
//       -> DECMsgDialog 弹 "应用多开提醒", 3 秒后退出
//   key 取值: emu / appmo / root / frida / hook / xposed / proxy / mitm / usb / signature ...
//   XSpace(999) 与真实第二用户都在 appmo 上命中 -> 判据是 "当前用户 != 0".
//
// 本模块做法:
//   不去伪造 uid, 也不去碰 ART 内部结构, 而是拦 JNI 的 RegisterNatives.
//   壳动态注册 H 的方法时, 我们把 "gha" 的函数指针换成自己的实现,
//   对 "appmo" 返回 0(无风险), 其余 key 原样转发给壳的原始实现.
//   全程不加载任何 Xposed 类, 因此壳的 de.robv.android.xposed 注入检测不会命中.

#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stdint.h>

#include "zygisk.hpp"

#define LOG_TAG "MCHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

static const char *TARGET_PKG = "com.greenpoint.android.mc10086.activity";
static const char *H_CLASS    = "com.secneo.apkwrapper.H";

static bool    g_isTarget = false;
static JavaVM *g_vm       = nullptr;

// 壳注册的原始 gha 实现
static void *g_origGha = nullptr;
// JNI 函数表里原始的 RegisterNatives
static jint (*g_origRegisterNatives)(JNIEnv *, jclass, const JNINativeMethod *, jint) = nullptr;
static volatile bool g_installed = false;

// 替换后的 gha: "appmo" 直接放行, 其他 key 转发原实现
static jint my_gha(JNIEnv *env, jclass clz, jstring key) {
    if (key != nullptr) {
        const char *k = env->GetStringUTFChars(key, nullptr);
        if (k != nullptr) {
            bool isAppmo = (strcmp(k, "appmo") == 0);
            env->ReleaseStringUTFChars(key, k);
            if (isAppmo) {
                LOGI("gha(appmo) -> 0 forced");
                return 0;
            }
        }
    }
    if (g_origGha != nullptr) {
        return ((jint (*)(JNIEnv *, jclass, jstring)) g_origGha)(env, clz, key);
    }
    return 0;
}

// 取 jclass 对应的类名, 失败返回 false
static bool classNameIs(JNIEnv *env, jclass clazz, const char *want) {
    bool hit = false;
    jclass clsClass = env->FindClass("java/lang/Class");
    if (clsClass == nullptr) { env->ExceptionClear(); return false; }
    jmethodID mGetName = env->GetMethodID(clsClass, "getName", "()Ljava/lang/String;");
    if (mGetName == nullptr) { env->ExceptionClear(); return false; }

    jstring jn = (jstring) env->CallObjectMethod(clazz, mGetName);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (jn != nullptr) {
        const char *nm = env->GetStringUTFChars(jn, nullptr);
        if (nm != nullptr) {
            hit = (strcmp(nm, want) == 0);
            env->ReleaseStringUTFChars(jn, nm);
        }
    }
    return hit;
}

// 我们的 RegisterNatives: 壳注册 H.gha 时把 fnPtr 换成 my_gha
static jint my_RegisterNatives(JNIEnv *env, jclass clazz,
                               const JNINativeMethod *methods, jint n) {
    if (clazz != nullptr && methods != nullptr && n > 0) {
        bool hasGha = false;
        for (jint i = 0; i < n; i++) {
            if (methods[i].name != nullptr && strcmp(methods[i].name, "gha") == 0) {
                hasGha = true;
                break;
            }
        }
        if (hasGha && classNameIs(env, clazz, H_CLASS)) {
            JNINativeMethod *m = const_cast<JNINativeMethod *>(methods);
            for (jint i = 0; i < n; i++) {
                if (m[i].name != nullptr && strcmp(m[i].name, "gha") == 0) {
                    if (g_origGha == nullptr) g_origGha = m[i].fnPtr;
                    m[i].fnPtr = (void *) my_gha;
                    LOGI("intercepted register of H.gha, orig=%p", g_origGha);
                }
            }
        }
    }
    return g_origRegisterNatives(env, clazz, methods, n);
}

// 把 JNIEnv 函数表里的 RegisterNatives 换成自己的
static bool installHook(JNIEnv *env) {
    if (g_installed) return true;
    if (env == nullptr || env->functions == nullptr) return false;

    JNINativeInterface *funcs = const_cast<JNINativeInterface *>(env->functions);

    long pg = sysconf(_SC_PAGESIZE);
    if (pg <= 0) pg = 4096;
    uintptr_t addr = (uintptr_t) &funcs->RegisterNatives;
    uintptr_t start = addr & ~(uintptr_t) (pg - 1);

    // JNI 函数表在只读段, 需要放开写权限
    if (mprotect((void *) start, (size_t) pg, PROT_READ | PROT_WRITE) != 0) {
        // 跨页时再试一次更大范围
        if (mprotect((void *) start, (size_t) pg * 2, PROT_READ | PROT_WRITE) != 0) {
            LOGE("mprotect failed: %s", strerror(errno));
            return false;
        }
    }

    g_origRegisterNatives = funcs->RegisterNatives;
    funcs->RegisterNatives = my_RegisterNatives;
    g_installed = true;
    LOGI("RegisterNatives hooked, orig=%p", (void *) g_origRegisterNatives);
    return true;
}

class MCHookModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        (void) api;
        env->GetJavaVM(&g_vm);
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        if (args->nice_name == nullptr) return;
        JNIEnv *env = nullptr;
        if (g_vm == nullptr || g_vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
            return;
        }
        const char *nice = env->GetStringUTFChars(args->nice_name, nullptr);
        if (nice != nullptr) {
            g_isTarget = (strncmp(nice, TARGET_PKG, strlen(TARGET_PKG)) == 0);
            if (g_isTarget) LOGI("target process matched: %s", nice);
            env->ReleaseStringUTFChars(args->nice_name, nice);
        }
    }

    void postAppSpecialize(const AppSpecializeArgs *) override {
        if (!g_isTarget) return;
        JNIEnv *env = nullptr;
        if (g_vm == nullptr || g_vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
            LOGE("postAppSpecialize: no JNIEnv");
            return;
        }
        installHook(env);
    }
};

REGISTER_ZYGISK_MODULE(MCHookModule)
