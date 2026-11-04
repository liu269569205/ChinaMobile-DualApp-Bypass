#!/usr/bin/env bash
# MCHook 构建脚本：编译 Zygisk 模块并打包成 Magisk 模块 zip
#
# 用法:
#   ./build.sh              编译 + 打包
#   ./build.sh compile      只编译
#   ./build.sh package      只打包（需已有 zygisk/arm64-v8a.so）
#
# 需要 Android NDK r26+，通过 ANDROID_NDK_HOME 指定，
# 或放在 ANDROID_HOME/ndk/<version> 下。

set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"

API="${API:-26}"
OUT_ZIP="${OUT_ZIP:-mchook.zip}"

# ---------- 定位 NDK ----------
# 找到某个 NDK 目录下可用的 clang++（Windows 下带 .cmd 后缀）
find_cxx() {
    local ndk="$1" tag="$2" pat="$3"
    local bin="$ndk/toolchains/llvm/prebuilt/$tag/bin"
    [ -d "$bin" ] || return 1
    local f
    for f in "$bin"/$pat; do
        [ -x "$f" ] && { echo "$f"; return 0; }
    done
    return 1
}

find_ndk() {
    local candidates=()
    [ -n "${ANDROID_NDK_HOME:-}" ] && candidates+=("$ANDROID_NDK_HOME")
    [ -n "${ANDROID_NDK_ROOT:-}" ] && candidates+=("$ANDROID_NDK_ROOT")
    local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
    if [ -n "$sdk" ] && [ -d "$sdk/ndk" ]; then
        # 版本号从高到低，逐个试
        while IFS= read -r d; do candidates+=("$sdk/ndk/$d"); done \
            < <(ls -1 "$sdk/ndk" 2>/dev/null | sort -Vr)
    fi
    [ ${#candidates[@]} -gt 0 ] || return 1
    printf '%s\n' "${candidates[@]}"
}

HOST_TAG=""
case "$(uname -s)" in
    Linux)   HOST_TAG=linux-x86_64 ;;
    Darwin)  HOST_TAG=darwin-x86_64 ;;
    MINGW*|MSYS*|CYGWIN*) HOST_TAG=windows-x86_64 ;;
    *) echo "错误: 不支持的主机平台 $(uname -s)"; exit 1 ;;
esac

NDK=""
CXX=""
while read -r cand; do
    [ -n "$cand" ] || continue
    # 优先精确匹配 API 级别，退化为任意 aarch64 clang++
    if CXX="$(find_cxx "$cand" "$HOST_TAG" "aarch64-linux-android${API}-clang++*")"; then
        NDK="$cand"; break
    fi
    if CXX="$(find_cxx "$cand" "$HOST_TAG" "aarch64-linux-android*-clang++*")"; then
        NDK="$cand"; break
    fi
done < <(find_ndk)

[ -n "$CXX" ] || { echo "错误: 找不到 Android NDK 编译器，请设置 ANDROID_NDK_HOME"; exit 1; }
echo "NDK: $NDK"
echo "CXX: $CXX"

# ---------- 编译 ----------
compile() {
    echo ">>> 编译 arm64-v8a"
    "$CXX" -shared -fPIC -O2 -std=c++17 \
        -I zygisk \
        -o zygisk/arm64-v8a.so \
        zygisk/module.cpp \
        -llog -static-libstdc++ -fvisibility=hidden
    echo "    产物: zygisk/arm64-v8a.so ($(wc -c < zygisk/arm64-v8a.so) 字节)"
}

# ---------- 打包 ----------
package() {
    [ -f zygisk/arm64-v8a.so ] || { echo "错误: 缺少 zygisk/arm64-v8a.so，请先编译"; exit 1; }

    rm -rf pkg
    mkdir -p pkg/zygisk
    cp module.prop pkg/
    cp zygisk/arm64-v8a.so pkg/zygisk/

    rm -f "$OUT_ZIP"
    if command -v zip >/dev/null 2>&1; then
        ( cd pkg && zip -qr "../$OUT_ZIP" . )
    else
        # 没有 zip 命令时用 python 打包（Windows/Git Bash 常见）
        python - "$OUT_ZIP" <<'PY'
import os, sys, zipfile
out = sys.argv[1]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk("pkg"):
        for f in files:
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, "pkg").replace("\\", "/"))
PY
    fi
    echo ">>> 打包完成: $OUT_ZIP"
    unzip -l "$OUT_ZIP"
}

case "${1:-all}" in
    compile) compile ;;
    package) package ;;
    all)     compile; package ;;
    *) echo "用法: $0 [compile|package|all]"; exit 1 ;;
esac
