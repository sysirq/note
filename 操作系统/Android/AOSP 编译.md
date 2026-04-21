# 编译 aosp_cf_x86_64_tv 遇到的坑

```
repo info
Manifest branch: android16-qpr2-release
Manifest merge branch: refs/heads/android-latest-release
Manifest groups: default,platform-linux
Superproject revision: None
```


### 0x00

```shell
[100% 280/280] analyzing Android.bp files and generating ninja file at out/soong/build.aosp_cf_x86_64_tv.ninja
FAILED: out/soong/build.aosp_cf_x86_64_tv.ninja
cd "$(dirname "out/host/linux-x86/bin/soong_build")" && BUILDER="$PWD/$(basename "out/host/linux-x86/bin/soong_build")" && cd / && env -i  "$BUILDER"     --top "$TO
P"     --soong_out "out/soong"     --out "out"     --soong_variables out/soong/soong.aosp_cf_x86_64_tv.variables -o out/soong/build.aosp_cf_x86_64_tv.ninja --kati_s
uffix -aosp_cf_x86_64_tv -l out/.module_paths/Android.bp.list --available_env out/soong/soong.environment.available --used_env out/soong/soong.environment.used.aosp
_cf_x86_64_tv.build Android.bp
error: platform_testing/libraries/sts-common-util/host-side/rootcanal/Android.bp:5:1: "sts-rootcanal-sidebins" depends on undefined module "android.hardware.bluetoo
th@1.1-service.sim".
Or did you mean ["android.hardware.bluetooth@1.1-service"]?
error: platform_testing/libraries/sts-common-util/host-side/rootcanal/Android.bp:5:1: "sts-rootcanal-sidebins" depends on undefined module "android.hardware.bluetoo
th@1.1-impl-sim".
Or did you mean ["android.hardware.bluetooth@1.0-impl" "android.hardware.bluetooth@1.0-impl-test" "androidx.wear.watchface_watchface-guava" "androidx.wear.watchface
_watchface-style" "com.android.apex.compressed.v2_original" "com.android.apex.cts.shim.v2_rebootless" "com.android.apex.cts.shim.v2_signed_bob" "com.android.apex.ct
s.shim.v3_rebootless" "com.android.apex.cts.shim.v3_signed_bob" "com.android.apex.vendor.foo.certificate" "com.android.bootanimation-file_contexts" "com.android.car
.framework-file_contexts" "com.android.cellbroadcast-file_contexts" "com.android.configinfrastrcture.init.rc" "com.android.crashrecovery-file_contexts" "com.android
.crashrecovery.flags-aconfig" "com.android.example-logging_parent.apex" "com.android.extensions.appfunctions.xml" "com.android.hardware.input-aconfig-java" "com.and
roid.hardware.keymint.trusty_tee" "com.android.hardware.security.authgraph" "com.android.healthfitness-file_contexts" "com.android.libraries.tv.tvsystem.stubs" "com
.android.media-mediatranscoding.32rc" "com.android.media.flags.editing-aconfig" "com.android.media.swcodec-file_contexts" "com.android.media.swcodec-ld.config.txt" 
"com.android.media.tv.remoteprovider.xml" "com.android.mediadrm.signer.api.test.28" "com.android.mediadrm.signer.api.test.29" "com.android.mediadrm.signer.api.test.
30" "com.android.mediadrm.signer.api.test.31" "com.android.mediadrm.signer.api.test.32" "com.android.mediadrm.signer.api.test.33" "com.android.mediadrm.signer.api.t
est.34" "com.android.mediadrm.signer.api.test.35" "com.android.mediadrm.signer.api.test.36" "com.android.mediaprovider-file_contexts" "com.android.microdroid.test.t
enant0.key" "com.android.microdroid.testservice-java" "com.android.microdroid.testservice-rust" "com.android.net.http.flags-aconfig-java" "com.android.nfc_extras.st
ubs.exportable" "com.android.ondevicepersonalization.key" "com.android.overlaytest.overlaid.pubkey" "com.android.sysprop.localization_public" "com.android.systemui.
retail.domain-impl" "com.android.telephonycore-file_contexts" "com.android.virt-bootclasspath-fragment" "com.android.wifi-bootclasspath-fragment" "com.android.windo
w.flags.window-aconfig" "libandroid_net_frameworktests_util_jni"]?
01:53:14 soong bootstrap failed with: exit status 1

#### failed to build some targets (01:26 (mm:ss)) ####
```

注释掉platform_testing/libraries/sts-common-util/host-side/rootcanal/Android.bp 中的sh_test块

### 0x01

```shell
m
============================================
PLATFORM_VERSION_CODENAME=Baklava
PLATFORM_VERSION=Baklava
TARGET_PRODUCT=aosp_cf_x86_64_tv
TARGET_BUILD_VARIANT=userdebug
TARGET_ARCH=x86_64
TARGET_ARCH_VARIANT=silvermont
TARGET_2ND_ARCH=x86
TARGET_2ND_ARCH_VARIANT=silvermont
HOST_OS=linux
HOST_OS_EXTRA=Linux-6.12.74+deb13+1-amd64-x86_64-Debian-GNU/Linux-13-(trixie)
HOST_CROSS_OS=windows
BUILD_ID=BP4A.251205.006
OUT_DIR=out
SOONG_ONLY=true
============================================
[100% 2/2] analyzing Android.bp files and generating ninja file at out/soong/build.aosp_cf_x86_64_tv.ninja
FAILED: out/soong/build.aosp_cf_x86_64_tv.ninja
cd "$(dirname "out/host/linux-x86/bin/soong_build")" && BUILDER="$PWD/$(basename "out/host/linux-x86/bin/soong_build")" && cd / && env -i  "$BUILDER"     --top "$TO
P"     --soong_out "out/soong"     --out "out"     --soong_variables out/soong/soong.aosp_cf_x86_64_tv.variables -o out/soong/build.aosp_cf_x86_64_tv.ninja --kati_s
uffix -aosp_cf_x86_64_tv -l out/.module_paths/Android.bp.list --available_env out/soong/soong.environment.available --used_env out/soong/soong.environment.used.aosp
_cf_x86_64_tv.build Android.bp
error: external/dng_sdk/Android.bp:101:1: "libdng_sdk" depends on undefined module "xmp_toolkit_sdk".
Or did you mean ["xmp_toolkit"]?
01:55:20 soong bootstrap failed with: exit status 1

#### failed to build some targets (38 seconds) ####
```

```sh
$ repo manifest | grep xmp_toolkit
<project name="platform/external/xmp_toolkit" path="external/xmp_toolkit" groups="pdk"/>
```

修改external/dng_sdk/Android.bp把："xmp_toolkit_sdk",改成："xmp_toolkit",


### 0x02

```shell
m
============================================
PLATFORM_VERSION_CODENAME=Baklava
PLATFORM_VERSION=Baklava
TARGET_PRODUCT=aosp_cf_x86_64_tv
TARGET_BUILD_VARIANT=userdebug
TARGET_ARCH=x86_64
TARGET_ARCH_VARIANT=silvermont
TARGET_2ND_ARCH=x86
TARGET_2ND_ARCH_VARIANT=silvermont
HOST_OS=linux
HOST_OS_EXTRA=Linux-6.12.74+deb13+1-amd64-x86_64-Debian-GNU/Linux-13-(trixie)
HOST_CROSS_OS=windows
BUILD_ID=BP4A.251205.006
OUT_DIR=out
SOONG_ONLY=true
============================================
[100% 2/2] analyzing Android.bp files and generating ninja file at out/soong/build.aosp_cf_x86_64_tv.ninja
FAILED: out/soong/build.aosp_cf_x86_64_tv.ninja
cd "$(dirname "out/host/linux-x86/bin/soong_build")" && BUILDER="$PWD/$(basename "out/host/linux-x86/bin/soong_build")" && cd / && env -i  "$BUILDER"     --top "$TO
P"     --soong_out "out/soong"     --out "out"     --soong_variables out/soong/soong.aosp_cf_x86_64_tv.variables -o out/soong/build.aosp_cf_x86_64_tv.ninja --kati_s
uffix -aosp_cf_x86_64_tv -l out/.module_paths/Android.bp.list --available_env out/soong/soong.environment.available --used_env out/soong/soong.environment.used.aosp
_cf_x86_64_tv.build Android.bp
error: tools/netsim/Android.bp:176:1: "lib-netsim" depends on undefined module "libbt-rootcanal".
Or did you mean ["clipboard_flags" "cts-root-readme" "libart-runtime" "libartd-runtime" "libboot_control" "libbootanimation" "librooted_path"]?
error: tools/netsim/Android.bp:176:1: "lib-netsim" depends on undefined module "libscriptedbeaconpayload-protos-lite".
Or did you mean ["//libcore/luni/src/test/androidsdk34" "//libcore/luni/src/test/annotations" "//libcore/luni/src/test/filesystems" "//libcore/luni/src/test/java9la
nguage" "_libberberis_guest_loader_tests_srcs" "lint_strict_updatability_checks_test"]?
02:00:11 soong bootstrap failed with: exit status 1

#### failed to build some targets (45 seconds) ####

```

# Mac 系统上编译

### 资料

Building AOSP on macOS

<https://dev.to/sriteja777/building-aosp-on-macos-2473>

Unknown directive .altmacro error happens when using android-ndk standalone toolchain

<https://stackoverflow.com/questions/47938599/unknown-directive-altmacro-error-happens-when-using-android-ndk-standalone-tool>
