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


# debian13 编译aosp_cf_x86_64_tv 

```
repo info
Manifest branch: refs/tags/android-11.0.0_r48
Manifest merge branch: refs/heads/android-11.0.0_r48
Manifest groups: default,platform-linux
Superproject revision: None
```

库下载：

- libncurses5_6.4-4_amd64.deb  
- libtinfo5_6.4-4_amd64.deb

地址：

https://ftp.debian.org/debian/pool/main/n/ncurses/

### 0x00

```sh
============================================
PLATFORM_VERSION_CODENAME=REL
PLATFORM_VERSION=11
TARGET_PRODUCT=aosp_cf_x86_tv
TARGET_BUILD_VARIANT=userdebug
TARGET_BUILD_TYPE=release
TARGET_ARCH=x86
TARGET_ARCH_VARIANT=x86
HOST_ARCH=x86_64
HOST_2ND_ARCH=x86
HOST_OS=linux
HOST_OS_EXTRA=Linux-6.12.74+deb13+1-amd64-x86_64-Debian-GNU/Linux-13-(trixie)
HOST_CROSS_OS=windows
HOST_CROSS_ARCH=x86
HOST_CROSS_2ND_ARCH=x86_64
HOST_BUILD_TYPE=release
BUILD_ID=RD2A.211001.002
OUT_DIR=out
PRODUCT_SOONG_NAMESPACES=device/generic/goldfish-opengl hardware/google/camera hardware/google/camera/devices/EmulatedCamera external/mesa3d
============================================
[  0% 39/7266] //frameworks/ml/nn/apex:com.android.neuralnetworks apex (image) [common]
FAILED: out/soong/.intermediates/frameworks/ml/nn/apex/com.android.neuralnetworks/android_common_com.android.neuralnetworks_image/com.android.neuralnetworks.apex.un
signed
rm -rf out/soong/.intermediates/frameworks/ml/nn/apex/com.android.neuralnetworks/android_common_com.android.neuralnetworks_image/image.apex && mkdir -p out/soong/.i
ntermediates/frameworks/ml/nn/apex/com.android.neuralnetworks/android_common_com.android.neuralnetworks_image/image.apex && (. out/soong/.intermediates/frameworks/m
l/nn/apex/com.android.neuralnetworks/android_common_com.android.neuralnetworks_image/com.android.neuralnetworks.apex.unsigned.copy_commands) && APEXER_TOOL_PATH=out
/soong/host/linux-x86/bin:prebuilts/sdk/tools/linux/bin out/soong/host/linux-x86/bin/apexer --force --manifest out/soong/.intermediates/frameworks/ml/nn/apex/com.an
droid.neuralnetworks/android_common_com.android.neuralnetworks_image/apex_manifest.pb --file_contexts system/sepolicy/apex/com.android.neuralnetworks-file_contexts 
--canned_fs_config out/soong/.intermediates/frameworks/ml/nn/apex/com.android.neuralnetworks/android_common_com.android.neuralnetworks_image/canned_fs_config --incl
ude_build_info --payload_type image --key frameworks/ml/nn/apex/com.android.neuralnetworks.pem --pubkey frameworks/ml/nn/apex/com.android.neuralnetworks.avbpubkey -
-android_manifest frameworks/ml/nn/apex/AndroidManifest.xml --target_sdk_version 30 --min_sdk_version 30 --assets_dir out/soong/.intermediates/frameworks/ml/nn/apex
/com.android.neuralnetworks/android_common_com.android.neuralnetworks_image/NOTICE --no_hashtree out/soong/.intermediates/frameworks/ml/nn/apex/com.android.neuralne
tworks/android_common_com.android.neuralnetworks_image/image.apex out/soong/.intermediates/frameworks/ml/nn/apex/com.android.neuralnetworks/android_common_com.andro
id.neuralnetworks_image/com.android.neuralnetworks.apex.unsigned 
mke2fs 1.45.4 (23-Sep-2019)
Creating regular file /home/sysirq/aosp/out/soong/.temp/tmpkmkfGA/content/apex_payload.img
Invalid filesystem option set: has_journal,extent,huge_file,flex_bg,metadata_csum,metadata_csum_seed,64bit,dir_nlink,extra_isize,orphan_file
Traceback (most recent call last):
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/__main__.py", line 12, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 708, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 701, in main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 502, in CreateApex
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 200, in RunCommand
AssertionError: Failed to execute: out/soong/host/linux-x86/bin/mke2fs -O ^has_journal -b 4096 -m 0 -t ext4 -I 256 -N 14 -U 7d1522e1-9dfa-5edb-a43e-98e3a4d20250 -E 
hash_seed=7d1522e1-9dfa-5edb-a43e-98e3a4d20250 /home/sysirq/aosp/out/soong/.temp/tmpkmkfGA/content/apex_payload.img 20M
[  0% 40/7266] //packages/modules/DnsResolver/apex:com.android.resolv apex (image) [common]
FAILED: out/soong/.intermediates/packages/modules/DnsResolver/apex/com.android.resolv/android_common_cfi_com.android.resolv_image/com.android.resolv.apex.unsigned
rm -rf out/soong/.intermediates/packages/modules/DnsResolver/apex/com.android.resolv/android_common_cfi_com.android.resolv_image/image.apex && mkdir -p out/soong/.i
ntermediates/packages/modules/DnsResolver/apex/com.android.resolv/android_common_cfi_com.android.resolv_image/image.apex && (. out/soong/.intermediates/packages/mod
ules/DnsResolver/apex/com.android.resolv/android_common_cfi_com.android.resolv_image/com.android.resolv.apex.unsigned.copy_commands) && APEXER_TOOL_PATH=out/soong/h
ost/linux-x86/bin:prebuilts/sdk/tools/linux/bin out/soong/host/linux-x86/bin/apexer --force --manifest out/soong/.intermediates/packages/modules/DnsResolver/apex/co
m.android.resolv/android_common_cfi_com.android.resolv_image/apex_manifest.pb --file_contexts system/sepolicy/apex/com.android.resolv-file_contexts --canned_fs_conf
ig out/soong/.intermediates/packages/modules/DnsResolver/apex/com.android.resolv/android_common_cfi_com.android.resolv_image/canned_fs_config --include_build_info -
-payload_type image --key packages/modules/DnsResolver/apex/com.android.resolv.pem --pubkey packages/modules/DnsResolver/apex/com.android.resolv.avbpubkey --android
_manifest packages/modules/DnsResolver/apex/AndroidManifest.xml --target_sdk_version 30 --min_sdk_version 29 --assets_dir out/soong/.intermediates/packages/modules/
DnsResolver/apex/com.android.resolv/android_common_cfi_com.android.resolv_image/NOTICE --manifest_json out/soong/.intermediates/packages/modules/DnsResolver/apex/co
m.android.resolv/android_common_cfi_com.android.resolv_image/apex_manifest.json out/soong/.intermediates/packages/modules/DnsResolver/apex/com.android.resolv/androi
d_common_cfi_com.android.resolv_image/image.apex out/soong/.intermediates/packages/modules/DnsResolver/apex/com.android.resolv/android_common_cfi_com.android.resolv
_image/com.android.resolv.apex.unsigned 
mke2fs 1.45.4 (23-Sep-2019)
Creating regular file /home/sysirq/aosp/out/soong/.temp/tmpP250Wc/content/apex_payload.img
Invalid filesystem option set: has_journal,extent,huge_file,flex_bg,metadata_csum,metadata_csum_seed,64bit,dir_nlink,extra_isize,orphan_file
Traceback (most recent call last):
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/__main__.py", line 12, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 708, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 701, in main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 502, in CreateApex
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 200, in RunCommand
AssertionError: Failed to execute: out/soong/host/linux-x86/bin/mke2fs -O ^has_journal -b 4096 -m 0 -t ext4 -I 256 -N 17 -U 7d1522e1-9dfa-5edb-a43e-98e3a4d20250 -E 
hash_seed=7d1522e1-9dfa-5edb-a43e-98e3a4d20250 /home/sysirq/aosp/out/soong/.temp/tmpP250Wc/content/apex_payload.img 18M
[  0% 43/7266] //system/timezone/apex:com.android.tzdata apex (image) [common]
FAILED: out/soong/.intermediates/system/timezone/apex/com.android.tzdata/android_common_com.android.tzdata_image/com.android.tzdata.apex.unsigned
rm -rf out/soong/.intermediates/system/timezone/apex/com.android.tzdata/android_common_com.android.tzdata_image/image.apex && mkdir -p out/soong/.intermediates/syst
em/timezone/apex/com.android.tzdata/android_common_com.android.tzdata_image/image.apex && (. out/soong/.intermediates/system/timezone/apex/com.android.tzdata/androi
d_common_com.android.tzdata_image/com.android.tzdata.apex.unsigned.copy_commands) && APEXER_TOOL_PATH=out/soong/host/linux-x86/bin:prebuilts/sdk/tools/linux/bin out
/soong/host/linux-x86/bin/apexer --force --manifest out/soong/.intermediates/system/timezone/apex/com.android.tzdata/android_common_com.android.tzdata_image/apex_ma
nifest.pb --file_contexts system/sepolicy/apex/com.android.tzdata-file_contexts --canned_fs_config out/soong/.intermediates/system/timezone/apex/com.android.tzdata/
android_common_com.android.tzdata_image/canned_fs_config --include_build_info --payload_type image --key system/timezone/apex/com.android.tzdata.pem --pubkey system
/timezone/apex/com.android.tzdata.avbpubkey --android_manifest system/timezone/apex/AndroidManifest.xml --target_sdk_version 30 --min_sdk_version 30 --no_hashtree o
ut/soong/.intermediates/system/timezone/apex/com.android.tzdata/android_common_com.android.tzdata_image/image.apex out/soong/.intermediates/system/timezone/apex/com
.android.tzdata/android_common_com.android.tzdata_image/com.android.tzdata.apex.unsigned 
mke2fs 1.45.4 (23-Sep-2019)
Creating regular file /home/sysirq/aosp/out/soong/.temp/tmpdjtEWA/content/apex_payload.img
Invalid filesystem option set: has_journal,extent,huge_file,flex_bg,metadata_csum,metadata_csum_seed,64bit,dir_nlink,extra_isize,orphan_file
Traceback (most recent call last):
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/__main__.py", line 12, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 708, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 701, in main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 502, in CreateApex
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 200, in RunCommand
AssertionError: Failed to execute: out/soong/host/linux-x86/bin/mke2fs -O ^has_journal -b 4096 -m 0 -t ext4 -I 256 -N 20 -U 7d1522e1-9dfa-5edb-a43e-98e3a4d20250 -E 
hash_seed=7d1522e1-9dfa-5edb-a43e-98e3a4d20250 /home/sysirq/aosp/out/soong/.temp/tmpdjtEWA/content/apex_payload.img 16M
[  0% 44/7266] //libcore/apex:com.android.i18n apex (image) [common]
FAILED: out/soong/.intermediates/libcore/apex/com.android.i18n/android_common_com.android.i18n_image/com.android.i18n.apex.unsigned
rm -rf out/soong/.intermediates/libcore/apex/com.android.i18n/android_common_com.android.i18n_image/image.apex && mkdir -p out/soong/.intermediates/libcore/apex/com
.android.i18n/android_common_com.android.i18n_image/image.apex && (. out/soong/.intermediates/libcore/apex/com.android.i18n/android_common_com.android.i18n_image/co
m.android.i18n.apex.unsigned.copy_commands) && APEXER_TOOL_PATH=out/soong/host/linux-x86/bin:prebuilts/sdk/tools/linux/bin out/soong/host/linux-x86/bin/apexer --for
ce --manifest out/soong/.intermediates/libcore/apex/com.android.i18n/android_common_com.android.i18n_image/apex_manifest.pb --file_contexts system/sepolicy/apex/com
.android.i18n-file_contexts --canned_fs_config out/soong/.intermediates/libcore/apex/com.android.i18n/android_common_com.android.i18n_image/canned_fs_config --inclu
de_build_info --payload_type image --key libcore/apex/com.android.i18n.pem --pubkey libcore/apex/com.android.i18n.avbpubkey --target_sdk_version 30 --min_sdk_versio
n 30 --no_hashtree out/soong/.intermediates/libcore/apex/com.android.i18n/android_common_com.android.i18n_image/image.apex out/soong/.intermediates/libcore/apex/com
.android.i18n/android_common_com.android.i18n_image/com.android.i18n.apex.unsigned 
mke2fs 1.45.4 (23-Sep-2019)
Creating regular file /home/sysirq/aosp/out/soong/.temp/tmpDQw0WF/content/apex_payload.img
Invalid filesystem option set: has_journal,extent,huge_file,flex_bg,metadata_csum,metadata_csum_seed,64bit,dir_nlink,extra_isize,orphan_file
Traceback (most recent call last):
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/__main__.py", line 12, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 708, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 701, in main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 502, in CreateApex
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 200, in RunCommand
AssertionError: Failed to execute: out/soong/host/linux-x86/bin/mke2fs -O ^has_journal -b 4096 -m 0 -t ext4 -I 256 -N 15 -U 7d1522e1-9dfa-5edb-a43e-98e3a4d20250 -E 
hash_seed=7d1522e1-9dfa-5edb-a43e-98e3a4d20250 /home/sysirq/aosp/out/soong/.temp/tmpDQw0WF/content/apex_payload.img 40M
[  0% 48/7266] //bionic/apex:com.android.runtime apex (image) [common]
FAILED: out/soong/.intermediates/bionic/apex/com.android.runtime/android_common_com.android.runtime_image/com.android.runtime.apex.unsigned
rm -rf out/soong/.intermediates/bionic/apex/com.android.runtime/android_common_com.android.runtime_image/image.apex && mkdir -p out/soong/.intermediates/bionic/apex
/com.android.runtime/android_common_com.android.runtime_image/image.apex && (. out/soong/.intermediates/bionic/apex/com.android.runtime/android_common_com.android.r
untime_image/com.android.runtime.apex.unsigned.copy_commands) && APEXER_TOOL_PATH=out/soong/host/linux-x86/bin:prebuilts/sdk/tools/linux/bin out/soong/host/linux-x8
6/bin/apexer --force --manifest out/soong/.intermediates/bionic/apex/com.android.runtime/android_common_com.android.runtime_image/apex_manifest.pb --file_contexts s
ystem/sepolicy/apex/com.android.runtime-file_contexts --canned_fs_config out/soong/.intermediates/bionic/apex/com.android.runtime/android_common_com.android.runtime
_image/canned_fs_config --include_build_info --payload_type image --key bionic/apex/com.android.runtime.pem --pubkey bionic/apex/com.android.runtime.avbpubkey --tar
get_sdk_version 30 --min_sdk_version 30 --assets_dir out/soong/.intermediates/bionic/apex/com.android.runtime/android_common_com.android.runtime_image/NOTICE --no_h
ashtree out/soong/.intermediates/bionic/apex/com.android.runtime/android_common_com.android.runtime_image/image.apex out/soong/.intermediates/bionic/apex/com.androi
d.runtime/android_common_com.android.runtime_image/com.android.runtime.apex.unsigned 
mke2fs 1.45.4 (23-Sep-2019)
Creating regular file /home/sysirq/aosp/out/soong/.temp/tmpr9inSx/content/apex_payload.img
Invalid filesystem option set: has_journal,extent,huge_file,flex_bg,metadata_csum,metadata_csum_seed,64bit,dir_nlink,extra_isize,orphan_file
Traceback (most recent call last):
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/__main__.py", line 12, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 708, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 701, in main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 502, in CreateApex
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 200, in RunCommand
AssertionError: Failed to execute: out/soong/host/linux-x86/bin/mke2fs -O ^has_journal -b 4096 -m 0 -t ext4 -I 256 -N 29 -U 7d1522e1-9dfa-5edb-a43e-98e3a4d20250 -E 
hash_seed=7d1522e1-9dfa-5edb-a43e-98e3a4d20250 /home/sysirq/aosp/out/soong/.temp/tmpr9inSx/content/apex_payload.img 20M
[  0% 49/7266] //system/core/adb/apex:com.android.adbd apex (image) [common]
FAILED: out/soong/.intermediates/system/core/adb/apex/com.android.adbd/android_common_com.android.adbd_image/com.android.adbd.apex.unsigned
rm -rf out/soong/.intermediates/system/core/adb/apex/com.android.adbd/android_common_com.android.adbd_image/image.apex && mkdir -p out/soong/.intermediates/system/c
ore/adb/apex/com.android.adbd/android_common_com.android.adbd_image/image.apex && (. out/soong/.intermediates/system/core/adb/apex/com.android.adbd/android_common_c
om.android.adbd_image/com.android.adbd.apex.unsigned.copy_commands) && APEXER_TOOL_PATH=out/soong/host/linux-x86/bin:prebuilts/sdk/tools/linux/bin out/soong/host/li
nux-x86/bin/apexer --force --manifest out/soong/.intermediates/system/core/adb/apex/com.android.adbd/android_common_com.android.adbd_image/apex_manifest.pb --file_c
ontexts system/sepolicy/apex/com.android.adbd-file_contexts --canned_fs_config out/soong/.intermediates/system/core/adb/apex/com.android.adbd/android_common_com.and
roid.adbd_image/canned_fs_config --include_build_info --payload_type image --key system/core/adb/apex/com.android.adbd.pem --pubkey system/core/adb/apex/com.android
.adbd.avbpubkey --target_sdk_version 30 --min_sdk_version 30 --assets_dir out/soong/.intermediates/system/core/adb/apex/com.android.adbd/android_common_com.android.
adbd_image/NOTICE --no_hashtree out/soong/.intermediates/system/core/adb/apex/com.android.adbd/android_common_com.android.adbd_image/image.apex out/soong/.intermedi
ates/system/core/adb/apex/com.android.adbd/android_common_com.android.adbd_image/com.android.adbd.apex.unsigned 
mke2fs 1.45.4 (23-Sep-2019)
Creating regular file /home/sysirq/aosp/out/soong/.temp/tmpAo9z9R/content/apex_payload.img
Invalid filesystem option set: has_journal,extent,huge_file,flex_bg,metadata_csum,metadata_csum_seed,64bit,dir_nlink,extra_isize,orphan_file
Traceback (most recent call last):
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/__main__.py", line 12, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 708, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 701, in main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 502, in CreateApex
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 200, in RunCommand
AssertionError: Failed to execute: out/soong/host/linux-x86/bin/mke2fs -O ^has_journal -b 4096 -m 0 -t ext4 -I 256 -N 28 -U 7d1522e1-9dfa-5edb-a43e-98e3a4d20250 -E 
hash_seed=7d1522e1-9dfa-5edb-a43e-98e3a4d20250 /home/sysirq/aosp/out/soong/.temp/tmpAo9z9R/content/apex_payload.img 21M
[  0% 65/7266] target Dex: Browser2
Warning: An API level of 1000 is not supported by this compiler. Please use an API level of 30 or earlier
[  0% 68/7266] //packages/modules/vndk/apex:com.android.vndk.v28 apex (image) [common]
FAILED: out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v28/android_common_image/com.android.vndk.v28.apex.unsigned
rm -rf out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v28/android_common_image/image.apex && mkdir -p out/soong/.intermediates/packages/module
s/vndk/apex/com.android.vndk.v28/android_common_image/image.apex && (. out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v28/android_common_image
/com.android.vndk.v28.apex.unsigned.copy_commands) && APEXER_TOOL_PATH=out/soong/host/linux-x86/bin:prebuilts/sdk/tools/linux/bin out/soong/host/linux-x86/bin/apexe
r --force --manifest out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v28/android_common_image/apex_manifest.pb --file_contexts system/sepolicy/
apex/com.android.vndk-file_contexts --canned_fs_config out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v28/android_common_image/canned_fs_confi
g --include_build_info --payload_type image --key packages/modules/vndk/apex/com.android.vndk.v28.pem --pubkey packages/modules/vndk/apex/com.android.vndk.v28.pubke
y --target_sdk_version 30 --min_sdk_version 30 --assets_dir out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v28/android_common_image/NOTICE --n
o_hashtree --do_not_check_keyname out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v28/android_common_image/image.apex out/soong/.intermediates/
packages/modules/vndk/apex/com.android.vndk.v28/android_common_image/com.android.vndk.v28.apex.unsigned 
mke2fs 1.45.4 (23-Sep-2019)
Creating regular file /home/sysirq/aosp/out/soong/.temp/tmpSbYbBn/content/apex_payload.img
Invalid filesystem option set: has_journal,extent,huge_file,flex_bg,metadata_csum,metadata_csum_seed,64bit,dir_nlink,extra_isize,orphan_file
Traceback (most recent call last):
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/__main__.py", line 12, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 708, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 701, in main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 502, in CreateApex
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 200, in RunCommand
AssertionError: Failed to execute: out/soong/host/linux-x86/bin/mke2fs -O ^has_journal -b 4096 -m 0 -t ext4 -I 256 -N 249 -U 7d1522e1-9dfa-5edb-a43e-98e3a4d20250 -E
 hash_seed=7d1522e1-9dfa-5edb-a43e-98e3a4d20250 /home/sysirq/aosp/out/soong/.temp/tmpSbYbBn/content/apex_payload.img 73M
[  0% 69/7266] //packages/modules/vndk/apex:com.android.vndk.v29 apex (image) [common]
FAILED: out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v29/android_common_image/com.android.vndk.v29.apex.unsigned
rm -rf out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v29/android_common_image/image.apex && mkdir -p out/soong/.intermediates/packages/module
s/vndk/apex/com.android.vndk.v29/android_common_image/image.apex && (. out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v29/android_common_image
/com.android.vndk.v29.apex.unsigned.copy_commands) && APEXER_TOOL_PATH=out/soong/host/linux-x86/bin:prebuilts/sdk/tools/linux/bin out/soong/host/linux-x86/bin/apexe
r --force --manifest out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v29/android_common_image/apex_manifest.pb --file_contexts system/sepolicy/
apex/com.android.vndk-file_contexts --canned_fs_config out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v29/android_common_image/canned_fs_confi
g --include_build_info --payload_type image --key packages/modules/vndk/apex/com.android.vndk.v29.pem --pubkey packages/modules/vndk/apex/com.android.vndk.v29.pubke
y --target_sdk_version 30 --min_sdk_version 30 --assets_dir out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v29/android_common_image/NOTICE --n
o_hashtree --do_not_check_keyname out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.v29/android_common_image/image.apex out/soong/.intermediates/
packages/modules/vndk/apex/com.android.vndk.v29/android_common_image/com.android.vndk.v29.apex.unsigned 
mke2fs 1.45.4 (23-Sep-2019)
Creating regular file /home/sysirq/aosp/out/soong/.temp/tmpRnAI6J/content/apex_payload.img
Invalid filesystem option set: has_journal,extent,huge_file,flex_bg,metadata_csum,metadata_csum_seed,64bit,dir_nlink,extra_isize,orphan_file
Traceback (most recent call last):
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/__main__.py", line 12, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 708, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 701, in main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 502, in CreateApex
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 200, in RunCommand
AssertionError: Failed to execute: out/soong/host/linux-x86/bin/mke2fs -O ^has_journal -b 4096 -m 0 -t ext4 -I 256 -N 271 -U 7d1522e1-9dfa-5edb-a43e-98e3a4d20250 -E
 hash_seed=7d1522e1-9dfa-5edb-a43e-98e3a4d20250 /home/sysirq/aosp/out/soong/.temp/tmpRnAI6J/content/apex_payload.img 77M
[  0% 70/7266] //packages/modules/vndk/apex:com.android.vndk.current apex (image) [common]
FAILED: out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.current/android_common_image/com.android.vndk.current.apex.unsigned
rm -rf out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.current/android_common_image/image.apex && mkdir -p out/soong/.intermediates/packages/mo
dules/vndk/apex/com.android.vndk.current/android_common_image/image.apex && (. out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.current/android_
common_image/com.android.vndk.current.apex.unsigned.copy_commands) && APEXER_TOOL_PATH=out/soong/host/linux-x86/bin:prebuilts/sdk/tools/linux/bin out/soong/host/lin
ux-x86/bin/apexer --force --manifest out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.current/android_common_image/apex_manifest.pb --file_conte
xts system/sepolicy/apex/com.android.vndk-file_contexts --canned_fs_config out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.current/android_comm
on_image/canned_fs_config --include_build_info --payload_type image --key packages/modules/vndk/apex/com.android.vndk.current.pem --pubkey packages/modules/vndk/ape
x/com.android.vndk.current.pubkey --target_sdk_version 30 --min_sdk_version 30 --assets_dir out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.cur
rent/android_common_image/NOTICE --no_hashtree --do_not_check_keyname out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.current/android_common_im
age/image.apex out/soong/.intermediates/packages/modules/vndk/apex/com.android.vndk.current/android_common_image/com.android.vndk.current.apex.unsigned 
mke2fs 1.45.4 (23-Sep-2019)
Creating regular file /home/sysirq/aosp/out/soong/.temp/tmpAykWIz/content/apex_payload.img
Invalid filesystem option set: has_journal,extent,huge_file,flex_bg,metadata_csum,metadata_csum_seed,64bit,dir_nlink,extra_isize,orphan_file
Traceback (most recent call last):
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/__main__.py", line 12, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 174, in _run_module_as_main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/internal/stdlib/runpy.py", line 72, in _run_code
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 708, in <module>
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 701, in main
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 502, in CreateApex
  File "/home/sysirq/aosp/out/soong/host/linux-x86/bin/apexer/apexer.py", line 200, in RunCommand
AssertionError: Failed to execute: out/soong/host/linux-x86/bin/mke2fs -O ^has_journal -b 4096 -m 0 -t ext4 -I 256 -N 306 -U 7d1522e1-9dfa-5edb-a43e-98e3a4d20250 -E
 hash_seed=7d1522e1-9dfa-5edb-a43e-98e3a4d20250 /home/sysirq/aosp/out/soong/.temp/tmpAykWIz/content/apex_payload.img 96M
22:59:33 ninja failed with: exit status 1

#### failed to build some targets (12 seconds) ####
```

debian13的mke2fs -V

```
mke2fs 1.47.2 (1-Jan-2025)
	Using EXT2FS Library version 1.47.2
```

aosp自带的mke2fs -V

```
mke2fs 1.45.4 (23-Sep-2019)
	Using EXT2FS Library version v1.45.4-867-g4bc58792
```

导致读取/etc/mke2fs.conf时，发现不能识别的选项，如：orphan_file、metadata_csum_seed。



备份一份/etc/mke2fs.conf，然后去掉orphan_file、metadata_csum_seed，重新编译即可。



# 判断编译c++程序使用的是那个stl

### 检查符号特征

使用 nm 工具查看二进制文件中的未定义符号:

```
arm-linux-androideabi-nm -u /path/to/xxxx | grep "std::"
```

- 如果是 GNU STL (gnustl):

你会看到类似 std::string 的原始修饰名，或者包含 __gnu_cxx 命名空间。
特征符号：_ZNSs (std::string), _ZNSt (std::), std::_Rb_tree（红黑树实现）。
正如你之前的报错，出现了 std::_Rb_tree_increment，这几乎 100% 确定是 gnustl。

- 如果是 LLVM libc++:

libc++ 使用内联命名空间 __1 来防止 ABI 冲突。
特征符号：你会看到符号中包含 __1。
例如：std::__1::basic_string 或 _ZNSt3__1...。


# Mac 系统上编译

### 资料

Building AOSP on macOS

<https://dev.to/sriteja777/building-aosp-on-macos-2473>

Unknown directive .altmacro error happens when using android-ndk standalone toolchain

<https://stackoverflow.com/questions/47938599/unknown-directive-altmacro-error-happens-when-using-android-ndk-standalone-tool>
