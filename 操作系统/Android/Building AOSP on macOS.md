# Building AOSP on macOS

[#](https://dev.to/t/android)[#](https://dev.to/t/macos)[#](https://dev.to/t/kernel)

In this post, we will see how to build Android source code on macOS. 

**Disclaimer**

1. Building AOSP on Mac is not officially supported. So we may not be able to build all tools.

1. The steps mentioned below are for macOS Monterey. For other versions, steps might be similar only. 

The default file system on macOS 10.13 and later which is called Apple File System (APFS) is case-insensitive. But to build AOSP, we need a case-sensitive file system. If you try building on default file system, the build will fail to start with the below message.

```
20:48:42 You are building on a case-insensitive filesystem.
20:48:42 Please move your source tree to a case-sensitive filesystem.
20:48:42 ************************************************************
20:48:42 Case-insensitive filesystems not supported
```

So, first we need to create a case-sensitive file system, before we can start downloading the code.

1. Open 

Disk Utility

1. Click on 

+ 

1. Give any name you want to the volume and select APFS (Case-sensitive) in the format section and click on add.

1. Optionally, you can customise size options if you want. But beware that, you need at least 130GB of space on you system in order to download the source code.

So, android team has made an utility called [repo](https://gerrit.googlesource.com/git-repo/), which helps in managing multiple repositories. We will be using this utility to download android source.

Install 

```
❯ brew install repo
```

Create and base directory inside the new volume, where you want to clone all the repos required for building inside the volume you created in first step. Replace 

<volume_name>

```
❯ cd /Volumes/<volume_name> 
❯ mkdir source
❯ cd source
```

Now let's initialise repo. This will create a 

```
❯ repo init -u 
Downloading Repo source from 
remote: Total 7372 (delta 3971), reused 7372 (delta 3971)
Downloading manifest from 
remote: Finding sources: 100% (98897/98897)
remote: Total 98897 (delta 31617), reused 98888 (delta 31617)
Your identity is: Your Name <email>
If you want to change this, please re-run 'repo init' with --config-name
repo has been initialised in /path/to/folder/
If this is not the directory in which you want to initialise repo, please run:
   rm -r /path/to/folder/.repo
and try again.
```

Now clone the source. Also remember to pass the 

```
❯ repo sync -c -j8
```

Note that the above step will take time to download and check out, depending on your network bandwidth and processing speed of your system. You will get the below message once finished.

```
repo sync has finished successfully.
/usr/local/Cellar/python@3.10/3.10.5/Frameworks/Python.framework/Versions/3.10/lib/python3.10/multiprocessing/resource_tracker.py:224: UserWarning: resource_tracker: There appear to be 17 leaked semaphore objects to clean up at shutdown
  warnings.warn('resource_tracker: There appear to be %d '
```

If you did get the above message, then congrats 🥳 you have completed the most time taking step. But due to some issue, if it failed then try out the [Troubleshooting steps](https://source.android.com/setup/build/downloading#troubleshooting-network-issues). Still not resolved? then comment below, will try to resolve it. 

Before, we can start the build, we need to some configuration steps.

- Commands Setup

Android source offers some helper commands for building, we can add them to our path in current session with below command.

```
❯ source build/envsetup.sh
```

You can use the 

- Selecting Build target

We can select the build target, i.e for which product and architecture we want to build for using the 

```
❯ lunch
You're building on Darwin
Lunch menu .. Here are the common combinations:
     1. aosp_arm-eng
     2. aosp_arm64-eng
     3. aosp_barbet-userdebug
     4. aosp_bramble-userdebug
     5. aosp_bramble_car-userdebug
     6. aosp_car_arm-userdebug
     7. aosp_car_arm64-userdebug
     8. aosp_car_x86-userdebug
     9. aosp_car_x86_64-userdebug
     10. aosp_cf_arm64_auto-userdebug
     11. aosp_cf_arm64_phone-userdebug
     12. aosp_cf_x86_64_foldable-userdebug
     13. aosp_cf_x86_64_pc-userdebug
     14. aosp_cf_x86_64_phone-userdebug
     15. aosp_cf_x86_64_tv-userdebug
     16. aosp_cf_x86_auto-userdebug
     17. aosp_cf_x86_phone-userdebug
     18. aosp_cf_x86_tv-userdebug
     19. aosp_coral-userdebug
     20. aosp_coral_car-userdebug
     21. aosp_flame-userdebug
     22. aosp_flame_car-userdebug
     23. aosp_oriole-userdebug
     24. aosp_oriole_car-userdebug
     25. aosp_raven-userdebug
     26. aosp_raven_car-userdebug
     27. aosp_redfin-userdebug
     28. aosp_redfin_car-userdebug
     29. aosp_redfin_vf-userdebug
     30. aosp_slider-userdebug
     31. aosp_sunfish-userdebug
     32. aosp_sunfish_car-userdebug
     33. aosp_trout_arm64-userdebug
     34. aosp_trout_x86-userdebug
     35. aosp_whitefin-userdebug
     36. aosp_x86-eng
     37. aosp_x86_64-eng
     38. arm_krait-eng
     39. arm_v7_v8-eng
     40. armv8-eng
     41. armv8_cortex_a55-eng
     42. armv8_kryo385-eng
     43. beagle_x15-userdebug
     44. beagle_x15_auto-userdebug
     45. car_ui_portrait-userdebug
     46. car_x86_64-userdebug
     47. db845c-userdebug
     48. gsi_car_arm64-userdebug
     49. gsi_car_x86_64-userdebug
     50. hikey-userdebug
     51. hikey64_only-userdebug
     52. hikey960-userdebug
     53. hikey960_tv-userdebug
     54. hikey_tv-userdebug
     55. poplar-eng
     56. poplar-user
     57. poplar-userdebug
     58. qemu_trusty_arm64-userdebug
     59. rb5-userdebug
     60. sdk_car_arm-userdebug
     61. sdk_car_arm64-userdebug
     62. sdk_car_portrait_x86_64-userdebug
     63. sdk_car_x86-userdebug
     64. sdk_car_x86_64-userdebug
     65. silvermont-eng
     66. uml-userdebug
     67. yukawa-userdebug
     68. yukawa_sei510-userdebug
Which would you like? [aosp_arm-eng]
Pick from common choices above (e.g. 13) or specify your own (e.g. aosp_barbet-eng):
```

Select any configuration that you would like to build for.

You can simply run the 

```
❯ m
```

And it will start the build for the target we specified. You can also specify number of threads for the build with 

 

 

Thank you for reading till the end. It is just the first part of the whole series, in next parts we will look into Soong Build system, building for different architectures, cross compiling and more. Stay tuned!!

Also let me know the feedback for this article in the comments!