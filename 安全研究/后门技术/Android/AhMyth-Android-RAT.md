# usesCleartextTraffic

在 `AndroidManifest.xml` 中设置 `android:usesCleartextTraffic="true"` 可以允许应用使用明文 HTTP 流量（即 `http://`），但这并不完全取决于 `AndroidManifest.xml` 中的这一设置，特别是在 Android 9.0（API 级别 28）及以上版本的设备上。

从 Android 9.0（API 级别 28）开始,(android:networkSecurityConfig="@xml/network_security_config")`network_security_config` 配置文件中的规则具有更高的优先级，尤其是对于是否允许明文 HTTP 流量。

如果你在 `network_security_config` 中明确禁用了明文流量（即 `cleartextTrafficPermitted="false"`），那么即使在 `AndroidManifest.xml` 中设置了 `android:usesCleartextTraffic="true"`，它仍然无法生效

# 资料

AhMyth-Android-RAT

https://github.com/AhMyth/AhMyth-Android-RAT

AhMyth-Android-RAT远控功能及通信模型剖析

https://xz.aliyun.com/t/14749?time__1311=mqmx9QwreWq05DI5YK0%3DHwc40hQ%2BYBeD&alichlgref=https%3A%2F%2Fwww.google.com%2F

十分钟学会angular

https://blog.csdn.net/Gefangenes/article/details/131772621