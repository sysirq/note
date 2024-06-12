# key word

- Hardware-based pixel-pushing



# Hardsec: practical non-Turing-machine security for threat elimination

资料地址：	https://www.hardsec.com



It is well known that maliciously constructed data inputs can be used by an attacker to exploit system vulnerabilities. 



#  Browser Isolation Buyer‘s Guide



资料地址：https://www.garrison.com/document/browser-isolation-buyers-guide.pdf



**browser isolation does not rely upon detection, instead it assumes that all web content which flows through it is risky.**

For full browser isolation, the Browser Isolation Platform needs to be implemented as shown below, with two systems: System A that is assumed to be compromised and System B that is always trusted. Moreover, the transfer format between the two should create a “pixel gap” analogous to air gap security techniques to ensure that only raw pixels— and therefore no code—can be transferred from system A to system B.

**Remember: Full Browser isolation must have a verifiable pixel gap.**

Hardsec uses FPGAs to provide a video display on system B and the video camera on system A that captures the displayed pixels. Even if System A is completely compromised, this pixel gap ensures that no malicious code can reach system B or the user endpoint.



### What is a Verifiable Pixel Gap?

New advances in hardware-based pixel-pushing can now enable full isolation with an easily verifiable pixel gap -- **a physically enforced separation between the user and the web** - that delivers a powerful combination of security and usability alongside lower costs and management overheads.



### Partial Browser Isolation



Moreover, even a pixel-pushing method may still only provide partial browser isolation if the browser isolation platform is not robustly architected and implemented.

If the browser isolation platform consists of only a single system that translates the web traffic to pixels, then should that system become compromised, **it can be used by an attacker to send something other than pixels to the end users’ browser** - such as malicious code - and thereby compromise that endpoint.



In addition, even if two systems are used in the browser isolation platform, if any web content other than raw pixels (and raw Pulse-Code Modulation audio) can be sent between them, there is still the potential for the system that connects to the web site to send malicious code to the trusted system that connects to the end user’s endpoint. The correct way to implement a browser isolation platform for Full Browser Isolation is described below.



### Full Browser Isolation



# The Promise and Reality of Remote Browser Isolation

资料地址：https://www.skyhighsecurity.com/wp-content/uploads/2023/01/wp-promise-reality-remote-browser-isolation-1.pdf



There are various implementations of this technology, but the core principle is that potentially unsafe content never reaches the user’s endpoint.

The fundamental value of this approach is that protection is no longer contingent on detection.



Malware may go undetected, but it will only compromise the temporary browser that has no access to valuable assets



# Remote Browser Isolation

资料地址：https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/datasheets/remote-browser-isolation



# Browser isolation as an enterprise security control



论文地址：https://www.garrison.com/document/browser-isolation-as-an-enterprise-security-control.pdf



hardware-based browser isolation platform 



The Browser Isolation security model depends critically on the data transfer format between an untrusted component responsible forprocessing risky web content and a trusted component responsible for transmitting information to the user’s endpoint. 



The browser isolation platform must therefore consist of at least two separate systems:

- system A, which processes remote data (and must at all times be assumed **compromised by malware**); 
- and a separate system B, which **must remain trusted at all times**, and which will send a safe data stream to the user’s endpoint. 

The **focus** must therefore be on the format of the data that is transferred from the first (assumed compromised) system A to the second (unimpeachably trusted) system,This data format must provide three things:

- First, it must not be possible to use this data format as a vector for compromising system B
- Secondly, it must allow the second system to generate a data stream which itself cannot possibly be used to compromise the user’s endpoint.
- And thirdly, it must faithfully represent the visual output of system A (for example, a web page).

The gold standard for this transfer format is **raw pixels** — an approach commonly known as ‘**pixel pushing**’. 

Raw pixels present a unique data format for visual data because there is no such thing as invalid pixel data

A 1080p raw 24-bit RGB bitmap (for example) is a buffer in memory containing 3x1920x1080 bytes: any data written into that memory buffer represents a valid image and can be displayed onto a screen with a simple memory copy

This is quite unlike other visual formats — jpeg, pdf, html — which require **sophisticated parsing that may potentially contain vulnerabilities that could be exploited by a carefully crafted data stream.** 

**The challenge with pixel pushing is the sheer volume of data generated**. At 30 frames per second (for example) a 1080p red, green, blue (RGB) screen image will generate 3x1920x1080x30 bytes — or a data rate of 1.5Gbit/s. It is clearly not feasible to deliver that 1.5Gbit/s to the user’s endpoint without either very substantial data compression or excessive network utilisation. The good news is that suitable compression algorithms are well-known: this is a video compression problem, and technologies like **H264** are well-established.



# 资料

基于代理映射的网络安全隔离与信息交换系统及方法

https://patents.google.com/patent/CN1571398A/zh