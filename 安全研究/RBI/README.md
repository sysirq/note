#  Browser Isolation Buyer‘s Guide



资料地址：https://www.garrison.com/document/browser-isolation-buyers-guide.pdf



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