# C2

1. Get the second-stage malware from an image file uploaded to Photobucket[.]com.
2. If the above fails, it tries to download the image from the domain toknowall[.]com.
3. If both fail, it starts listening to all TCP packets on the affected device to receive the IP address from a specific TCP packet sent by the attacker.

If the malware does not get a valid image from previous stages, it will then enter into listening mode. This allows the attackers to regain control over infected victims if the sinkholed alternative domain does not serve a valid image.

# ssler module

The first action taken by the ssler module is to configure the device's iptables to redirect all traffic destined for port 80 to its local service listening on port 8888.

Any outgoing web requests on port 80 are now intercepted by ssler and can be inspected and manipulated before being sent to the legitimate HTTP service. All HTTP requests are sslstripped. That is, the following changes are made to requests before being sent to the true HTTP server:

- Any instances of the string https:// are replaced with http://, converting requests for secure HTTP resources to requests for insecure ones so sensitive data such as credentials can be extracted from them.
- If the request contains the header Connection: keep-alive, it is replaced with Connection: close
- If the request contains the header Accept-Encoding with the gzip value, this is converted to Accept-Encoding: plaintext/none so no responses will be compressed with gzip (exceptions are made for certain file types, such as images).

After these modifications are made, a connection to the true HTTP server is made by ssler using the modified request data over port 80


# 资料

What Is A Botnet?

https://www.fortinet.com/resources/cyberglossary/what-is-botnet#:~:text=A%20botnet%20is%20a%20network,is%20known%20as%20a%20bot.

IoT Botnet

https://www.trendmicro.com/vinfo/sg/security/definition/iot-botnet

VPNFilter Two Years Later: Routers Still Compromised

https://www.trendmicro.com/en_us/research/21/a/vpnfilter-two-years-later-routers-still-compromised-.html

VPNFilter Update - VPNFilter exploits endpoints, targets new devices

https://blog.talosintelligence.com/vpnfilter-update/

New VPNFilter malware targets at least 500K networking devices worldwide

https://blog.talosintelligence.com/vpnfilter/

VPNFilter 物联网僵尸网络深度分析报告

https://www.6cloudtech.com/upload/default/20180821/3b9df83890935447995292156402215c.pdf