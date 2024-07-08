# RFB原理

RFB协议的显示部分基于一个简单的画图原理：**“将一个矩形块的象素点放在给定位置（x，y）上”**。这样做初看起来也许非常低效，因为要将用户所有的图形组件都画出来。但是由于可以为象素数据进行多种不同的编码，可以根据不同的参数比如网络带宽、客户端计算速度和服务器处理的速度等选择灵活的编码方式。**一系列的矩形块组成了一个帧缓冲更新** 。一个更新描述了帧缓冲从一个状态到另一个状态的变化情况，所以，某些方面，这和音频的帧很类似。


# 资料

VNC远程桌面解决方案与原理介绍

https://blog.csdn.net/c_base_jin/article/details/131948771?utm_medium=distribute.pc_relevant.none-task-blog-2~default~baidujs_baidulandingword~default-0-131948771-blog-114969149.235%5Ev43%5Epc_blog_bottom_relevance_base9&spm=1001.2101.3001.4242.1&utm_relevant_index=1

 The RFB Protocol
 
 https://vncdotool.readthedocs.io/en/0.8.0/rfbproto.html#id12