# 数量

全网设备：

```
[~]$ python3 -m shodan count "http.title:'Vigor Login Page'"
512924
```

```
[~]$ python3 -m shodan count http.html:"v2960" 'http.title:"Vigor Login Page"'
10233
```

![image-20241008175401727](images/image-20241008175401727.png)


# 参考资料

VPN设备的矛与盾

https://drive.google.com/file/d/1z4QZctHU3XYB-X9jXiWrTGhMLJqP27ub/view?pli=1