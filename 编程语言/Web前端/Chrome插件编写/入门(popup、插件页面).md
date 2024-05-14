# 一个简单的项目

==注意： manifest.json文件必须放在项目根目录下==

### 结构

![image](images/D32208A48BC54A9B9F6F66725B45BE0Cclipboard.png)

### manifest.json文件

```
{
  "manifest_version": 3,
  "name": "Hello Extensions of the world",
  "description": "Base Level Extension",
  "version": "1.0",
  "action": {
    "default_popup": "hello.html",
    "default_icon": "hello_extensions.png"
  }
}
```


### hello.html

```
<html>
  <body>
    <h1>Hello Extensions</h1>
    <script src="popup.js"></script>
  </body>
</html>
```

### popup.js

```
console.log("This is a popup!A")
```



# 效果

![image](images/2A8BAF2D34FF4877B732988C770EF1BAclipboard.png)

# 调试方法

![image](images/00E56C1DC0F5499C98D6FF4C236EA535clipboard.png)

![image](images/5DA17EFE1107473EA7143560C2200250clipboard.png)