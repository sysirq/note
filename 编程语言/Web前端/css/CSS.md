# 四种CSS导入方式

### 外部样式 （推荐）

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

<h1>我是标题</h1>

</body>
</html>
```

### 内部样式

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    <!-- 
        选择器 {
            声明1;
            声明2;
            声明3;
        }
     -->
    <style>
        h1 {
            color: blanchedalmond;
        }
    </style>
</head>
<body>

<h1>我是标题</h1>

</body>
</html>
```

### 行内样式

在标签元素中，编写一个style属性，编辑样式即可

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
</head>
<body>

<h1 style="color: red;">我是标题</h1>

</body>
</html>
```

### 优先级

就近原则，那个样式离元素最近，那个样式生效

# 选择器

作用：选着页面上的某一个或者某一类元素

### 标签选择器

```css
h1 {
    color:blue;
    background-color: aqua;
    border-radius: 24px;
}
```

### 类选择器

```html
<h1 class="title2">我是标题2</h1>
```

```css
.title2 {
    color:red;
    background-color: blue;
    border-radius: 24px;
}
```

### ID选择器

```html
<h1 id="title3">我是标题3</h1>
```

```css
#title3 {
    color:#111111;
    background-color: blue;
    border-radius: 24px;
}
```

### 层次选择器

*   后代选择器
*   子代选择器
*   兄弟选择器
*   通用兄弟选择器

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <style>
        /* 后代选择器:某个元素的后面元素 */
        /* p0~p6都变色 */
        /* body p {
            background-color: red;
        } */



        /* 子选择器:选一代 */
        /* p0~p3 变色 */
        /* body>p{
            background-color: bisque;
        } */


        /* 相邻兄弟选择器:当前选中元素的向下的第一个兄弟元素 */
        /* p2 变色 */
        /* .active+p {
            background-color: red;
        } */


        /* 通用兄弟选择器：当前选中元素的向下的所有兄弟元素 */
        /* p2、p3、p7 变色 */
        .active ~p{
            background-color: green;
        }
    </style>
</head>
<body>

<p>p0</p>
<p class="active">p1</p>
<p>p2</p>
<p>p3</p>

<ul>
    <li>
        <p>p4</p>
    </li>
    <li>
        <p>p5</p>
    </li>
    <li>
        <p>p6</p>
    </li>
</ul>

<p>p7</p>

</body>
</html>
```

### 结构伪类选择器

伪类：相当于条件

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <style>
        /* ul的第一个子元素 */
        ul li:first-child{
            color: green;
        }

        /* ul的最后一个子元素 */
        ul li:last-child{
            color: red;
        }

        /* 选中p1:定位到父元素，选着当前的第一个元素,
        选着当前p元素的父级元素，选中父级元素的第一个，并且是当前元素才生效
        */
        p:nth-child(1){
            background-color: blue;
        }

        /* 选中父元素，下的p元素的第二个 */
        p:nth-of-type(2){
            background-color: yellow;
        }

        
        a:hover{
            background: yellow;
        }

    </style>
</head>
<body>
    <p>p1</p>
    <p>p2</p>
    <p>p3</p>
    
    <ul>
        <li>li1</li>
        <li>li2</li>
        <li>li3</li>
    </ul>
<a href="#">click me</a>
</body>
</html>
```

### 属性选择器

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <style>
        .demo a{
            float: left;
            display: block;
            height: 50px;
            width: 50px;
            border-radius: 10px;
            background-color: black;
            text-align: center;
            color: gainsboro;
            text-decoration: none;
            margin-right: 5px;
            font:bold 20px/50px Arial;
        }

        /* id="seven"属性的元素 */
        /* 7 */
        a[id="seven"]{
            background-color: yellow;
        }

        /* *= :包含 */
        /* 3 4 5 6 */
        a[class*="links"]{
            background-color: aqua;
        }

        /* ^=：以什么开头 */
        /* 1 */
        a[href^="http"]{
            background-color: green;
        }

        /* $=：以什么结尾 */
        /* 8 */
            a[href$="pdf"]{
            background-color: gray;
        }
    </style>
</head>
<body>

<p class="demo">
    <a href="http://www.baidu.com" class="links item first">1</a>
    <a href="" class="" target="_blank" title="test">2</a>
    <a href="" class="links">3</a>
    <a href="" class="links">4</a>
    <a href="" class="links">5</a>
    <a href="" class="links">6</a>
    <a href="" class="" id="seven">7</a>
    <a href="abc.pdf" class="">8</a>
    <a href="abc.doc" class="">9</a>
    <a href="abcd.doc" class="last">10</a>
</p>

</body>
</html>
```

效果：

![image](19EE27330AEC4C91A1FC81FC27F8AD3C)

# 字体样式

span标签：重点要突出的字使用span标签套起来

*   font-family:字体
*   font-size：字体大小
*   font-weight：字体粗细
*   color: 字体颜色

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <!-- 
        font-family:字体
        font-size：字体大小
        font-weight：字体粗细
        color: 字体颜色
     -->
    <style>
        body {
            font-family:Impact, Haettenschweiler, 'Arial Narrow Bold', sans-serif;
            color:green;
        }

        h1 {
            font-size: 50px;
        }

        .p1 {
            font-weight: bold;
        }

    </style>
</head>
<body>

<h1>火影忍者</h1>

<p class="p1">首领的名字由柱间取名为火影，村子的名字由斑取名为木叶忍村。</p>

<p>“木”代表森之千手一族（千手一族领袖千手柱间拥有木遁的血继限界），“叶”代表宇智波一族（宇智波一族族徽外形是扇叶）。</p>

</body>
</html>
```

# 文本样式

*   color：
    单词：red
    RGB：0~F
    RGBA：A代表透明度(0~1)

*   text-align:排版，居中

*   text-indent: 段落首行缩进，em单位为一个字体

*   line-height:行高，可以用于上下居中(line-height = height)

*   text-decoration:下划线、中划线、上划线

*   text-shadow:阴影

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <!-- 
        color：
            单词：red
            RGB：0~F
            RGBA：A代表透明度(0~1)
        
        text-align:排版，居中
        text-indent: 段落首行缩进，em单位为一个字体
        line-height:行高，可以用于上下居中
        text-decoration:下划线、中划线、上划线
     -->
    <style>

        h1 {
            color: rgba(255, 0, 0, 0.2);
            text-align: center;
        }

        .p1 {
            text-indent: 4em;
        }

        .p2 {
            text-indent: 4em;
            background-color: green;
            line-height: 100px;
            text-decoration: underline;
        }

    </style>
</head>
<body>

<h1>火影忍者</h1>

<p class="p1">首领的名字由柱间取名为火影，村子的名字由斑取名为木叶忍村。</p>

<p class="p2">“木”代表森之千手一族（千手一族领袖千手柱间拥有木遁的血继限界），“叶”代表宇智波一族（宇智波一族族徽外形是扇叶）。</p>

</body>
</html>
```

# 列表样式

list-style-type: none; 去掉列表前面的点符号

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <style>

        #nav {
            width: 200px;
            background-color: gray;
        }

        .title {
            font-size: 18px;
            font-weight: bold;
            text-indent: 1em;
            line-height: 1.5;
            background-color: red;
        }

        /* 
        list-style-type：
         none 去掉圆点
        */

        ul {
            background-color: gray;
        }
        ul li {
            line-height: 30px;
            list-style-type: none;
            text-indent: 1em;
            
        }

        a {
            text-decoration: none;
            font-size: 14px;
            color: black;
        }

        a:hover {
            color: orange;
            text-decoration: underline;
        }
    </style>
</head>
<body>

<div id="nav">
    <h2 class="title">全部商品分类</h2>
    
    <ul>
        <li>
            <a href="#">图书</a>  
            <a href="#">音像</a>  
            <a href="#">数字商品</a>
        </li>
        <li>
            <a href="#">家用电器</a>  
            <a href="#">手机</a>  
            <a href="#">数码</a>
        </li>
        <li>
            <a href="#">电脑</a>  
            <a href="#">办公</a>
        </li>
        <li>
            <a href="#">家居</a>  
            <a href="#">家装</a>  
            <a href="#">厨具</a>
        </li>
        <li>
            <a href="#">服饰鞋帽</a>  
            <a href="#">个性化妆</a>
        </li>
        <li>
            <a href="#">礼品箱包</a>  
            <a href="#">钟表</a>  
            <a href="#">珠宝</a>
        </li>
        <li>
            <a href="#">食品饮料</a>  
            <a href="#">保健食品</a>
        </li>
        <li>
            <a href="#">彩票</a>  
            <a href="#">旅行</a>  
            <a href="#">充值</a>  
            <a href="#">票务</a>
        </li>
    </ul>
</div>

</body>
</html>
```

# 背景样式

background 属性：

*   第一个值为颜色
*   第二个值为图片url
*   第三个值为图片x轴的位置
*   第四个值为图片y轴的位置
*   第五个值为平铺方式

```css
{
    background: red url("images/1.png") 200px 10px no-repeat;
}
```

背景颜色

背景图片

# 渐变

linear-gradient属性

# 盒子模型

![image](A71FB83283314D3EA5F5FE435227CFF6)

### margin 外边距

外边距的妙用：居中元素

margin的四个值：上边距 距 右边距 下边距 左边

```css
margin: 0 auto;
```

### padding 内边距

### 边框

*   边框的粗细
*   边框的样式
*   边框的颜色

```css

h1 {
    border: 1px solid red;
}

```

### 圆角边框

border-radius: 50px;

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <style>
        div {
            width: 100px;
            height: 50px;
            border: 3px solid red;
            margin-top: 100px;
            border-radius: 50px 50px 0px 0px;
        }

        img {
            border-radius: 100px;
            width: 100px;
            height: 100px;
        }
    </style>
</head>
<body>

<div></div>

<img src="images/111.png">

</body>
</html>
```

### 阴影

box-shadow属性:

# 浮动

标准文档流

块级元素：独占一行

行内元素：不独占一行

行内元素可以被包含在块级元素中，反之不可以

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <!-- 
        display属性：
            block 块元素
            inline 行内元素
            inline-block 是块元素，但是可以与行内元素在一行
            none 消失该元素
     -->
    <style>
        div {
            width: 100px;
            height: 100px;
            border: 1px solid red;
        }

        #div1 {
            float: right;
        }

        #div2 {
            float: right;
        }

        #div3 {
            float: right;
        }

    </style>
</head>
<body>

<div id="div1">
    div1块元素
</div>

<div id="div2">
    div2块元素
</div>

<div id="div3">
    div3块元素
</div>

</body>
</html>
```

### 父级边框塌陷问题

###### 方法一：增加一个空的div标签，清除浮动

clear\:both;

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <!-- 
        display属性：
            block 块元素
            inline 行内元素
            inline-block 是块元素，但是可以与行内元素在一行
            none 消失该元素
     -->
    <style>
        div {
            border: 1px solid red;
        }

        #father {
            width: 1920px;
        }

        #div1 {
           float: left;
        }

        #div2 {
            float: left;
        }

        #div3 {
            float: left;
        }

        #div4 {
            float: left;
            clear: both;
        }

        .clear {
            margin: 0;
            padding: 0;
            clear:both;
        }
    </style>
</head>
<body>

<div id="father">
    <div id="div1">
        div1块元素
    </div>

    <div id="div2">
        div2块元素
    </div>

    <div id="div3">
        div3块元素
    </div>

    <div id="div4">
        <span>hanhaniscat</span>
    </div>

    <div class="clear"></div>
</div>

</body>
</html>
```

###### 方法二：overflow属性，在父级元素中增加一个overflow属性

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <!-- 
        display属性：
            block 块元素
            inline 行内元素
            inline-block 是块元素，但是可以与行内元素在一行
            none 消失该元素
     -->
    <style>
        div {
            border: 1px solid red;
        }

        #father {
            width: 1920px;
            overflow: hidden;
        }

        #div1 {
           float: left;
        }

        #div2 {
            float: left;
        }

        #div3 {
            float: left;
        }

        #div4 {
            float: left;
            clear: both;
        }

        .clear {
            margin: 0;
            padding: 0;
            clear:both;
        }
    </style>
</head>
<body>

<div id="father">
    <div id="div1">
        div1块元素
    </div>

    <div id="div2">
        div2块元素
    </div>

    <div id="div3">
        div3块元素
    </div>

    <div id="div4">
        <span>hanhaniscat</span>
    </div>
</div>

</body>
</html>
```

###### 方法三：伪类 (推荐使用)

```css
        #father::after {
            content: "";
            display: block;
            clear: both;
        }
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <!-- 
        display属性：
            block 块元素
            inline 行内元素
            inline-block 是块元素，但是可以与行内元素在一行
            none 消失该元素
     -->
    <style>
        div {
            border: 1px solid red;
        }

        #father {
            width: 1920px;
        }

        #father::after {
            content: "";
            display: block;
            clear: both;
        }

        #div1 {
           float: left;
        }

        #div2 {
            float: left;
        }

        #div3 {
            float: left;
        }

        #div4 {
            float: left;
            clear: both;
        }

        .clear {
            margin: 0;
            padding: 0;
            clear:both;
        }
    </style>
</head>
<body>

<div id="father">
    <div id="div1">
        div1块元素
    </div>

    <div id="div2">
        div2块元素
    </div>

    <div id="div3">
        div3块元素
    </div>

    <div id="div4">
        <span>hanhaniscat</span>
    </div>
</div>

</body>
</html>
```

# 定位

### 相对定位

相对于自己原来的位置进行偏移，仍然在标准文档流中

```css
position: relative;
top: -20px;
left: 20px;
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <style>
        div {
            margin: 10px;
            padding: 5px;
            font-size: 12px;
            line-height: 1.5;
        }

        #father {
            border: 1px solid red;
            background-color: red;
        }

        #div1 {
            border: 1px dashed blue;
            background-color: blue;

            position: relative;
            top: -20px;
            left: 20px;
        }

        #div2 {
            border: 1px dashed yellow;
            background-color: yellow;
        }

        #div3 {
            border: 1px dashed orange;
            background-color: orange;
        }

        #div4 {
            border: 1px dashed pink;
            background-color: pink;
        }
    </style>
</head>
<body>

<div id="father">
    <div id="div1">
        div1块元素
    </div>

    <div id="div2">
        div2块元素
    </div>

    <div id="div3">
        div3块元素
    </div>

    <div id="div4">
        <span>hanhaniscat</span>
    </div>
</div>


</body>
</html>
```

### 绝对定位

*   没有父级元素的定位的前提下，相对于浏览器定位
*   父级元素存在定位，我们通常相对于父级元素进行偏移
*   相对于父级或浏览器的位置，进行绝对定位的话，它不在标准的文档流中，原来的位置不会被保留

```css
//相对父级元素定位的实现，首先得在父元素中编写定位代码（position: relative;对父元素无影响）
#father {
    border: 1px solid red;
    background-color: red;
    position: relative;
}

#div1 {
    border: 1px dashed blue;
    background-color: blue;

    position: absolute;
    top:  200px;
    left: 20px;
}
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <style>
        div {
            margin: 10px;
            padding: 5px;
            font-size: 12px;
            line-height: 1.5;
        }

        #father {
            border: 1px solid red;
            background-color: red;
            position: relative;
        }

        #div1 {
            border: 1px dashed blue;
            background-color: blue;

            position: absolute;
            top:  200px;
            left: 20px;
        }

        #div2 {
            border: 1px dashed yellow;
            background-color: yellow;
        }

        #div3 {
            border: 1px dashed orange;
            background-color: orange;
        }

        #div4 {
            border: 1px dashed pink;
            background-color: pink;
        }
    </style>
</head>
<body>

<div id="father">
    <div id="div1">
        div1块元素
    </div>

    <div id="div2">
        div2块元素
    </div>

    <div id="div3">
        div3块元素
    </div>

    <div id="div4">
        <span>hanhaniscat</span>
    </div>
</div>


</body>
</html>
```

### 固定定位fixed

通常用来实现返回网页顶部的功能

```css
div {
    position: fixed;
    width: 50px;
    height: 50px;
}
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <style>
        body {
            height: 10000px;
        }

        div {
            position: fixed;
            width: 50px;
            height: 50px;
            line-height: 50px;
            text-align: center;
            right: 0;
            bottom: 0;
            background-color: red;
        }
    </style>
</head>
<body>

<div>
    <span>div1</span>
</div>


</body>
</html>
```

### z-index

类似图层得概念,控制谁显示在顶层（0\~999）

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <style>
        div {
            width: 100px;
            height: 100px;
            line-height: 100px;
            text-align: center;
        }

        #father {
            position: relative;
            overflow: auto;
            
        }

        #div1 {
            background: pink;
            position:absolute;
            z-index: 3;
        }

        #div2 {
            background: red;
            position:absolute;
        }

        #div3 {
            background: green;
            position:absolute;
        }


    </style>
</head>
<body>

<div id="father">

<div id="div1">
    <span>div1</span>
</div>

<div id="div2">
    <span>div2</span>
</div>

<div id="div3">
    <span>div3</span>
</div>

</div>

</body>
</html>
```

### opacity

设置透明度
