# 定义一个网格

首先，将容器的display属性设置为grid来定义一个网络

```css
.container {
    display: grid;
}
```

与弹性盒子不同的是，在定义网格后，网页并不会马上发生变化。因为display: grid的声明只创建了一个只有一列的网格，所以你的子项还是会像正常布局流那样从上而下一个接一个的排布。

为了让我们的容器看起来更像一个网格，我们要给刚定义的==网格加一些列==。那就让我们加三个宽度为200px的列。当然，这里可以用任何长度单位，包括百分比。

```css
.container {
    display: grid;
    grid-template-columns: 200px 200px 200px;
}
```

# 使用 fr 单位的灵活网格

除了长度和百分比，我们也可以用fr这个单位来灵活地定义网格的行与列的大小。==这个单位表示了可用空间的一个比例==

```css
.container {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
}
```

# 网格间隙

使用 grid-column-gap (en-US) 属性来定义列间隙；使用 grid-row-gap (en-US) 来定义行间隙；使用 grid-gap (en-US) 可以同时设定两者。  

```css
.container {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr;
    grid-gap: 20px;
}
```

### 显式网格与隐式网格

显式网格是我们用grid-template-columns 或 grid-template-rows 属性创建的。而隐式网格则是当有内容被放到网格外时才会生成的。显式网格与隐式网格的关系与弹性盒子的 main 和 cross 轴的关系有些类似。

隐式网格中生成的行/列大小是参数默认是auto，大小会根据放入的内容自动调整。当然，你也可以使用grid-auto-rows和grid-auto-columns属性手动设定隐式网格的大小。下面的例子将grid-auto-rows设为了100px，然后你可以看到那些隐式网格中的行（因为这个例子里没有设定grid-template-rows，因此，所有行都位于隐式网格内）现在都是 100 像素高了。

简单来说，隐式网格就是为了放显式网格放不下的元素，浏览器根据已经定义的显式网格自动生成的网格部分。

==可用来设置默认行大小==

```css
.container {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  grid-auto-rows: 100px;
  grid-gap: 20px;
}
```

# 基于线的元素放置

在定义完了网格之后，我们要把元素放入网格中。我们的网格有许多分隔线

我们根据这些分隔线来放置元素，通过以下属性来指定从那条线开始到哪条线结束。

- grid-column-start
- grid-column-end
- grid-row-start
- grid-row-end

这些属性的值均为分隔线序号，你也可以用以下缩写形式来同时指定开始与结束的线。

- grid-column
- grid-row

注意开始与结束的线的序号要使用/符号分开。

```css
header {
  grid-column: 1 / 3;
  grid-row: 1;
}

article {
  grid-column: 2;
  grid-row: 2;
}

aside {
  grid-column: 1;
  grid-row: 2;
}

footer {
  grid-column: 1 / 3;
  grid-row: 3;
}
```

# 使用 grid-template-areas 属性放置元素

另一种往网格放元素的方式是用grid-template-areas属性，并且你要命名一些元素并在属性中使用这些名字作为一个区域。

```css
.container {
  display: grid;
  grid-template-areas:
      "header header"
      "sidebar content"
      "footer footer";
  grid-template-columns: 1fr 3fr;
  grid-gap: 20px;
}

header {
  grid-area: header;
}

article {
  grid-area: content;
}

aside {
  grid-area: sidebar;
}

footer {
  grid-area: footer;
}
```

grid-template-areas属性的使用规则如下：

- 你需要填满网格的每个格子
- 对于某个横跨多个格子的元素，重复写上那个元素grid-area属性定义的区域名字
- 所有名字只能出现在一个连续的区域，不能在不同的位置出现
- 一个连续的区域必须是一个矩形
- 使用.符号，让一个格子留空

# eg

```css
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    
    <style>
        .item {
            border: 2px solid red;
        }
        #father {
            display: grid;
            border: 2px solid green;
            padding: 5px;
            grid-template-columns: 1fr 1fr 1fr;
            grid-gap: 2px;
            grid-auto-rows: 100px;
        }

        #div1{
            grid-column: 1/4;
            grid-row: 1/3;
        }

    </style>
</head>
<body>

<div id="father">

<div id="div1" class="item">
    <span>div1</span>
</div>

<div id="div2" class="item">
    <span>div2</span>
</div>

<div id="div3" class="item">
    <span>div3</span>
</div>

<div id="div4" class="item">
    <span>div4</span>
</div>

<div id="div5" class="item">
    <span>div5</span>
</div>

<div id="div6" class="item">
    <span>div6</span>
</div>

<div id="div7" class="item">
    <span>div7</span>
</div>

</div>

</body>
</html>
```