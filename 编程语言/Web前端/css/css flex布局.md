# 指定元素的布局为flex

display:flex;

# flex模型说明

![image](https://developer.mozilla.org/en-US/docs/Learn/CSS/CSS_layout/Flexbox/flex_terms.png)

- **主轴**（main axis）是沿着 flex 元素放置的方向延伸的轴（比如页面上的横向的行、纵向的列）。该轴的开始和结束被称为 main start 和 main end。
- **交叉轴**（cross axis）是垂直于 flex 元素放置方向的轴。该轴的开始和结束被称为 cross start 和 cross end。
- 设置了 display: flex 的父元素被称之为 flex 容器（flex container）。
- 在 flex 容器中表现为弹性的盒子的元素被称之为 **flex 项**（flex item）

# 指定主轴

在父容器中添加

```css
flex-direction: column;
```

# 弹性盒子子元素溢出解决

在父元素中添加

```css
flex-wrap: wrap; /*任何溢出都会向下移动到下一行*/
```

子元素中添加

```css
flex: 200px; /*声明意味着每个声明将至少为 200px 宽*/
```

# flex 项的动态尺寸

eg:

```css
article {
  flex: 1;
}
```

这是一个无单位的比例值，表示每个 flex 项沿主轴的可用空间大小。占用的空间是在设置 padding 和 margin 之后剩余的空间。类似分数分母的关系

你还可以指定 flex 的最小值。

```css
article {
  flex: 1 200px;
}
```

# 水平和垂直对齐

```css
div {
  display: flex;
  align-items: center;
  justify-content: space-around;
}
```

==align-items 控制 flex 项在交叉轴上的位置。==

- 在上面规则中我们使用的 center 值会使这些项保持其原有的高度，但是会在交叉轴居中。这就是那些按钮垂直居中的原因。
- 你也可以设置诸如 flex-start 或 flex-end 这样使 flex 项在交叉轴的开始或结束处对齐所有的值。查看 align-items 了解更多。
- 默认的值是 stretch，其会使所有 flex 项沿着交叉轴的方向拉伸以填充父容器。如果父容器在交叉轴方向上没有固定宽度（即高度），则所有 flex 项将变得与最长的 flex 项一样长（即高度保持一致）。我们的第一个例子在默认情况下得到相等的高度的列的原因。

==justify-content 控制 flex 项在主轴上的位置==

- 默认值是 flex-start，这会使所有 flex 项都位于主轴的开始处。
- 你也可以用 flex-end 来让 flex 项到结尾处。
- center 在 justify-content 里也是可用的，可以让 flex 项在主轴居中。
- 而我们上面用到的值 space-around 是很有用的——它会使所有 flex 项沿着主轴均匀地分布，在任意一端都会留有一点空间。
- 还有一个值是 space-between，它和 space-around 非常相似，只是它不会在两端留下任何空间。

# flex 项排序

```css
button:first-child {
  order: 1;
}
```

- 所有 flex 项默认的 order 值是 0。
- order 值大的 flex 项比 order 值小的在显示顺序中更靠后。
- 相同 order 值的 flex 项按源顺序显示。所以假如你有四个元素，其 order 值分别是 2，1，1 和 0，那么它们的显示顺序就分别是第四，第二，第三，和第一
- 第三个元素显示在第二个后面是因为它们的 order 值一样，且第三个元素在源顺序中排在第二个后面。

# eg

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
            height: 1000px;
            width: 1000px;
            line-height: 100px;
            text-align: center;
            border: 1px solid red;
        }

        #father {
            display: flex;
            flex-direction: row;
            align-items: center;

        }

        #div1 {
            height: 150px;
            width: 150px;
        }

        #div2 {
            height: 150px;
            width: 150px;
        }

        #div3 {
            height: 150px;
            width: 150px;
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