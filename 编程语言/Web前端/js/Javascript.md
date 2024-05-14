# 快速入门

### 引入JavaScript

- ==script标签引入js代码==

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

<script>
    alert("Hello,world");
</script>
</body>
</html>
```

- ==外部引入 (推荐)==

```css
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    <script src="js/index.js" defer></script>
</head>
<body>

</body>
</html>
```

js/index.js:
```javascript
```

# 基本语法入门

### 变量

###### 声明变量

```javascript
let myName;
let myAge;
```

###### 变量类型

- ==Number==

```javascript
let myAge = 17;
```

- ==Boolean==

```javascript
let iAmAlive = true;
```

- ==String==

```javascript
let dolphinGoodbye = 'So long and thanks for all the fish';

let len = dolphinGoodbye.length;//字符串的长度

dolphinGoodbye[0];//检索特定字符

dolphinGoodbye.indexOf(long);//在字符串中查找子字符串,并返回其所在位置，没有则返回-1

dolphinGoodbye.slice(0,3);//提取子串
```

- ==Array==

```javascript
let myNameArray = ['Chris', 'Bob', 'Jim'];
let myNumberArray = [10,15,40];

myNumberArray.length;//获取数组长度

let myData = 'Manchester,London,Liverpool,Birmingham,Leeds,Carlisle';
let myArray = myData.split(',');//字符串转数组

let myNewString = myArray.join(',');//数组转字符串
myNewString;


myArray.push('Cardiff');//添加元素到数组末尾
myArray.pop();//从数组末尾弹出一个元素  

myArray.unshift('Edinburgh');//在数组首部加一个元素
let removedItem = myArray.shift();//从数组首部移除一个元素


```

- ==Object==

```javascript
let dog = { name : 'Spot', breed : 'Dalmatian' };
```

- ==获取变量的类型==

```javascript
let myVar = 10;
typeof myVar;

```

### 条件语句

###### if ... else 语句

```javascript
if (condition1) {
  code to run if condition1 is true
} else if(condition2) {
  code to run if condition2 is true
} else {
  run some other code instead
}
```

###### switch语句

```javascript
switch (expression) {
  case choice1:
    run this code
    break;

  case choice2:
    run this code instead
    break;

  // include as many cases as you like

  default:
    actually, just run this code
}
```

### 循环

```javascript
for (initializer; exit-condition; final-expression) {
  // code to run
}
```

### 函数

```javascript
function myFunction() {
  alert('hello');
}

myFunction()
```

###### 匿名函数

```javascript
function() {
  alert('hello');
}
```

###### 箭头函数

```javascript
textBox.addEventListener('keydown', (event) => {
  console.log(`You pressed "${event.key}".`);
});
```

如果函数只有一条语句在“{}”中，则可以省略“{}”

```javascript
textBox.addEventListener('keydown', (event) => console.log(`You pressed "${event.key}".`));
```

如果函数仅仅只接受一个参数，可以把“（）”省略

```javascript
textBox.addEventListener('keydown', event => console.log(`You pressed "${event.key}".`));
```

如果函数体仅仅包含一条语句，且需要返回值时，可以将return关键字省略（也必须将“{}”省略）

```javascript
let myFunc = num =>  num * num;

console.log(myFunc(20))
```

### 对象

###### 构造函数与继承

```javascript
class Person{
    name;
    constructor(name){//构造函数
        this.name = name;
    }

    introduceSelf(){
        console.log(`Hi! I'm ${this.name}`);
    }
}

class Professor extends Person{//继承
    teaches;

    constructor(name,teaches){
        super(name);
        this.teaches = teaches;
    }
    
    introduceSelf() {
        console.log(`My name is ${this.name}, and I will be your ${this.teaches} professor.`);
    }

    grade(paper) {
        const grade = Math.floor(Math.random() * (5 - 1) + 1);
        console.log(grade);
    }
}

const walsh = new Professor('Walsh', 'Psychology');
walsh.introduceSelf();  // 'My name is Walsh, and I will be your Psychology professor'

walsh.grade('my paper'); // some random grade
```

###### 封装

```javascript
class Student extends Person {

    #year;//#year 是一个私有数据属性 ， 也可以用#声明私有方法
  
    constructor(name, year) {
      super(name);
      this.#year = year;
    }
  
  
    introduceSelf() {
      console.log(`Hi! I'm ${this.name}, and I'm in year ${this.#year}.`);
    }
  
    canStudyArchery() {
      return this.#year > 1;
    }
  
}

const summers = new Student('Summers', 2);

summers.introduceSelf(); // Hi! I'm Summers, and I'm in year 2.
summers.canStudyArchery(); // true

summers.#year; // SyntaxError
```

###### ES6 对象新特性

- 对象简写

对于对象的属性与参数的名称相同的这样的代码：

```js
name="hanhan";
age = 3;

let info = {
    name:name,
    age:age
}

console.log(info.name)//输出hanhan
```

我们可以简写为:

```js
name="hanhan";
age = 3;

let info = {
    name,
    age
}

console.log(info.name)//输出hanhan
```

- 对象解构

用于快速提取对象的多个字段：

```js
let cat = {
    name:"hanhan",
    age:3,
    weight:13
};

let {name,age,weight} = cat;

console.log(name);
console.log(age);
```

- 传播操作符

```js
let cat = {
    name:"hanhan",
    age:3,
    weight:13,
    money:2000,
    pay(){
        console.log(`You need to pay ${this.money}`)
    }
};

let {name,age,...cat2} = cat;

console.log(name);
console.log(age);

console.log(cat2)
```

output:

```
hanhan
3
{weight: 13, money: 2000, pay: ƒ}
```         


# 使用JSON数据

- parse(): 以文本字符串形式接受 JSON 对象作为参数，并返回相应的对象。
- stringify(): 接收一个对象作为参数，返回一个对应的 JSON 字符串。


```javascript
let myString = '{"name" : "Chris", "age" : "38"}';

myObject = JSON.parse(myString);
console.log(myObject.name);

console.log(JSON.stringify(myObject));
```

# 异步JavaScript

Promise 是现代 JavaScript 中异步编程的基础，是一个由异步函数返回的可以向我们指示当前操作所处的状态的==对象==。在 Promise 返回给调用者的时候，操作往往还没有完成，但 Promise 对象可以让我们操作最终完成时对其进行处理（无论成功还是失败）。

在基于 Promise 的 API 中，异步函数会启动操作并返回 Promise 对象。然后，你可以将处理函数附加到 Promise 对象上，当操作完成时（成功或失败），这些处理函数将被执行。

### 从服务端获取数据

```javaScript
const fetchPromise = fetch('https://mdn.github.io/learning-area/javascript/apis/fetching-data/can-store/products.json');

console.log(fetchPromise);

fetchPromise.then( response => {
  console.log(`已收到响应：${response.status}`);
});

console.log("已发送请求……");
```

- 调用 fetch() API，并将返回值赋给 fetchPromise 变量。
- 紧接着，输出 fetchPromise 变量，输出结果应该像这样：Promise { <state>: "pending" }。这告诉我们有一个 Promise 对象，它有一个 state属性，值是 "pending"。"pending" 状态意味着操作仍在进行中。
- 将一个处理函数传递给 Promise 的 then() 方法。当（如果）获取操作成功时，Promise 将调用我们的处理函数，传入一个包含服务器的响应的 Response 对象。
- 输出一条信息，说明我们已经发送了这个请求。

完整的输出结果应该是这样的：

```
Promise { <state>: "pending" }
已发送请求……
已收到响应：200
```

### 链式使用 Promise

```JavaScript
const fetchPromise = fetch('bad-scheme://mdn.github.io/learning-area/javascript/apis/fetching-data/can-store/products.json');

fetchPromise
  .then( response => {
    if (!response.ok) {
      throw new Error(`HTTP 请求错误：${response.status}`);
    }
    return response.json();
  })
  .then( json => {
    console.log(json[0].name);
  })
  .catch( error => {//catch() 添加到 Promise 链的末尾，它就可以在任何异步函数失败时被调用
    console.error(`无法获取产品列表：${error}`);
  });
```

catch() 添加到 Promise 链的末尾，它就可以在任何异步函数失败时被调用

### Promise 术语

首先，Promise 有三种状态：

- 待定（pending）：初始状态，既没有被兑现，也没有被拒绝。这是调用 fetch() 返回 Promise 时的状态，此时请求还在进行中。
- 已兑现（fulfilled）：意味着操作成功完成。当 Promise 完成时，它的 then() 处理函数被调用。
- 已拒绝（rejected）：意味着操作失败。当一个 Promise 失败时，它的 catch() 处理函数被调用。

注意，这里的“成功”或“失败”的含义取决于所使用的 API：例如，fetch() 认为服务器返回一个错误（如404 Not Found）时请求成功，但如果网络错误阻止请求被发送，则认为请求失败。

### 合并使用多个 Promise

当你的操作由几个异步函数组成，而且你需要在开始下一个函数之前完成之前每一个函数时，你需要的就是 Promise 链。但是在其他的一些情况下，你可能需要合并多个异步函数的调用，Promise API 为解决这一问题提供了帮助。

有时你需要所有的 Promise 都得到实现，但它们并不相互依赖。在这种情况下，将它们一起启动然后在它们全部被兑现后得到通知会更有效率。这里需要 Promise.all() 方法。它接收一个 Promise 数组，并返回一个单一的 Promise。

由Promise.all()返回的 Promise：

- 当且仅当数组中所有的 Promise 都被兑现时，才会通知 then() 处理函数并提供一个包含所有响应的数组，数组中响应的顺序与被传入 all() 的 Promise 的顺序相同。
- 会被拒绝——如果数组中有任何一个 Promise 被拒绝。此时，catch() 处理函数被调用，并提供被拒绝的 Promise 所抛出的错误。

```JavaScript
const fetchPromise1 = fetch('https://mdn.github.io/learning-area/javascript/apis/fetching-data/can-store/products.json');
const fetchPromise2 = fetch('https://mdn.github.io/learning-area/javascript/apis/fetching-data/can-store/not-found');
const fetchPromise3 = fetch('https://mdn.github.io/learning-area/javascript/oojs/json/superheroes.json');

Promise.all([fetchPromise1, fetchPromise2, fetchPromise3])
  .then( responses => {
    for (const response of responses) {
      console.log(`${response.url}：${response.status}`);
    }
  })
  .catch( error => {
    console.error(`获取失败：${error}`)
  });
```

有时，你可能需要等待一组 Promise 中的某一个 Promise 的执行，而不关心是哪一个。在这种情况下，你需要 Promise.any()

### async 和 await

async 关键字为你提供了一种更简单的方法来处理基于异步 Promise 的代码。在一个函数的开头添加 async，就可以使其成为一个异步函数。

```JavaScript
async function myFunction() {
  // 这是一个异步函数
}
```

在异步函数中，你可以在调用一个返回 Promise 的函数之前使用 await 关键字。这使得代码在该点上等待，直到 Promise 被完成，这时 Promise 的响应被当作返回值，或者被拒绝的响应被作为错误抛出。

```JavaScript
async function fetchProducts() {
  try {
    // 在这一行之后，我们的函数将等待 `fetch()` 调用完成
    // 调用 `fetch()` 将返回一个“响应”或抛出一个错误
    const response = await fetch('https://mdn.github.io/learning-area/javascript/apis/fetching-data/can-store/products.json');
    if (!response.ok) {
      throw new Error(`HTTP 请求错误：${response.status}`);
    }
    // 在这一行之后，我们的函数将等待 `response.json()` 的调用完成
    // `response.json()` 调用将返回 JSON 对象或抛出一个错误
    const json = await response.json();
    console.log(json[0].name);
  }
  catch(error) {
    console.error(`无法获取产品列表：${error}`);
  }
}

fetchProducts();
```

这里我们调用 await fetch()，我们的调用者得到的并不是 Promise，而是一个完整的 Response 对象，就好像 fetch() 是一个同步函数一样。

我们甚至可以使用 try...catch 块来处理错误，就像我们在写同步代码时一样。

但请注意，这个写法只在异步函数中起作用。异步函数总是返回一个 Pomise，所以你不能做这样的事情：

```javaScript
async function fetchProducts() {
  try {
    const response = await fetch('https://mdn.github.io/learning-area/javascript/apis/fetching-data/can-store/products.json');
    if (!response.ok) {
      throw new Error(`HTTP 请求错误：${response.status}`);
    }
    const json = await response.json();
    return json;
  }
  catch(error) {
    console.error(`无法获取产品列表：${error}`);
  }
}

const json = fetchProducts();
console.log(json[0].name);   // json 是一个 Promise 对象，因此这句代码无法正常工作
```

### 实现基于 Promise 的 API

在这个示例中我们将会实现一个基于 promise 的 alarm API，叫做 alarm() 。它将以被唤醒人的名字和一个在人被唤醒前以毫秒为单位的延迟作为参数。在延迟之后，本函数将会发送一个包含需要被唤醒人名字的 "Wake up!" 消息。

###### 用 setTimeout() 包裹

我们将会使用 setTimeout() 来实现 alarm() 函数。setTimeout() 以一个回调函数和一个以毫秒为单位的延迟作为参数。当调用 setTimeout() 时，它将启动一个设置为给定延迟的计时器，当时间过期时，它就会调用给定的回调函数。

在下面的例子中，我们使用一个回调函数和一个 1000 毫秒的延迟调用 setTimeout()

```html
<button id="set-alarm">Set alarm</button>
<div id="output"></div>
```

```javascript
const output = document.querySelector('#output');
const button = document.querySelector('#set-alarm');

function setAlarm() {
  window.setTimeout(() => {
    output.textContent = 'Wake up!';
  }, 1000);
}

button.addEventListener('click', setAlarm);
```

###### Promise() 构造器

我们的 alarm() 函数返回一个在定时器过期时才会被兑现的 Promise。它将会传递一个 "Wake up!" 消息到 then() 处理器中，也会在当调用者提供一个负延迟值时拒绝这个 promise。

这里的关键组件是 Promise() 构造器。Promise() 构造器使用单个函数作为参数。我们把这个函数称作执行器（executor）。当你创建一个新的 promise 的时候你需要实现这个执行器。

这个执行器本身采用两个参数，这两个参数都是函数，通常被称作 ==resolve 和 reject==。在你的执行器实现里，==你调用原始的异步函数==。==如果异步函数成功了，就调用 resolve，如果失败了，就调用 reject==。如果执行器函数抛出了一个错误，reject 会被自动调用。你可以将任何类型的单个参数传递到 resolve 和 reject 中。

所以我们可以像下面这样实现 alarm()：

```javascript
function alarm(person, delay) {
  return new Promise((resolve, reject) => {
    if (delay < 0) {
      throw new Error('Alarm delay must not be negative');
    }
    window.setTimeout(() => {
      resolve(`Wake up, ${person}!`);
    }, delay);
  });
}
```
此函数创建并且返回一个新的 Promise。对于执行器中的 promise，我们：

- 检查 delay（延迟）是否为负数，如果是的话就抛出一个错误。
- 调用 window.setTimeout()，传递一个回调函数和 delay（延迟）。当计时器过期时回调会被调用，在回调函数内，我们调用了 resolve，并且传递了 "Wake up!" 消息。

###### 使用 alarm() API

这一部分同上一篇文章是相当相似的。我们可以调用 alarm()，在返回的 promise 中调用 then() 和 catch() 来设置 promise 兑现和拒绝状态的处理器。

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=s, initial-scale=1.0">
    <title>Document</title>
    <script src="js/index.js" defer></script>
</head>
<body>

<div>
    <span>Name:</span>
    <input type="text" id="name">
</div>

<div>
    <span>Delay:</span>
    <input type="number" id="delay">
</div>

<div>
    <button id="btn">set alarm</button>
</div>


<div id="output">

</div>

</body>
</html>
```

```javascript
const name = document.getElementById("name");
const delay = document.getElementById("delay");
const output = document.getElementById("output");
const btn = document.getElementById("btn");

name.value="Matilda";
delay.value = "1000";

function alarm(person,delay){
    return new Promise((resolve,reject)=>{
        if(delay < 0){
            throw new Error("Alarm delay must not be negative");
        }
        window.setTimeout(()=>{
            resolve(`Wake up, ${person}!`);
        },delay);
    });
}



btn.addEventListener('click',()=>{
alarm(name.value,delay.value).then(
    message => output.textContent=message
).catch(
    error => output.textContent = error
);
});
```

# DOM操作

### 选中元素

和 JavaScript 中的许多事情一样，有很多方法可以选择一个元素，并在一个变量中存储一个引用。==Document.querySelector()是推荐的主流方法，它允许你使用 CSS 选择器选择元素==，使用很方便

### 创建节点

Document.createElement()

```javascript
var para = document.createElement('p');//创建一个新的段落元素
```

### 添加节点

Node.appendChild()

```javascript
let sect = document.querySelector('section');
let para = document.createElement('p');
para.textContent = 'We hope you enjoyed the ride.';
sect.appendChild(para);
```

### 删除节点

Node.removeChild()

```javascript
sect.removeChild(linkPara);
```

要删除一个仅基于自身引用的节点可能稍微有点复杂，这也是很常见的。没有方法会告诉节点删除自己，所以你必须像下面这样操作

```javascript
linkPara.parentNode.removeChild(linkPara);
```

# 操作样式

- 第一种方法是直接在想要动态设置样式的元素内部添加内联样式。这是用HTMLElement.style (en-US)属性来实现。这个属性包含了文档中每个元素的内联样式信息。你可以设置这个对象的属性直接修改元素样式。

```javascript
para.style.color = 'white';
para.style.backgroundColor = 'black';
para.style.padding = '10px';
para.style.width = '250px';
para.style.textAlign = 'center';
```

- 现在我们改为使用 HTML 操作的常用方法 — Element.setAttribute() — 这里有两个参数，你想在元素上设置的属性，你要为它设置的值。在这种情况下，我们在段落中设置类名为 highlight：

```css
<style>
.highlight {
  color: white;
  background-color: black;
  padding: 10px;
  width: 250px;
  text-align: center;
}
</style>
```

```javascript
para.setAttribute('class', 'highlight');
```