# 原型链

在 JavaScript 中，（函数对象）函数（function）是允许拥有属性的。所有的函数会有一个特别的属性 —— ==prototype== 对象。如果该函数被做为构造函数，那么用它创建的对象，其__proto__会指向该函数的prototype属性，通常用该属性实现实列共享相同的数据与方法

javascript中的函数不同于其他的语言，它的每个函数都是作为一个对象被维护和运行的.

可以用function关键字定义一个函数，并为每个函数指定一个函数名，通过函数名来进行调用。在JavaScript解释执行时，函数都是被维护为一个对象，这就是要介绍的函数对象（Function Object）。

在JavaScript中，函数对象对应的类型是Function,也可以通过new Function()来创建一个函数对象

JavaScript引入Function类型并提供new Function()这样的语法是因为函数对象添加属性和方法就必须借助于Function这个类型。

==Function是所有函数对象的基础，而Object则是所有对象（包括函数对象）的基础==。在JavaScript中，任何一个对象都是Object的实例，因此，可以修改Object这个类型来让所有的对象具有一些通用的属性和方法，修改Object类型是通过prototype来完成的

```javascript
console.log(Object.__proto__ == Function.prototype) //true
console.log(Function.prototype.__proto__ == Object.prototype) //true
```

- 每个对象都有 __proto__ 属性，但只有函数对象才有 prototype 属性

资料：https://blog.csdn.net/geekwangminli/article/details/24475113

# for .. in语句便利一个对象的属性

```js
let cat = {
    name:'hanhan',
    age:'3',
    sex:'boy'
}

for(p in cat){
    console.log(p)
}
```

output:

```js
name
age
sex
```

# this 的词法

在箭头函数出现之前，每一个新函数都重新定义了自己的 this 值

箭头函数捕捉闭包上下文的this值

# 创建对象的三种方法

- 对象字面量

```js
let myObj = {name:"hanhan"}
```

- 构造函数

```js
function Cat(name){
    this.name = name
}

let cat = new Cat("hanhan")
```

- 使用 Object.create 方法

允许你为创建的对象选择一个原型对象

```js
let animal = {
    say:function(){
        console.log("miaomiaomiao")
    }
}

let cat = Object.create(animal)

```