# 组合方API编程方式

### eg

```
<template>
.....
</template>

<script setup>
.....
</script>

<style scoped>
.....
</style>
```

### 声明式渲染
 
Vue 的核心功能是声明式渲染：通过扩展于标准 HTML 的模板语法，我们可以根据 JavaScript 的状态来描述 HTML 应该是什么样子的。当状态改变时，HTML 会自动更新。 
 
我们可以使用 reactive() 函数创建一个响应式对象或数组：

```js
import { reactive } from 'vue'

const state = reactive({ count: 0 })
```

响应式对象其实是 JavaScript Proxy，其行为表现与一般对象相似。不同之处在于 Vue 能够跟踪对响应式对象属性的访问与更改操作。

reactive() 只适用于对象 (包括数组和内置类型，如 Map 和 Set)。而另一个 API ref() 则可以接受任何值类型。ref 会返回一个包裹对象，并在 .value 属性下暴露内部值

```html
<script setup>
import { ref } from 'vue'

// 组件逻辑
// 此处声明一些响应式状态
 const message = ref("hello world!");
 const myInfo = ref({name:"dundun"});
message.value = "11111";
myInfo.value.name = "hanhan";
  
</script>

<template>
  <h1>{{message + " " + myInfo.name}}</h1>
</template>
```


### 引用组件

直接 import 即可在template中使用

```js
import ChildComp from './ChildComp.vue'
```

```html
<ChildComp />
```

### 子组件定义props

在使用 <script setup> 的单文件组件中，props 可以使用 defineProps() 宏来声明：

```js
defineProps(['foo'])
```

除了使用字符串数组来声明 props 外，还可以使用对象的形式：

```js
// 使用 <script setup>
defineProps({
  title: String,
  likes: Number,
  // 必传，且为 String 类型
  propC: {
    type: String,
    required: true
  },
  // Number 类型的默认值
  propD: {
    type: Number,
    default: 100
  },
  // 自定义类型校验函数
  propF: {
    validator(value) {
      // The value must match one of these strings
      return ['success', 'warning', 'danger'].includes(value)
    }
  },
})


```

### 计算属性创建

```js
import { ref, computed } from 'vue'

const hideCompleted = ref(false)
const todos = ref([
  /* ... */
])

const filteredTodos = computed(() => {
  // 根据 `todos.value` & `hideCompleted.value`
  // 返回过滤后的 todo 项目
})
```

### 子组件定义事件 并触发

```js
// 声明触发的事件
const emit = defineEmits(['enlarge-text'])

emit('enlarge-text')
```

==For item-edited event, you'll need to pass the item.id and the special $event variable. This is a special Vue variable used to pass event data to methods.==








==**后面得笔记使用的是选项式 API 编程方式**==

# 环境搭建

### 1.安装vue/cli最新稳定版本

对于 Vue 3，应该使用 npm 上可用的 Vue CLI v4.5 作为 @vue/cli。

```
npm install -g @vue/cli@next
```

安装完后可以使用命令

```
vue --version
```

来查看版本

### 2.创建项目

```
> npm init vue@latest
```

### 3.运行

在项目被创建后，通过以下步骤安装依赖并启动开发服务器

```
> cd <your-project-name>
> npm install
> npm run dev
```

### 4.发布

当你准备将应用发布到生产环境时，请运行：

```
> npm run build
```

此命令会在 ./dist 文件夹中为你的应用创建一个生产环境的构建版本

# 第一个Vue应用

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <!-- 导入vue -->
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script> 
</head>
<body>

<div id="app">
    {{message}}
</div>

<script>
    Vue.createApp({
        data(){
            return {
                message:"Hello,vue"
            }
        }
    }).mount("#app");
</script>

</body>
</html>
```
# 条件渲染（if判断）

### v-if

v-if 指令用于条件性地渲染一块内容。这块内容只会在指令的表达式返回真值时才被渲染。

```html
<h1 v-if="awesome">Vue is awesome!</h1>
```

eg : 

```html
<div id="app">
    <h1 v-if="count == 0">count == 0</h1>
    <h1 v-else-if="count == 1">count == 1</h1>
    <h1 v-else>count != 0 && count !=1</h1>
</div>

<script>
    let ve = Vue.createApp(
        {
            data(){
                return {
                    count:0
                };
            }
        }
    ).mount("#app");
</script>
```

###### <template> 上的 v-if

因为 v-if 是一个指令，他必须依附于某个元素。但如果我们想要切换不止一个元素呢？在这种情况下我们可以在一个 <template> 元素上使用 v-if，这只是一个不可见的包装器元素，最后渲染的结果并不会包含这个 <template> 元素.

```html
<template v-if="ok">
  <h1>Title</h1>
  <p>Paragraph 1</p>
  <p>Paragraph 2</p>
</template>
```

v-else 和 v-else-if 也可以在 <template> 上使用。

eg: 

```html
<div id="app">
    <h1 v-if="count == 0">count == 0</h1>
    <h1 v-else-if="count == 1">count == 1</h1>
    <template v-else>
        <h1>template</h1>
        <h1>count != 0 && count != 1</h1>
    </template>
</div>

<script>
    let ve = Vue.createApp(
        {
            data(){
                return {
                    count:0
                };
            }
        }
    ).mount("#app");
</script>
```

# 列表渲染(for循环)

我们可以使用 v-for 指令基于一个数组来渲染一个列表。v-for 指令的值需要使用 item in items 形式的特殊语法，其中 items 是源数据的数组，而 item 是迭代项的别名：

```html
<div id="app">
    <ol>
        <li v-for="item in items">{{item.message}}</li>
    </ol>
</div>

<script>
    let ve = Vue.createApp({
        data(){
            return {
                items:[{message:"Linux"},{message:"C++"},{message:"C"},{message:"Kernel"}]
            };
        }
    }).mount("#app");
</script>
```

在 v-for 块中可以完整地访问父作用域内的属性和变量。v-for 也支持使用可选的第二个参数表示当前项的位置索引。

```html
<li v-for="(item, index) in items">{{item.message}}</li>
```

# 绑定属性

给html标签绑定一个属性：双大括号不能在 HTML attributes 中使用。想要响应式地绑定一个 attribute，应该使用 v-bind 指令

```html
<div v-bind:id="dynamicId"></div>
```

v-bind 指令指示 Vue 将元素的 id attribute 与组件的 dynamicId 属性保持一致。如果绑定的值是 null 或者 undefined，那么该 attribute 将会从渲染的元素上移除。

因为 v-bind 非常常用，我们提供了特定的简写语法

```html
<div :id="dynamicId"></div>
```


# 计算属性

计算属性会自动跟踪其计算中所使用的到的其他响应式状态，并将它们收集为自己的依赖。计算结果会被缓存，并只有在其依赖发生改变时才会被自动更新。

```html
<script>
export default {
  data() {
    return {
      author: {
        name: 'John Doe',
        books: [
          'Vue 2 - Advanced Guide',
          'Vue 3 - Basic Guide',
          'Vue 4 - The Mystery'
        ]
      }
    }
  },
  computed: {
    // 一个计算属性的 getter
    publishedBooksMessage() {
      // `this` 指向当前组件实例
      return this.author.books.length > 0 ? 'Yes' : 'No'
    }
  }
}
</script>

<template>
<p>Has published books:</p>
<span>{{ publishedBooksMessage }}</span>
</template>
```

我们在这里定义了一个计算属性 publishedBooksMessage

更改此应用的 data 中 books 数组的值后，可以看到 publishedBooksMessage 也会随之改变。

在模板中使用计算属性的方式和一般的属性并无二致。Vue 会检测到 this.publishedBooksMessage 依赖于 this.author.books，所以当 this.author.books 改变时，任何依赖于 this.publishedBooksMessage 的绑定都将同时更新

### 计算属性缓存 vs 方法    

若我们将同样的函数定义为一个方法而不是计算属性，两种方式在结果上确实是完全相同的，然而，不同之处在于计算属性值会基于其响应式依赖被缓存。一个计算属性仅会在其响应式依赖更新时才重新计算。这意味着只要 author.books 不改变，无论多少次访问

# 侦听器

有时我们需要响应性地执行一些“副作用”——例如，当一个数字改变时将其输出到控制台。我们可以通过侦听器来实现它：

```js
import { ref, watch } from 'vue'

const count = ref(0)

watch(count, (newCount) => {
  // 没错，console.log() 是一个副作用
  console.log(`new count is: ${newCount}`)
})
```

watch() 可以直接侦听一个 ref，并且只要 count 的值改变就会触发回调。

一个比在控制台输出更加实际的例子是当 ID 改变时抓取新的数据。

# 绑定事件

我们可以使用 ==v-on== 指令 (==简写为 @==) 来监听 DOM 事件，并在事件触发时执行对应的 JavaScript。用法：v-on:click="methodName" 或 @click="handler"。

事件处理器的值可以是：

- 内联事件处理器：事件被触发时执行的内联 JavaScript 语句 (与 onclick 类似)。
- 方法事件处理器：一个指向组件上定义的方法的属性名或是路径。

### 内联事件处理器

内联事件处理器通常用于简单场景，例如：

```js
data() {
  return {
    count: 0
  }
}
```

```html
<button @click="count++">Add 1</button>
<p>Count is: {{ count }}</p>
```

### 方法事件处理器

随着事件处理器的逻辑变得愈发复杂，内联代码方式变得不够灵活。因此 v-on 也可以接受一个方法名或对某个方法的调用。

```js
data() {
  return {
    name: 'Vue.js'
  }
},
methods: {
  greet(event) {
    // 方法中的 `this` 指向当前活跃的组件实例
    alert(`Hello ${this.name}!`)
    // `event` 是 DOM 原生事件
    if (event) {
      alert(event.target.tagName)
    }
  }
}
```

```html
<button @click="greet">Greet</button>
```

方法事件处理器会自动接收原生 DOM 事件并触发执行。在上面的例子中，我们能够通过被触发事件的 event.target.tagName 访问到该 DOM 元素。

eg:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <!-- 导入vue -->
    <script src="../vue.global.js"></script> 
</head>
<body>

<div id="app">
    <!-- 内联事件处理器 -->
    <div>
        <button @click="count1++">Click me</button>
        <span>{{count1}}</span>
    </div>
    <!-- 方法事件处理器 -->
    <div>
        <button @click="countPlus">Click me</button>
        <span>{{count2}}</span>
    </div>
</div>

<script>
    let ve = Vue.createApp({
        data(){
            return {count1:0,
                    count2:100};
        },
        methods:{
            countPlus(){
                this.count2--;
            }
        }
    }).mount(app);
</script>

</body>
</html>
```

# 表单输入绑定

在前端处理表单时，我们常常需要将表单输入框的内容同步给 JavaScript 中相应的变量。手动连接值绑定和更改事件监听器可能会很麻烦：

```html
<input
  :value="text"
  @input="event => text = event.target.value">
```
v-model 指令帮我们简化了这一步骤：

```html
<input v-model="text">
```

另外，v-model 还可以用于各种不同类型的输入，<textarea>、<select> 元素。它会根据所使用的元素自动使用对应的 DOM 属性和事件组合：

- 文本类型的 <input> 和 <textarea> 元素会绑定 value property 并侦听 input 事件
- <input type="checkbox"> 和 <input type="radio"> 会绑定 checked property (如果设置了元素value属性，则会绑定value property)并侦听 change 事件
- <select> 会绑定 value property 并侦听 change 事件

eg:

```html
<div id="app">
    <div>
        <span>性别：</span>
        <input type="radio" name="sex" v-model="sexChoose" value="男"><span>男</span>
        <input type="radio" name="sex" v-model="sexChoose" value="女"><span>女</span>
        <input type="radio" name="sex" v-model="sexChoose" value="other"><span>other</span>
    </div>

    <div>
        <span>您选中了：{{sexChoose}}</span>
    </div>
</div>

<script>
    let ve = Vue.createApp({
        data(){
            return {
                sexChoose:""
            };
        }
    }).mount("#app");
</script>

```
# 组件基础

组件允许我们将 UI 划分为独立的、可重用的部分，并且可以对每个部分进行单独的思考。在实际应用中，组件常常被组织成层层嵌套的树状结构

### 定义组件

当使用构建步骤时，我们一般会将 Vue 组件定义在一个单独的 .vue 文件中，这被叫做单文件组件 (简称 SFC)：

ButtonCounter.vue:

```html
<script>
export default {
  data() {
    return {
      count: 0
    }
  }
}
</script>

<template>
  <button @click="count++">You clicked me {{ count }} times.</button>
</template>
```

### 使用组件

要使用一个子组件，我们需要在父组件中导入它。假设我们把计数器组件放在了一个叫做 ButtonCounter.vue 的文件中。

若要将导入的组件暴露给模板，我们需要在 components 选项上注册它。这个组件将会以其注册时的名字作为模板中的标签名。

```html
<script>
import ButtonCounter from './ButtonCounter.vue'

export default {
  components: {
    ButtonCounter
  }
}
</script>

<template>
  <h1>Here is a child component!</h1>
  <ButtonCounter />
</template>
```

### 传递props(父组件向子组件传递值)


要向子组件中传递数据，这就会使用到props。

Props 是一种特别的 attributes，你可以在组件上声明注册。如要传递给博客文章组件一个标题，我们必须在博客文章组件的 props 列表上声明它。这里要用到 props 选项：


```html
<!-- BlogPost.vue -->
<script>
export default {
  props: ['title']
}
</script>

<template>
  <h4>{{ title }}</h4>
</template>
```

当一个值被传递给 prop 时，它将成为该组件实例上的一个属性。该属性的值可以像其他组件属性一样，在模板和组件的 this 上下文中访问。

一个组件可以有任意多的 props，默认情况下，所有 prop 都接受任意类型的值。

当一个 prop 被注册后，可以像这样以自定义 attribute 的形式传递数据给它：

```html
<BlogPost title="My journey with Vue" />
<BlogPost title="Blogging with Vue" />
<BlogPost title="Why Vue is so fun" />
```

eg:

创建组件，并使其能接受数据

BlogPost.vue:

```html
<script>
export default{
    props:["title","content"]
}
</script>

<template>
    <div>
        <h1>{{title}}</h1>
        <p>{{content}}</p>
    </div>
</template>
```

App.vue:

```html
<script>
import BlogPost from './components/BlogPost.vue'

export default{
    data(){
        return {
      posts: [
        { content:'[Vue warn]: Failed to resolve component: counter' , title: 'My journey with Vue' },
        { content:'If this is a native custom element, make sure to exclude it from component resolution via compilerOptions', title: 'Blogging with Vue' },
        { content:'Failed to resolve component: counter', title: 'Why Vue is so fun' }
      ]
    }
    },
    components:{
        BlogPost
    }
}

</script>

<template>
    <div >
        <BlogPost
        v-for="post in posts"
        :content="post.content"
        :title="post.title"
        />
    </div>
</template>

<style>
</style>

```

### 监听事件（子组件向父组件发送事件）

#### 定义事件

首先在子组件中，我们可以通过 emits 选项来声明需要抛出的事件：

```html
<!-- BlogPost.vue -->
<script>
export default {
  props: ['title'],
  emits: ['enlarge-text']
}
</script>
```

#### 发送事件

然后子组件可以通过调用内置的 $emit 方法，通过传入事件名称来抛出一个事件

```html
<!-- BlogPost.vue, 省略了 <script> -->
<template>
  <div class="blog-post">
    <h4>{{ title }}</h4>
    <button @click="$emit('enlarge-text')">Enlarge text</button>
  </div>
</template>
```

#### 监听事件

最后父组件可以通过 v-on 或 @ 来选择性地监听子组件上抛的事件，就像监听原生 DOM 事件那样

```html
<template>
    <div :style="{ fontSize : postFontSize + 'em'}">
        <BlogPost
        v-for="post in posts"
        :content="post.content"
        :title="post.title"
        @enlarge-text="postFontSize += 0.1"
        />
    </div>
</template>
```

#### 事件参数

有时候我们会需要在触发事件时附带一个特定的值。在这个场景下，我们可以给 $emit 提供一个额外的参数：

```html
<button @click="$emit('increaseBy', 1)">
  Increase by 1
</button>
```

然后我们在父组件中监听事件，我们可以先简单写一个内联的箭头函数作为监听器，此函数会接收到事件附带的参数：

```html
<MyButton @increase-by="(n) => count += n" />
```

或者，也可以用一个组件方法来作为事件处理函数：

```html
<MyButton @increase-by="increaseCount" />
```

该方法也会接收到事件所传递的参数：

```js
methods: {
  increaseCount(n) {
    this.count += n
  }
}
```

#### 事件校验

要为事件添加校验，那么事件可以被赋值为一个函数，接受的参数就是抛出事件时传入 this.$emit 的内容，返回一个布尔值来表明事件是否合法。

```js
export default {
  emits: {
    // 没有校验
    click: null,

    // 校验 submit 事件
    submit: ({ email, password }) => {
      if (email && password) {
        return true
      } else {
        console.warn('Invalid submit event payload!')
        return false
      }
    }
  },
  methods: {
    submitForm(email, password) {
      this.$emit('submit', { email, password })
    }
  }
}
```

### 插槽(父组件向子组件传递内容)

==主要用于子组件接收父组件传递过来的模板内容==

一些情况下我们会希望能和 HTML 元素一样向组件中传递内容：

```html
<AlertBox>
  Something bad happened.
</AlertBox>
```

这可以通过 Vue 的自定义 <slot> 元素来实现：

```html
<template>
  <div class="alert-box">
    <strong>This is an Error for Demo Purposes</strong>
    <slot />
  </div>
</template>

<style scoped>
.alert-box {
  /* ... */
}
</style>
```

如上所示，我们使用 <slot> 作为一个占位符，父组件传递进来的内容就会渲染在这里。

#### 默认内容

在外部没有提供任何内容的情况下，可以为插槽指定默认内容。比如有这样一个组件

```html
<button type="submit">
  <slot>
    Submit <!-- 默认内容 -->
  </slot>
</button>
```

#### 具名插槽

有时在一个组件中包含多个插槽出口是很有用的。举例来说，在一个 <BaseLayout> 组件中，有如下模板：

```html
<div class="container">
  <header>
    <!-- 标题内容放这里 -->
  </header>
  <main>
    <!-- 主要内容放这里 -->
  </main>
  <footer>
    <!-- 底部内容放这里 -->
  </footer>
</div>
```

对于这种场景，<slot> 元素可以有一个特殊的 attribute name，用来给各个插槽分配唯一的 ID，以确定每一处要渲染的内容：

```html
<div class="container">
  <header>
    <slot name="header"></slot>
  </header>
  <main>
    <slot></slot>
  </main>
  <footer>
    <slot name="footer"></slot>
  </footer>
</div>
```

这类带 name 的插槽被称为具名插槽 (named slots)。没有提供 name 的 <slot> 出口会隐式地命名为“default”

在父组件中使用 <BaseLayout> 时，我们需要一种方式将多个插槽内容传入到各自目标插槽的出口。此时就需要用到具名插槽了：

要为具名插槽传入内容，我们需要使用一个含 v-slot 指令的 <template> 元素，并将目标插槽的名字传给该指令

```html
<BaseLayout>
  <template v-slot:header>
    <!-- header 插槽的内容放这里 -->
  </template>
</BaseLayout>
```

v-slot 有对应的简写 #，因此 <template v-slot:header> 可以简写为 <template #header>。其意思就是“将这部分模板片段传入子组件的 header 插槽中”

#### 作用域插槽

访问到子组件的状态

然而在某些场景下插槽的内容可能想要同时使用父组件域内和子组件域内的数据。要做到这一点，我们需要一种方法来让子组件在渲染时将一部分数据提供给插槽

- ==默认插槽如何接受 props==

```html
<!-- <MyComponent> 的模板 -->
<div>
  <slot :text="greetingMessage" :count="1"></slot>
</div>
```

```html
<MyComponent v-slot="slotProps">
  {{ slotProps.text }} {{ slotProps.count }}
</MyComponent>
```

子组件传入插槽的 props 作为了 v-slot 指令的值，可以在插槽内的表达式中访问

- ==具名作用域插槽==

具名作用域插槽的工作方式也是类似的，插槽 props 可以作为 v-slot 指令的值被访问到：v-slot:name="slotProps"。当使用缩写时是这样：

```html
<MyComponent>
  <template #header="headerProps">
    {{ headerProps }}
  </template>

  <template #default="defaultProps">
    {{ defaultProps }}
  </template>

  <template #footer="footerProps">
    {{ footerProps }}
  </template>
</MyComponent>
```

向具名插槽中传入 props：

```html
<slot name="header" message="hello"></slot>
```

注意插槽上的 name 是一个 Vue 特别保留的 attribute，不会作为 props 传递给插槽。因此最终 headerProps 的结果是 { message: 'hello' }。



# 组件生命周期

每个 Vue 组件实例在创建时都需要经历一系列的初始化步骤，比如设置好数据侦听，编译模板，挂载实例到 DOM，以及在数据改变时更新 DOM。在此过程中，它也会运行被称为生命周期钩子的函数，让开发者有机会在特定阶段运行自己的代码。

### 注册周期钩子

举例来说，mounted 钩子可以用来在组件完成初始渲染并创建 DOM 节点后运行代码：

```html
export default {
  mounted() {
    console.log(`the component is now mounted.`)
  }
}
```

还有其他一些钩子，会在实例生命周期的不同阶段被调用，最常用的是 mounted、updated 和 unmounted。

### 生命周期图示

![image](https://cn.vuejs.org/assets/lifecycle.16e4c08e.png)

### eg：加载网络数据

```html
<script>
import BlogPost from './components/BlogPost.vue'

export default{
    data(){
        return {
            items:[]

        };
    },
    mounted(){
        const fetchPromise = fetch('https://mdn.github.io/learning-area/javascript/apis/fetching-data/can-store/products.json');
        fetchPromise
        .then( response => response.json() )
        .then(
            data => {
                this.items = data
            }
        );

    }
}

</script>

<template>
   <div v-for="item in items" class="item">
        <p>name  : {{item.name}}</p>
        <p>price : {{item.price}}</p>
        <p>type  : {{item.type}}</p>
   </div>
</template>

<style>

.item {
    border: 1px solid red;
    margin-top: 2px;
    background-color: green;
}

</style>

```


# 资料

https://cn.vuejs.org/