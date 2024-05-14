#  Store

### Store 是什么？

Store (如 Pinia) 是一个保存状态和业务逻辑的实体，它并不与你的组件树绑定。换句话说，它承载着全局状态。它有点像一个永远存在的组件，每个组件都可以读取和写入它。它有三个概念，state、getter 和 action，我们可以假设这些概念相当于组件中的 data、 computed 和 methods

### 定义 Store

```js
import { defineStore } from 'pinia'

// 你可以对 `defineStore()` 的返回值进行任意命名，但最好使用 store 的名字，同时以 `use` 开头且以 `Store` 结尾。(比如 `useUserStore`，`useCartStore`，`useProductStore`)
// 第一个参数是你的应用中 Store 的唯一 ID。
export const useStore = defineStore('main', {
  // 其他配置...
})
```

==Store 是用 defineStore() 定义的，它的第一个参数要求是一个独一无二的名字。为了养成习惯性的用法，将返回的函数命名为 use... 是一个符合组合式函数风格的约定。==

defineStore() 的第二个参数可接受两类值：Setup 函数或 Option 对象。

###### Setup Store

另一种定义 store 的可用语法。与 Vue 组合式 API 的 setup 函数 相似，我们可以传入一个函数，该函数定义了一些响应式属性和方法，==并且返回一个带有我们想暴露出去的属性和方法的对象== 

```js
import { defineStore } from 'pinia'
export const useCounterStore = defineStore('counter', () => {
  const count = ref(0)
  function increment() {
    count.value++
  }

  return { count, increment }
})
```

在 Setup Store 中:

- ref() 就是 state 属性
- computed() 就是 getters
- function() 就是 actions

### 使用store

```js
import { useCounterStore } from '@/stores/counter'

export default {
  setup() {
    const store = useCounterStore()

    return {
      // 为了能在模板中使用它，你可以返回整个 Store 实例。
      store,
    }
  },
}
```