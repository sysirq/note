# 安装

切换到vue项目目录下，运行：

```
npm install element-plus --save
```

# 使用

main.js:

```js
import { createApp } from 'vue'
import App from './App.vue'
//导入elementUI
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'


let app = createApp(App);

app.use(ElementPlus)

app.mount('#app')
```

# 资料

https://element-plus.org/zh-CN/