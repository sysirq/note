# vscode debug

```json
{
    "version": "0.2.0",
    "compounds": [
        {
            "name": "Main + renderer",
            "configurations": [
                "Main",
                "Renderer"
            ],
            "stopAll": true
        }
    ],
    "configurations": [
        {
            "name": "Renderer",
            "port": 9222,
            "request": "attach",
            "type": "chrome",
            "webRoot": "${workspaceFolder}"
        },
        {
            "name": "Main",
            "type": "node",
            "request": "launch",
            "cwd": "${workspaceFolder}",
            "runtimeExecutable": "${workspaceFolder}/node_modules/.bin/electron",
            "windows": {
                "runtimeExecutable": "${workspaceFolder}/node_modules/.bin/electron.cmd"
            },
            "args": [
                ".",
                "--remote-debugging-port=9222"
            ],
            "outputCapture": "std",
            "console": "integratedTerminal"
        }
    ]
}
```

# Preload

Electron's main process is a Node.js environment that has full operating system access.  On the other hand, renderer processes run web pages and do not run Node.js by default for security reasons.



A BrowserWindow's preload script runs in a context that has access to both the HTML DOM and a limited subset of Node.js and Electron APIs.

Preload scripts are injected before a web page loads in the renderer, similar to a Chrome extension's [content scripts](https://developer.chrome.com/docs/extensions/mv3/content_scripts/). To add features to your renderer that require privileged access, you can define [global](https://developer.mozilla.org/en-US/docs/Glossary/Global_object) objects through the [contextBridge](https://www.electronjs.org/docs/latest/api/context-bridge) API.



preload.js

```js
const { contextBridge } = require('electron')

contextBridge.exposeInMainWorld('versions', {
  node: () => process.versions.node,
  chrome: () => process.versions.chrome,
  electron: () => process.versions.electron
  // we can also expose variables, not just functions
})
```

main.js

```js
const { app, BrowserWindow } = require('electron')
const path = require('node:path')

const createWindow = () => {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  })

  win.loadFile('index.html')
}

app.whenReady().then(() => {
  createWindow()
})
```

At this point, the renderer has access to the `versions` global, so let's display that information in the window. This variable can be accessed via `window.versions` or simply `versions`. 

renderer.js

```js
const information = document.getElementById('info')
information.innerText = `This app is using Chrome (v${versions.chrome()}), Node.js (v${versions.node()}), and Electron (v${versions.electron()})`
```



# IPC

### Renderer to main (two-way)

use Electron's `ipcMain` and `ipcRenderer` modules for inter-process communication (IPC). To send a message from your web page to the main process, you can set up a main process handler with `ipcMain.handle` and then expose a function that calls `ipcRenderer.invoke` to trigger the handler in your preload script.



First, set up the `invoke` call in your preload script:

```js
const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('versions', {
  node: () => process.versions.node,
  chrome: () => process.versions.chrome,
  electron: () => process.versions.electron,
  ping: () => ipcRenderer.invoke('ping')
  // we can also expose variables, not just functions
})
```

Then, set up your `handle` listener in the main process. We do this *before* loading the HTML file so that the handler is guaranteed to be ready before you send out the `invoke`call from the renderer.

```js
const { app, BrowserWindow, ipcMain } = require('electron/main')
const path = require('node:path')

const createWindow = () => {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  })
  win.loadFile('index.html')
}
app.whenReady().then(() => {
  ipcMain.handle('ping', () => 'pong')
  createWindow()
})
```

Once you have the sender and receiver set up, you can now send messages from the renderer to the main process through the `'ping'` channel you just defined.



```js
const func = async () => {
  const response = await window.versions.ping()
  console.log(response) // prints out 'pong'
}

func()
```

### Renderer to main(one-way)

To fire a one-way IPC message from a renderer process to the main process, you can use the [`ipcRenderer.send`](https://www.electronjs.org/docs/latest/api/ipc-renderer) API to send a message that is then received by the [`ipcMain.on`](https://www.electronjs.org/docs/latest/api/ipc-main) API.



##### 1.Listen for events with `ipcMain.on`

In the main process, set an IPC listener on the `set-title` channel with the `ipcMain.on`API:

```js
const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('node:path')

// ...

function handleSetTitle (event, title) {
  const webContents = event.sender
  const win = BrowserWindow.fromWebContents(webContents)
  win.setTitle(title)
}

function createWindow () {
  const mainWindow = new BrowserWindow({
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  })
  mainWindow.loadFile('index.html')
}

app.whenReady().then(() => {
  ipcMain.on('set-title', handleSetTitle)
  createWindow()
})
```

The above `handleSetTitle` callback has two parameters: an [IpcMainEvent](https://www.electronjs.org/docs/latest/api/structures/ipc-main-event) structure and a `title` string. Whenever a message comes through the `set-title` channel, this function will find the BrowserWindow instance attached to the message sender and use the `win.setTitle` API on it.

##### 2. Expose `ipcRenderer.send` via preload

To send messages to the listener created above, you can use the `ipcRenderer.send`API. By default, the renderer process has no Node.js or Electron module access. As an app developer, you need to choose which APIs to expose from your preload script using the `contextBridge` API.

In your preload script, add the following code, which will expose a global `window.electronAPI` variable to your renderer process.

```js
const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('electronAPI', {
  setTitle: (title) => ipcRenderer.send('set-title', title)
})
```

At this point, you'll be able to use the `window.electronAPI.setTitle()` function in the renderer process.

##### 3. Build the renderer process UI

In our BrowserWindow's loaded HTML file, add a basic user interface consisting of a text input and a button:

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <!-- https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
    <title>Hello World!</title>
  </head>
  <body>
    Title: <input id="title"/>
    <button id="btn" type="button">Set</button>
    <script src="./renderer.js"></script>
  </body>
</html>
```

To make these elements interactive, we'll be adding a few lines of code in the imported`renderer.js` file that leverages the `window.electronAPI` functionality exposed from the preload script:

```js
const setButton = document.getElementById('btn')
const titleInput = document.getElementById('title')
setButton.addEventListener('click', () => {
  const title = titleInput.value
  window.electronAPI.setTitle(title)
})
```

### Main to renderer

When sending a message from the main process to a renderer process, you need to specify which renderer is receiving the message. Messages need to be sent to a renderer process via its [`WebContents`](https://www.electronjs.org/docs/latest/api/web-contents) instance. This WebContents instance contains a [`send`](https://www.electronjs.org/docs/latest/api/web-contents#contentssendchannel-args)method that can be used in the same way as `ipcRenderer.send`.

##### 1. Send messages with the `webContents` module

For this demo, we'll need to first build a custom menu in the main process using Electron's `Menu` module that uses the `webContents.send` API to send an IPC message from the main process to the target renderer.

```js
const { app, BrowserWindow, Menu, ipcMain } = require('electron')
const path = require('node:path')

function createWindow () {
  const mainWindow = new BrowserWindow({
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  })

  const menu = Menu.buildFromTemplate([
    {
      label: app.name,
      submenu: [
        {
          click: () => mainWindow.webContents.send('update-counter', 1),
          label: 'Increment'
        },
        {
          click: () => mainWindow.webContents.send('update-counter', -1),
          label: 'Decrement'
        }
      ]
    }
  ])
  Menu.setApplicationMenu(menu)

  mainWindow.loadFile('index.html')
}
// ...
```

For the purposes of the tutorial, it's important to note that the `click` handler sends a message (either `1` or `-1`) to the renderer process through the `update-counter`channel.

#####  2.Expose `ipcRenderer.on` via preload

Like in the previous renderer-to-main example, we use the `contextBridge` and `ipcRenderer` modules in the preload script to expose IPC functionality to the renderer process:

```js
const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('electronAPI', {
  onUpdateCounter: (callback) => ipcRenderer.on('update-counter', (_event, value) => callback(value))
})
```

After loading the preload script, your renderer process should have access to the`window.electronAPI.onUpdateCounter()` listener function.

##### 3. Build the renderer process UI

To tie it all together, we'll create an interface in the loaded HTML file that contains a`#counter` element that we'll use to display the values:

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <!-- https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
    <title>Menu Counter</title>
  </head>
  <body>
    Current value: <strong id="counter">0</strong>
    <script src="./renderer.js"></script>
  </body>
</html>
```

Finally, to make the values update in the HTML document, we'll add a few lines of DOM manipulation so that the value of the `#counter` element is updated whenever we fire an `update-counter` event.

```js
const counter = document.getElementById('counter')

window.electronAPI.onUpdateCounter((value) => {
  const oldValue = Number(counter.innerText)
  const newValue = oldValue + value
  counter.innerText = newValue.toString()
})
```

In the above code, we're passing in a callback to the `window.electronAPI.onUpdateCounter` function exposed from our preload script. The second `value` parameter corresponds to the `1` or `-1` we were passing in from the `webContents.send` call from the native menu.

##### Optional: returning a reply

There's no equivalent for `ipcRenderer.invoke` for main-to-renderer IPC. Instead, you can send a reply back to the main process from within the `ipcRenderer.on` callback.

We can demonstrate this with slight modifications to the code from the previous example. In the renderer process, expose another API to send a reply back to the main process through the `counter-value` channel.



preload.js

```js
const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('electronAPI', {
  onUpdateCounter: (callback) => ipcRenderer.on('update-counter', (_event, value) => callback(value)),
  counterValue: (value) => ipcRenderer.send('counter-value', value)
})
```

renderer.js 

```js
const counter = document.getElementById('counter')

window.electronAPI.onUpdateCounter((value) => {
  const oldValue = Number(counter.innerText)
  const newValue = oldValue + value
  counter.innerText = newValue.toString()
  window.electronAPI.counterValue(newValue)
})
```

In the main process, listen for `counter-value` events and handle them appropriately.

```js
// ...
ipcMain.on('counter-value', (_event, value) => {
  console.log(value) // will print value to Node console
})
// ...
```

# MessagePorts

[`MessagePort`](https://developer.mozilla.org/en-US/docs/Web/API/MessagePort)s are a web feature that allow passing messages between different contexts. It's like `window.postMessage`, but on different channels. The goal of this document is to describe how Electron extends the Channel Messaging model, and to give some examples of how you might use MessagePorts in your app.

Here is a very brief example of what a MessagePort is and how it works:

renderer.js (Renderer Process)

```js
// MessagePorts are created in pairs. A connected pair of message ports is
// called a channel.
const channel = new MessageChannel()

// The only difference between port1 and port2 is in how you use them. Messages
// sent to port1 will be received by port2 and vice-versa.
const port1 = channel.port1
const port2 = channel.port2

// It's OK to send a message on the channel before the other end has registered
// a listener. Messages will be queued until a listener is registered.
port2.postMessage({ answer: 42 })

// Here we send the other end of the channel, port1, to the main process. It's
// also possible to send MessagePorts to other frames, or to Web Workers, etc.
ipcRenderer.postMessage('port', null, [port1])
```

main.js

```js
// In the main process, we receive the port.
ipcMain.on('port', (event) => {
  // When we receive a MessagePort in the main process, it becomes a
  // MessagePortMain.
  const port = event.ports[0]

  // MessagePortMain uses the Node.js-style events API, rather than the
  // web-style events API. So .on('message', ...) instead of .onmessage = ...
  port.on('message', (event) => {
    // data is { answer: 42 }
    const data = event.data
  })

  // MessagePortMain queues messages until the .start() method has been called.
  port.start()
})
```

`MessagePort` objects can be created in either the renderer or the main process, and passed back and forth using the [`ipcRenderer.postMessage`](https://www.electronjs.org/docs/latest/api/ipc-renderer#ipcrendererpostmessagechannel-message-transfer) and[`WebContents.postMessage`](https://www.electronjs.org/docs/latest/api/web-contents#contentspostmessagechannel-message-transfer) methods. Note that the usual IPC methods like `send` and `invoke` cannot be used to transfer `MessagePort`s, only the `postMessage` methods can transfer `MessagePort`s.

### Extension: `close` event

Electron adds one feature to `MessagePort` that isn't present on the web, in order to make MessagePorts more useful. That is the `close` event, which is emitted when the other end of the channel is closed. Ports can also be implicitly closed by being garbage-collected.

In the renderer, you can listen for the `close` event either by assigning to `port.onclose`or by calling `port.addEventListener('close', ...)`. In the main process, you can listen for the `close` event by calling `port.on('close', ...)`.

### Setting up a MessageChannel between two renderers

In this example, the main process sets up a MessageChannel, then sends each port to a different renderer. This allows renderers to send messages to each other without needing to use the main process as an in-between.

main.js:

```js
const { BrowserWindow, app, MessageChannelMain } = require('electron')

app.whenReady().then(async () => {
  // create the windows.
  const mainWindow = new BrowserWindow({
    show: false,
    webPreferences: {
      contextIsolation: false,
      preload: 'preloadMain.js'
    }
  })

  const secondaryWindow = new BrowserWindow({
    show: false,
    webPreferences: {
      contextIsolation: false,
      preload: 'preloadSecondary.js'
    }
  })

  // set up the channel.
  const { port1, port2 } = new MessageChannelMain()

  // once the webContents are ready, send a port to each webContents with postMessage.
  mainWindow.once('ready-to-show', () => {
    mainWindow.webContents.postMessage('port', null, [port1])
  })

  secondaryWindow.once('ready-to-show', () => {
    secondaryWindow.webContents.postMessage('port', null, [port2])
  })
})
```

Then, in your preload scripts you receive the port through IPC and set up the listeners.

preloadMain.js and preloadSecondary.js (Preload scripts):

```js
const { ipcRenderer } = require('electron')

ipcRenderer.on('port', e => {
  // port received, make it globally available.
  window.electronMessagePort = e.ports[0]

  window.electronMessagePort.onmessage = messageEvent => {
    // handle message
  }
})
```

That means window.electronMessagePort is globally available and you can call`postMessage` on it from anywhere in your app to send a message to the other renderer.

```js
// elsewhere in your code to send a message to the other renderers message handler
window.electronMessagePort.postMessage('ping')
```


# 资料

告别卡顿！Electron内存管理终极指南：从泄漏排查到性能飞升

https://blog.csdn.net/gitblog_00828/article/details/151421503

给我5分钟！教你定位内存泄露

https://juejin.cn/post/7024752695659462693

Electron内存占用优化：从架构到实践的深度解析

https://comate.baidu.com/zh/page/87yoj692bec