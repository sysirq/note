If you only need to send a single message to another part of your extension (and optionally get a response back), use the simplified runtime.sendMessage() method or tabs.sendMessage() 。

- Sending a request from a content script looks like this:

content-script.js:

```js
(async () => {
  const response = await chrome.runtime.sendMessage({greeting: "hello"});
  // do something with response here, not outside the function
  console.log(response);
})();
```

- Sending a request from the extension to a content script is similar, except that you need to specify which tab to send it to. This example demonstrates sending a message to the content script in the selected tab.

service-worker.js
```js
(async () => {
  const [tab] = await chrome.tabs.query({active: true, lastFocusedWindow: true});
  const response = await chrome.tabs.sendMessage(tab.id, {greeting: "hello"});
  // do something with response here, not outside the function
  console.log(response);
})();
```


On the receiving end, you need to set up an runtime.onMessage event listener to handle the message. This looks the same from a content script or extension page.

content-script.js or service-worker.js:

```js
chrome.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
    console.log(sender.tab ?
                "from a content script:" + sender.tab.url :
                "from the extension");
    if (request.greeting === "hello")
      sendResponse({farewell: "goodbye"});
  }
);
```

In the above example, sendResponse() was called synchronously. If you want to asynchronously use sendResponse(), add return true; to the onMessage event handler.

For new extensions you should prefer promises over callbacks. If you're using callbacks, the sendResponse() callback is only valid if used synchronously, or if the event handler returns true to indicate that it will respond asynchronously. The sendMessage() function's callback will be invoked automatically if no handlers return true or if the sendResponse() callback is garbage-collected.