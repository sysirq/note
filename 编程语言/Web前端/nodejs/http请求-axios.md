# 安装

```
npm install axios
```

# example

```js
import axios from 'axios';
//const axios = require('axios'); // legacy way

// Make a request for a user with a given ID
axios.get('/user?ID=12345')
  .then(function (response) {
    // handle success
    console.log(response);
  })
  .catch(function (error) {
    // handle error
    console.log(error);
  })
  .finally(function () {
    // always executed
  });

// Optionally the request above could also be done as
axios.get('/user', {
    params: {
      ID: 12345
    }
  })
  .then(function (response) {
    console.log(response);
  })
  .catch(function (error) {
    console.log(error);
  })
  .finally(function () {
    // always executed
  });

// Want to use async/await? Add the `async` keyword to your outer function/method.
async function getUser() {
  try {
    const response = await axios.get('/user?ID=12345');
    console.log(response);
  } catch (error) {
    console.error(error);
  }
}
```

```js
var option = {
    headers: {
        'authority': 'weibo.com',
        'pragma': 'no-cache',
        'cache-control': 'no-cache',
        'server-version': 'v2022.09.19.2',
        'x-xsrf-token': 'HZonfoACpKXZIMOMIOMc8y0b',
        'traceparent': '00-d925421b95d78ed73bafd2caed0cbd85-d21a698eff02f887-00',
        'sec-ch-ua-mobile': '?0',
        'client-version': 'v2.35.2',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
        'accept': 'application/json, text/plain, */*',
        'x-requested-with': 'XMLHttpRequest',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://weibo.com/newlogin?url=https%3A%2F%2Fweibo.com%2F',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7',
        'cookie': 'SINAGLOBAL=5037293883765.11.1592755698570; SCF=AvGPjvoIgatl_Km54N5lsBGA06flluaOTUcjmG2i2L2YeK4HOTa1Voar-0Ev3FcDOINoYW122S9gO8896pNNJ90.; ALF=1669559693; SUB=_2AkMVQ5FKf8NxqwJRmPATymviaIp0zgvEieKjH2CRJRMxHRl-yT9jqnwDtRB6PsO_WLgUxUbfBmN0a8DQ-WByGIgx997S; SUBP=0033WrSXqPxfM72-Ws9jqgMF55529P9D9WFCwjKpB5Xfbk0rIDJhSqQu; UOR=,,www.baidu.com; ULV=1646206596535:8:1:1:682239284045.305.1646206596530:1632125497107; XSRF-TOKEN=HZonfoACpKXZIMOMIOMc8y0b; WBPSESS=durPiJxsbzq5XDaI2wW0N6ET-b2ytp8n58jgCm5B6U2fKwwMxWGcDGWqRlDvg85bX24BypCou0b2NQOLN37NXJngjuq3QEQ_OnB1GSws99oIKpNDkTbFEyDoVbHitmUguOtnqxtlUi3Lz2aC7DZqH-nDFDpiBi4P89n0g-xepkQ=',
    }

}

function parseData(data) {
    var result = []
    realtime = data.data.realtime
    //对于数组对象要这么循环取值
    realtime.forEach(function (element) {
        var title = element.word
        var num = element.num
        result.push({
            title,
            num
        })

    })
    return result

}

function getHotList() {
    return new Promise(((resolve, reject) => {
        axios.get(hotListUrl, option).then(function (resposne) {
            // console.log(resposne.data)
            var result = parseData(resposne.data)
            console.log(result)
            result.length ? resolve(result) : reject("err")
        }).catch(function (err) {
            console.log(err)
        }).finally(function () {
            console.log("完成一次抓取")

        })

    }))


}
```

```js
import axios from "axios"

const DELAYTIME = 500 //ms

let _cookie = ".AspNetCore.Cookies=CfDJ8IBgkWVr6LlBu1Utid8h1NSHh4Y3xQ-f3AtnW2djE7U9HcE8GYXWYRF8owIsjViooWYhJ8uo9mWOlJj-LFriDvysMoLqx3xOFjlwS-13MhWCMSqeS_mJsD0Wdmyde0Xpho0aGIQ5oI6Xj9sdnRU-BTjqHhNIznNzuuCYGSf3UA5fNbR7wGImFPbHVm8_MJ5YnB-ED_jZyFyvAHeYCJ7XteqPiIsZeyZWnLzwYyBjx7KVWqDdELqWiOazydc1giTZ3LGnHAAi4BMoX1DuHO8kuIjvwHogQD_JwSbHqPkf0ethFtoC0BbWn-7RY4pVt_gPhAUUOnQPInHoR3DWwVjlKMYizQ9tt6QkcvoaRfY2NBl0ZftA2SuNg8ucPJDsT58wpe-fxy5Y70LQHG6LG6eLxBKn9Ikdclxo0-uy1F_XHnKuoa-0L0jBIXRw3_m49W8Sv3JiNA-_L8-vw2CadnkhyOLJiDlR_O2qI6AKRj5ITRwj3Qfpv3q4xHpdujvjEWsGodMgOjdFD6U-bLkHXVPkv6XrelUZB44oLewKkPib97bR; SERVERID=26af2ba949a6f912446bf78dc635a4dc|"
let lastmodified = null

function sleep(ms)
{
    return new Promise(resolve=>setTimeout(resolve,ms))
}

async function getServerTimestamp() {
    let Options = {
        headers
            : {
            'Host': 'bm.ldylm.cn',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
            'Accept': '*/*',
        },
        validateStatus: function (status) {
            return status >= 200 && status < 400; // default
        },
    };
    if (lastmodified) {//不是第一次获取时间戳
        Options.headers['If-Modified-Since'] = lastmodified
    }
    let resposne = await axios.get("http://bm.ldylm.cn/Scripts/api/home.js?v=", Options)
    lastmodified = resposne.headers['last-modified']

    let [cookie] = resposne.headers['set-cookie']
    
    let timestap = cookie.split(";")[0].split('|')[1]
    timestap = parseInt(timestap)

    return timestap
}

function genCookie(timestamp){
    return _cookie+""+timestamp+"|"+timestamp
}

function timestapToLocalTimeString(timestap){
    return new Date(timestap*1000).toLocaleString()
}


/*
{
  code: 1,
  data: {
    ID: '41c81fdfb26e468b838bc2fd41f8fba9',
    Name: '陈宇',
    IDCard: '500102201911017610',
    Birthday: '2019-11-01',
    Gender: '男',
    CityID: ',2448,2449,2460,',
    CityName: '重庆 重庆市 涪陵区',
    Status: 0,
    Phone: '17154389854',
    WxOpenId: '',
    CreateTime: '2023/7/1 20:58:52',
    UpdateTime: '2023-07-01 21:28:17',
    IPAddress: '27.13.221.31',
    Timestamp: -148844107,
    Expiration: 1688304497,
    ModifyProperty: {}
  },
  message: '数据操作失败'
}
*/
async function getUserInfo(){
    let cookie = genCookie(await getServerTimestamp())
    let Options = {
        headers
            : {
            'Host': 'bm.ldylm.cn',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
            'Accept': '*/*',
            'If-Modified-Since':lastmodified,
            'Cookie':cookie
        },
        validateStatus: function (status) {
            return status >= 200 && status < 400; // default
        },
    };

    let resposne = await axios.get("http://bm.ldylm.cn/Account/MyInfo", Options)
    return resposne.data
}

async function grabSeat(){
    let cookie = genCookie(await getServerTimestamp())
    let Options = {
        headers
            : {
            'Host': 'bm.ldylm.cn',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
            'Accept': '*/*',
            'If-Modified-Since':lastmodified,
            'Cookie':cookie
        },
        validateStatus: function (status) {
            return status >= 200 && status < 400; // default
        },
    };

    let resposne = await axios.get("http://bm.ldylm.cn/Account/MyInfo", Options)
    return resposne.data
}

let name = (await getUserInfo())["data"]["Name"]
let timestap
let targetTimeStap = 1688259600
while( (timestap = await getServerTimestamp()) <= targetTimeStap){
    
    console.log("Name:"+name+"\tNow timestamp:"+timestap+"\tNow time:"+timestapToLocalTimeString(timestap) +
    `\tTarget timestamp: ${targetTimeStap}\tTarget time: ${timestapToLocalTimeString(targetTimeStap)}`)
    await sleep(DELAYTIME)
}

//await grabSeat()

console.log("hello")
```


# 资料

https://www.npmjs.com/package/axios#axios-api