登录包：
POST /idp/authcenter/ActionAuthChain HTTP/1.1
Host: tyrz.crec.cn
Connection: close
Content-Length: 156
sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: https://tyrz.crec.cn
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://tyrz.crec.cn/idp/authcenter/ActionAuthChain?entityId=anquanjiaoyu
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en-GB;q=0.8,en;q=0.7
Cookie: SESSION=cdeaf1c7-f80c-420f-ac2c-98a0645ea74e; _idp_authn_lc_key=f7d28aab-9af3-4f59-b8c2-08d885cc211b; x=x

j_username=aaaaaaa&j_password=jpopCsQAdoVsfIKWdccwLA%3D%3D&j_checkcode=%E9%AA%8C%E8%AF%81%E7%A0%81&op=login&spAuthChainCode=7c2327ed34a7499794d6a2b69edfa3e2


https://tyrz.crec.cn/idp/themes/default/js/cmxforms.js?date=201901031946
//DES加密
function encryptByDES(message, key) {
    var key = 'PassB01Il71';
    var keyHex = CryptoJS.enc.Utf8.parse(key);
    var encrypted = CryptoJS.DES.encrypt(message, keyHex, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    return encrypted.toString();
}



key: "PassB01Il71"
keyHex: init
sigBytes: 11
words: Array(3)
0: 1348563827    ====> 0x5061 7373
1: 1110454601    ====> 0x4230 3149
2: 1815556352    ====> 0x6C37 3100
length: 3
[[Prototype]]: Array(0)

用户名  ：aaaaaaaaaaa
密码    ：aaaaaaaaaaa

des加密后

iTany6GMB3OszJy/9Lvhvw==


view-source:https://tyrz.crec.cn/idp/authcenter/ActionAuthChain?entityId=anquanjiaoyu

                                <a id="tabA1"
                                   href="javascript:void(0)"
                                   onclick="switchAuthTab('1','7c2327ed34a7499794d6a2b69edfa3e2');">
                                    <li id="tabView7c2327ed34a7499794d6a2b69edfa3e2">
		                                <span class="tab tab1"
                                              title="一体化平台用户名密码认证"></span>
                                    </li>
                                </a>


///


GET /idp/oauth2/authorize?client_id=anquanjiaoyu&redirect_uri=http://aqpx.crec.cn&response_type=code&state=123 HTTP/1.1
Host: tyrz.crec.cn
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en-GB;q=0.8,en;q=0.7
Cookie: SESSION=d3f8717c-e9e1-4a6b-a914-a8dc2f76513a; x=x