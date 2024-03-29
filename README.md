# crypto-pack

浏览器环境和 Node.js 环境通用的加解密工具集

Node.js 在 v15 版本引入了同 W3C 一致的 [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)，在浏览器端和 Node 环境可以使用相同的函数进行加解密。

本仓库在 WebCryptoAPI 的基础上封装 AES 和 RSA 工具集，进一步简化加解密模块的使用。

## Installation

### HTML script 标签引入:

```html
<script src="https://unpkg.com/crypto-pack/lib/browser.js"></script>

<script>
  const { cryptoPack } = window;
  const { RSA } = cryptoPack;
</script>
```

### npm 引入：

```bash
npm install crypto-pack --save
```

#### ES6 module / TypeScript:

```ts
// 浏览器
import { RSA } from "crypto-pack/lib/browser";

// Node.js
import { RSA } from "crypto-pack/lib/node";
```

#### [Node.js](http://nodejs.org):

```js
// Node.js
const { RSA } = require("crypto-pack/lib/node");
```

## 通用函数集

### AES

```ts
import { AES } from "crypto-pack/lib/browser";
// or
import { AES } from "crypto-pack/lib/node";
```

#### 生成AES密钥，返回 base64 字符串

```ts
await AES.generateKey(l ?: number)
```

#### AES加解密

```ts
// AES 加密，返回 base64 字符串
await AES.encrypt(key: string, iv: string, msg: string)

// AES 解密
await AES.decrypt(key: string, iv: string, t: string)
```

### RSA

```ts
import { RSA } from "crypto-pack/lib/browser";
// or
import { RSA } from "crypto-pack/lib/node";
```

#### 生成密钥对

```ts
await RSA.generateKeyPair()

// 对于只需要在内存生成一次密钥对的场景，可以使用工具集提供的闭包函数
const getRsaKeyPair = await RSA.getKeyPairClosure();

const { publicKey, privateKey } = await getRsaKeyPair();
```

#### RSA 公钥加密

```ts
await RSA.publicEncrypt(msg: string, key: string)
```

#### RSA 私钥解密

```ts
await RSA.privateDecrypt(eMsg: string, key: string)
```

### AES + RSA 

```ts
import { encryptWithAesRsaPb, decryptWithAesRsaPv } from "crypto-pack/lib/browser";
// or
import { encryptWithAesRsaPb, decryptWithAesRsaPv } from "crypto-pack/lib/node";

```

非对称加密通常只公开只能加密的公钥，解密的私钥不对外公开，所以安全性会更高。缺点是对加密的内容长度有限制，并且相比于对称加密性能开销更大。

在双端通信过程中，更好的做法是，生成随机对称加密密钥，使用生成的对称密钥加密主内容，再使用对端的非对称公钥加密对称密钥。

这样发给对端的是公钥加密后的对称密钥和对称密钥加密的主内容。对端收到内容后反向解密，先使用私钥解密对称密钥，再使用对称密钥解密主内容。

对于这个常见的通信场景，封装了如下函数：

#### RSA Public Key + AES 加密

```ts
await encryptWithAesRsaPb(data: string, publicKey: string)

```

#### RSA Private Key + AES 解密

```ts
// 解密函数添加了防重放功能，timeoutSecond 参数如果大于 0，防重放功能生效，单位为秒
await decryptWithAesRsaPv(
  encryptAesData: string,
  encryptAesKey: string,
  privateKey: string,
  // 防重放
  timeoutSecond = -1
)
```

## Node.js 独有的函数

### 生成 RSA 密钥对并保存到本地

```ts
import { RSA_GenerateKeyPairToFile } from "crypto-pack/lib/node";

await RSA_GenerateKeyPairToFile()
```