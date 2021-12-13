# PracticeTLS

网上的文字千千万，但是看完是不真的觉得自己都懂了呢？其实还是`知其然而不知其所以然`，不如从头开始自己动手用swift实现一遍TLS协议不就能更加深入的理解了。本文不讲`理论`只重`实践`。`Just do it.卷卷更健康`

> 理论知识详见参考资料或自行谷歌，本文仅实现TLS 1.2、1.3协议的基本功能

调试工具: NSS Key Log & Wireshark

## 预览



```bash
git clone git@github.com:BinaryParadise/PracticeTLS.git
cd PracticeTLS
swift run
浏览器打开 http://127.0.0.1:8443
```



![image](https://user-images.githubusercontent.com/8289395/136887221-6055b688-5b5d-4b9e-9a25-f75938b51a5a.png)

![image](https://user-images.githubusercontent.com/8289395/136887369-f4cabdbb-1a8c-43f7-b43d-2f33368b7aa8.png)

## 协议总览

```
Client                                               Server

ClientHello                  -------->
                                                ServerHello
                                               Certificate*
                                         ServerKeyExchange*
                                        CertificateRequest*
                             <--------      ServerHelloDone
Certificate*
ClientKeyExchange
CertificateVerify*
[ChangeCipherSpec]
Finished                     -------->
                                         [ChangeCipherSpec]
                             <--------             Finished
Application Data             <------->     Application Data

* 可选、视情况而定
```

![image](https://user-images.githubusercontent.com/8289395/128992483-e6d5340b-ec3e-4561-afc6-d5c31e910870.png)



### TLS 1.2握手过程图解

![image](https://user-images.githubusercontent.com/8289395/128992867-8b653dac-7f85-4ce3-87da-73f90a8c6574.png)

## 协议报文（TLS 1.2 rfc5246）

| 名称           | 占用字节 | 说明               |
| -------------- | :------: | ------------------ |
| Content Type   |    1     | 协议类型           |
| Version        |    2     | TLS版本号          |
| Length         |    2     | 协议体字节数       |
| Handshake Type |    1     | 握手协议类型       |
| Length         |    3     | 握手协议内容字节数 |
| ...            |    n     | 内容字段           |



### Client Hello

![image](https://user-images.githubusercontent.com/8289395/145744534-d150cb8f-b2a6-4af1-81b8-033d5ee8c693.png)

### Server Hello

![image](https://user-images.githubusercontent.com/8289395/145744609-c614e750-4098-496b-8b4e-6bcbf35652d4.png)

### Certificate

![image](https://user-images.githubusercontent.com/8289395/145745012-0ce5ebd7-447a-47ca-aa2b-854a926a34ff.png)

### Server Key Exchange

![image](https://user-images.githubusercontent.com/8289395/145745194-b35540de-cf20-4bf4-8eb3-322bb09d7acf.png)

### Server Hello Done

### Client Key Exchange

![image](https://user-images.githubusercontent.com/8289395/145745629-9b6903ec-0729-4d1e-8ffd-608fa04e73e1.png)

### Change Cipher Spec

### Encrypted Handshake Message

![image](https://user-images.githubusercontent.com/8289395/145745710-955e2aca-6ae8-4f91-b067-633b11966613.png)

### Change Cipher Sepc

### Encrypted Handshake Message

### Application Data...

![image](https://user-images.githubusercontent.com/8289395/145745809-eb5728ab-371c-4611-a566-dbdb0adb6fb9.png)

## 密匙推导过程

[PRF&HKDF](https://blog.csdn.net/mrpre/article/details/80056618)

### TLS_RSA_WITH_AES_128_GCM_SHA256

```c
master_secret = PRF(ClientKeyExchange.pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47];

key_block = PRF(SecurityParameters.master_secret, "key expansion", SecurityParameters.server_random + SecurityParameters.client_random);

client_write_MAC_key[SecurityParameters.mac_key_length]
server_write_MAC_key[SecurityParameters.mac_key_length]
client_write_key[SecurityParameters.enc_key_length]
server_write_key[SecurityParameters.enc_key_length]
client_write_IV[SecurityParameters.fixed_iv_length]
server_write_IV[SecurityParameters.fixed_iv_length]
```





## TLS 1.2 & 1.3参考资料

[SwiftTLS](https://github.com/nsc/SwiftTLS)

[图解 HTTPS：RSA 握手过程](https://zhuanlan.zhihu.com/p/344086342)

[SSL/TLS协议详解](https://cshihong.github.io/2019/05/09/SSL%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/)

[从Chrome源码看HTTPS](https://zhuanlan.zhihu.com/p/34041372)

[AES-GCM 加密简介](https://juejin.cn/post/6844904122676690951)

[TLS1.2 PreMasterSecret And MasterSecret](https://laoqingcai.com/tls1.2-premasterkey/)

[图解 ECDHE 密钥交换算法](https://www.cnblogs.com/xiaolincoding/p/14318338.html)
[TLS 1.3 Handshake Protocol](https://github.com/halfrost/Halfrost-Field/blob/master/contents/Protocol/TLS_1.3_Handshake_Protocol.md)
[ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)](https://datatracker.ietf.org/doc/html/rfc7905)
[TLS1.3---密钥的计算...](https://blog.csdn.net/qq_35324057/article/details/105792293)
[HTTPS 温故知新（五） —— TLS 中的密钥计算](https://halfrost.com/https-key-cipher/)

## HTTP2

[HTTP/2 简介](https://developers.google.com/web/fundamentals/performance/http2?hl=zh-cn)
[HTTP2 详解](https://juejin.cn/post/6844903667569541133#heading-11)

## 扩展阅读

[SSL/TLS协议详解(上)：密码套件，哈希，加密，密钥交换算法](https://xz.aliyun.com/t/2526)
