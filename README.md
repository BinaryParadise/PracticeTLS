# PracticeTLS

与其`知其然而不知其所以然`，不如从头开始自己动手用swift实现TLS协议不就什么都知道了。本文不讲`理论`只重`实践`。`Just do it.`

> 理论知识详见参考资料或自行谷歌，本文仅实现TLS 1.2、1.3协议

调试工具: NSS Key Log & Wireshark

## 实现

### 预览

![image](https://user-images.githubusercontent.com/8289395/136887221-6055b688-5b5d-4b9e-9a25-f75938b51a5a.png)

![image](https://user-images.githubusercontent.com/8289395/136887369-f4cabdbb-1a8c-43f7-b43d-2f33368b7aa8.png)

### 一、创建项目

```shell
mkdir PracticeTLS
cd PracticeTLS
swift package init
```

### 二、具体实现

- [x] 实现HTTP协议
- [x] 实现TLS握手
- [x] 测试协议

### 三、任务列表

- [ ] 证书OCPS验证
- [ ] 会话恢复

### TLS握手过程

![image](https://user-images.githubusercontent.com/8289395/128992483-e6d5340b-ec3e-4561-afc6-d5c31e910870.png)

![image](https://user-images.githubusercontent.com/8289395/128992867-8b653dac-7f85-4ce3-87da-73f90a8c6574.png)

### TLS 1.2 & 1.3参考资料

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

## QUIC

[本站开始支持 QUIC](https://halfrost.com/quic_start/)
[QUIC协议详解之Initial包的处理](https://segmentfault.com/a/1190000023592802)
[QUIC包类型和格式](https://quic.readthedocs.io/zh/latest/Packet%20Types%20and%20Formats.html)
