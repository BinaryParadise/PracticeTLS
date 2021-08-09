# PracticeTLS

很多事物我们都是`知其然而不知其所以然`，既然这样不如从头开始自己动手实现TLS协议不就什么都知道了。本文不讲`理论`只重`实践`。

> 理论知识详见参考资料或自行谷歌，本文仅实现TLS 1.2协议

## 步骤

### 一、创建项目

```shell
mkdir PracticeTLS
cd PracticeTLS
swift package init
```

### 二、具体实现

- [ ] 实现HTTP协议
- [ ] 实现TLS握手
- [ ] 测试协议

### TLS握手过程

```sequence
title: TLS握手过程
participant Client as c
participant Server as s
c-->s: ClientHello
s-->c: ServerHello
s-->c: Certificate
```

## 参考资料

[HTTPS 详解一：附带最精美详尽的 HTTPS 原理图](https://segmentfault.com/a/1190000021494676)

[HTTPS详解二：SSL / TLS 工作原理和详细握手过程](https://segmentfault.com/a/1190000021559557)

[SSL/TLS协议详解](https://cshihong.github.io/2019/05/09/SSL%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/)

[SSL](https://aandds.com/blog/network-tls.html)