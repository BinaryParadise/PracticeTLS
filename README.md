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

- [x] 实现HTTP协议
- [ ] 实现TLS握手
- [ ] 测试协议

### 三、任务列表

- [ ] AES加解密
- [ ] 证书OCPS验证
- [ ] 统一使用`[UInt8]`传递数据

### TLS握手过程

![image](https://user-images.githubusercontent.com/8289395/128992483-e6d5340b-ec3e-4561-afc6-d5c31e910870.png)



![image](https://user-images.githubusercontent.com/8289395/128992867-8b653dac-7f85-4ce3-87da-73f90a8c6574.png)

## 参考资料

[图解 HTTPS：RSA 握手过程](https://zhuanlan.zhihu.com/p/344086342)

[SSL/TLS协议详解](https://cshihong.github.io/2019/05/09/SSL%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/)

[SSL](https://aandds.com/blog/network-tls.html)

[从Chrome源码看HTTPS](https://zhuanlan.zhihu.com/p/34041372)

[TLS1.2 PreMasterSecret And MasterSecret](https://laoqingcai.com/tls1.2-premasterkey/)