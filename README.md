# libssl
Secure Sockets Layer In Windows KernelMode Driver

在驱动中使用套接字算是比较高级的话题了。  
最早的是TDI客户端（不是tdi filter），后来是WSK。  
但是，来个TLS不是更好，更安全。  

个人见识的最早在驱动中使用https的是CrowdStrike公司的一个产品，  
它有个驱动将近3MB，以为是用第三方库实现的，如：mbedtls。  
后来，深入了解了sspi，才知，这也没啥？WSK+SSPI而已。  

让你的驱动通讯不在裸奔，更加私密吧！  

参考：
https://github.com/winsiderss/systeminformer.git  
本仓库参考的版本是：SHA-1: a3c639140649dec395d150a1bb54205f7bb93970  
https://github.com/PKRoma/ProcessHacker 也有相似的代码。  

本工程，只是整理下上面的代码，并写个测试示例而已。  

注释：本工程只配置了x64的debug的编译。  
