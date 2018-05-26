# QuicProxy
##**直接部署与使用**
1. 解压GoQuicProxy.zip压缩包。
2. 将CA证书certs/ca/ca.cer导入系统可信任CA中心。
3. 在cmd控制台中使用`./GoQuicProxy.exe`命令。
4. 将HTTP应用代理指向127.0.0.1:8081。

##**从源码编译运行**
1. 安装GO编译环境。
2. 将CA证书certs/ca/ca.cer导入系统可信任CA中心。
3. 在cmd控制台中使用`go run main.go`命令。
4. 将HTTP应用代理指向127.0.0.1:8081。