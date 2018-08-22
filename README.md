### 一个用来生成自签名证书的小工具
1. 修改`openssl.cnf`文件中的配置，改为自己需要的参数
2. 运行`openssl-gen.sh`生成根证书对`ca.pem`和`ca.key.pem`
3. 运行`./main -hostname yourdomainname`或者`go run main.go -hostname yourdomainname生成签名的站点证书`ca.cer`和`ca.key`
4. 主机或者浏览器信任根证书`ca.pem`，应用站点部署证书`ca.cer`和`ca.key`
5. 此程序使用go1.10.3编译，OS X 10.13.6运行成功