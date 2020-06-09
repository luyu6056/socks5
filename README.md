# server
*  这个是运行在服务器端的，仿mysql握手，配置文件config.json和tls证书放在config目录下,生成配置后，这个config目录是必须的。
* static目录是一个简单的网页测速，main.go里监听了80和443端口，可以删掉相关代码。

# client
*  这个只是socker5隧道的客户端，本质还是一个tcp的socks5服务器（udp懒得写），运行在你的路由器，或者本机电脑，连接server的ip和端口，本地监听10808端口，socks5协议。
*  由于client端要放到路由器或者傻瓜式运行，所以没有配置文件，需要你打开main.go去修改，用于连接server端的证书在590行
*  client连上服务器后，会有若干行connect to xxxx:xxx success，这时候你的浏览器设置socks5代理，或者服务器的不可描述插件，连接socks5到这个client10808端口，就能达到科学目的。
*  最重要的，你要有一台能够科学的server服务器，server运行在本地，没啥效果
