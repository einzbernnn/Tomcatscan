# Tomcatscan
Tomcat common vulnerability detection <br>
Scanner:  <br>
```
  -u IP          target ip 
  -H H           target ip-ip 
  -p PORT        target port 
  -f FILE        target list 
  --proxy PROXY  http proxy, e.g., 127.0.0.1:8080  
  -t THREADS     thread number, default 10
```

use <br>
```
python Tomcatscan.py -u 192.168.0.23 -p 80,8080,8009 -t 20  
python Tomcatscan.py -u 192.168.0.23 -p 80,8080,8009 -t 20 --proxy 127.0.0.1:8080
python TomcatScan.py -H 192.168.1.1-192.168.2.255 //Default detection of ports 80, 8080, and 8009.
python TomcatScan.py -f url.txt -p 80,8080,8009
```


-f  Now only Supported IP in the file: <br>
```
192.168.1.1             
```


To perform weak password detection, please add username and password dictionaries in the "dict" directory.<br>
