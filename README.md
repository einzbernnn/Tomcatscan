# Tomcatscan
Tomcat common vulnerability detection <br>
Scanner:  <br>
```
  -u IP          target ip <br>
  -H H           target ip-ip  <br>
  -p PORT        target port  <br>
  -f FILE        target list  <br>
  --proxy PROXY  http proxy, e.g., 127.0.0.1:8080  <br>
  -t THREADS     thread number, default 10  <br>
```

use <br>
```
python Tomcatscan.py -u 192.168.0.23 -p 80,8080,8009 -t 20  <br>
python Tomcatscan.py -u 192.168.0.23 -p 80,8080,8009 -t 20 --proxy 127.0.0.1:8080 <br>
python TomcatScan.py -H 192.168.1.1-192.168.2.255 //Default detection of ports 80, 8080, and 8009. <br>
python TomcatScan.py -f url.txt  <br>
```


-f  Supported IP formats in the file: <br>
```
http://192.168.1.1:8080 <br>
http://192.168.1.1 <br>
https://192.168.1.1 <br>
192.168.1.1             <br>    
192.168.1.1:8080  <br>
```


To perform weak password detection, please add username and password dictionaries in the "dict" directory.<br>
