# Tomcatscan
Tomcat common vulnerability detection


Scanner:
  -u IP          target ip
  -H H           target ip-ip
  -p PORT        target port
  -f FILE        target list
  --proxy PROXY  http proxy, e.g., 127.0.0.1:8080
  -t THREADS     thread number, default 10


python Tomcatscan.py -u 192.168.0.23 -p 80,8080,8009
python TomcatScan.py -H 192.168.1.1-192.168.2.255 //Default detection of ports 80, 8080, and 8009.

python TomcatScan.py -f url.txt 
#-f  Supported IP formats in the file:
```
http://192.168.1.1:8080
http://192.168.1.1
https://192.168.1.1
192.168.1.1               
192.168.1.1:8080 
```

To perform weak password detection, please add username and password dictionaries in the "dict" directory.
