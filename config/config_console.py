#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
import argparse
import sys
import socket
import requests
from config.config_logging import loglog
from multiprocessing import Pool, Manager
from config.config_requests import headers
from poc.index import *
tport=['8080','80','443','8081','8443']
tport3=['80','443']
tport2=['8009']
iplist=[]
iplist2=[]
iplist3=[]
iplist4=[]
file=[]
file1=[]
file2=[]
file3=[]
file4=[]
file5=[]
file10=[]
#只探测端口不探测服务，如何探测端口，返回网站内容
def pocbase(pocname,rip,rport):
    try:
        tmp,res=eval(pocname).run(rip,rport)
        return (tmp,res)
    except:
        pass

def poc(rip,rport):
    print ("[*] =========Task Start=========")
    for i in pocindex:
        res=pocbase(i,rip,rport)
        if res:
            loglog(res[1])
            print(res[1])
    print ("[*] =========Task E n d=========")
def poc2(rip,rport):
    for i in pocindex:
        if i != 'cve_2020_1938':
            res=pocbase(i,rip,rport)
            if res:
                loglog(res[1])
                print(res[1])

def Tomcat_Console():
    parser = argparse.ArgumentParser()
    scanner = parser.add_argument_group('Scanner')
    scanner.add_argument("-u",dest='ip', help="target ip")
    scanner.add_argument("-H",type=str,dest='H', help="target ip-ip") 
    scanner.add_argument("-p", dest='port', help="target port")
    scanner.add_argument("-f", dest='file', help="target list")
    args = parser.parse_args()
    def int_ip(x):
        return '.'.join([str(x/(256**i)%256) for i in range(3,-1,-1)])
    def ip_int(x):
        return  sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])

    def get_ips(get_ips_a,get_ips_b):
        ip1_num = ip_int(get_ips_a)
        ip2_num = ip_int(get_ips_b)
        for i in range(ip1_num,ip2_num+1):
            ip=str(int_ip(i))
            ip1=ip.split(".")[0]
            ip2=ip.split(".")[2]
            ip3=ip.split(".")[4]
            ip4=ip.split(".")[6]
            ip5=ip1+'.'+ip2+'.'+ip3+'.'+ip4
            iplist.append(ip5)
    if args.H:
        get_ips_a=args.H.split("-")[0] 
        get_ips_b=args.H.split("-")[1]
        iplist=[]
        get_ips(get_ips_a,get_ips_b)
        # print(iplist)



    if args.ip and args.port:
        #设置默认也检测8009端口if不等于8009，则也检测8009
        try:
            poc(args.ip,int(args.port))
        except ConnectionRefusedError:
            print("[-] [{}] Tomcat Network Is Abnormal ".format(args.ip + ':' + str(args.port)))
            print("[*] ==========Task End==========")
    

    elif args.file:
        with open(args.file,'r') as f:
            for line in f:
                if 'https:'  in line or 'http' in line or 'HTTP' in line or 'HTTPS' in line:
                    a=line.strip('\n')
                    b=a.split("://")[1]
                    file10.append(b)
                    #print(file)
                else:
                    file10.append(line.strip('\n'))
            file = list(filter(None, file10))
            for i in file:
                if ':' in i and '/' in i:
                    a=i.split(":")[0]
                    file3.append(a)
                if ':' in i:
                    a=i.split(":")[0]
                    file3.append(a)
                if '/' in i:   
                    a=i.split("/")[0]
                    file3.append(a)
                else:
                    file3.append(i)
            print ("[*] =========Task Start=========")
            file4=list(set(file3))
            for i in file4:
                sk=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                sk.settimeout(1)
                try:
                    sk.connect((i,8009))
                    print('[+] %s server port 8009 open'%i)
                    file5.append(i)
                except Exception:
                    pass
                sk.close()

            if file5:
                for ip in file5:
                    port='8009'
                    try:
                        res=pocbase('cve_2020_1938',ip,port)
                        if res:
                            loglog(res[1])
                            print(res[1])
                    except ConnectionRefusedError:
                        print("[-] [{}] Tomcat Network Is Abnormal ".format(ip + ':' + str(port)))
                        print("[*] ==========Task End==========")
            for i in file:
                if ':' in i:
                    if '/' in i:
                        a=i.split("/")[0]
                        file1.append(a)
                    else:
                        file1.append(i)
                else:
                    if '/' in i:
                        a=i.split("/")[0]
                        file2.append(a)
                    else:
                        file2.append(i)
            
            file6=list(set(file1))
            file7=list(set(file2))
            for i in file6:
                ip=i.split(":")[0]
                port=i.split(":")[1]

                try:
                    poc2(ip,int(port))
                except ConnectionRefusedError:
                    print("[-] [{}] Tomcat Network Is Abnormal ".format(ip + ':' + str(port)))
                    print("[*] ==========Task End==========")
            for i in file7:
                for i2 in tport3:
                    try:
                        poc2(i,int(i2))
                    except ConnectionRefusedError:
                        print("[-] [{}] Tomcat Network Is Abnormal ".format(i + ':' + str(i2)))
                        print("[*] ==========Task End==========")
            print("[*] ==========Task End==========")
    elif iplist!=[]:
        print ("[*] =========Task Start=========")
        for i in iplist:
            sk=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sk.settimeout(1)
            try:
                sk.connect((i,8009))
                print('%s server port 8009 open!'%i)
                iplist2.append(i)
            except Exception:
                #print('%s server port 8009 not open!'%i)
                pass
            sk.close()
        for i in iplist:
            for i2 in tport:
                sk=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                sk.settimeout(1)
                i2=int(i2)
                try:
                    sk.connect((i,i2))
                    print('%s server port %s open!'%(i,i2))
                    i3='http://'+str(i)+':'+str(i2)
                    iplist3.append(i3)
                except Exception:
                    #print('%s server port %s not open!'%(i,i2))
                    pass
                sk.close()
        # for i in iplist3:
        #     if '443'!=i:
        #     r = requests.get(i, headers=headers)
        #     if 'https://tomcat.apache.org' in r.text:
        #         print('find Tomcat :%s'%i) 
        #         iplist4.append(i)
        #     else:

        for ip in iplist2:
            port='8009'
            try:
                res=pocbase('cve_2020_1938',ip,port)
                if res:
                    loglog(res[1])
                    print(res[1])
            except ConnectionRefusedError:
                print("[-] [{}] Tomcat Network Is Abnormal ".format(ip + ':' + str(port)))
                print("[*] ==========Task End==========")
        for i in iplist3:
            ip1=i.split("http://")[1]
            ip=ip1.split(":")[0]
            port=ip1.split(":")[1]
            try:
                poc2(ip,int(port))
            except ConnectionRefusedError:
                print("[-] [{}] Tomcat Network Is Abnormal ".format(ip + ':' + str(port)))
                print("[*] ==========Task End==========")
        print("[*] ==========Task End==========")