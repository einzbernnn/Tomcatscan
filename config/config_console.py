#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import argparse
import sys
import socket
import requests
from urllib.parse import urlparse
from config.config_logging import loglog
from multiprocessing import Pool, Manager
from config.config_requests import headers, set_proxy, get_proxies, set_threads
from poc.index import *
from poc.utils import normalize_target
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
def pocbase(pocname,rip,rport):
    try:
        tmp,res=eval(pocname).run(rip,rport)
        return (tmp,res)
    except:
        pass

def poc(rip, rport):
    print("[*] =========Task Start=========")
    for i in pocindex:
        res = pocbase(i, rip, rport)
        if res and res[0] == 1:
            loglog(res[1])
            print(res[1])
    print("[*] =========Task End=========")

def poc2(rip, rport):
    for i in pocindex:
        if i != 'cve_2020_1938':
            res = pocbase(i, rip, rport)
            if res and res[0] == 1:
                loglog(res[1])
                print(res[1])

def poc2_with_scheme(rip, rport, scheme):
    from poc.utils import HTTPS_PORTS
    original_https_ports = HTTPS_PORTS.copy()
    
    try:
        if scheme == 'https':
            HTTPS_PORTS.add(rport)
        else:
            HTTPS_PORTS.discard(rport)
        
        for i in pocindex:
            if i != 'cve_2020_1938':
                res = pocbase(i, rip, rport)
                if res and res[0] == 1:
                    loglog(res[1])
                    print(res[1])
    finally:
        HTTPS_PORTS.clear()
        HTTPS_PORTS.update(original_https_ports)

def check_port_open(host, port, timeout=1):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.settimeout(timeout)
    try:
        sk.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        sk.close()

def Tomcat_Console():
    parser = argparse.ArgumentParser()
    scanner = parser.add_argument_group('Scanner')
    scanner.add_argument("-u",dest='ip', help="target ip")
    scanner.add_argument("-H",type=str,dest='H', help="target ip-ip") 
    scanner.add_argument("-p", dest='port', help="target port")
    scanner.add_argument("-f", dest='file', help="target list")
    scanner.add_argument("--proxy", dest='proxy', help="http proxy, e.g., 127.0.0.1:8080")
    scanner.add_argument("-t", dest='threads', type=int, default=10, help="thread number, default 10")
    args = parser.parse_args()
    
    if args.proxy:
        set_proxy(args.proxy)
    set_threads(args.threads)
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



    if args.ip:
        if args.port:
            port_list = []
            if ',' in args.port:
                for p in args.port.split(','):
                    p = p.strip()
                    if '-' in p:
                        start, end = p.split('-')
                        port_list.extend(range(int(start.strip()), int(end.strip()) + 1))
                    else:
                        port_list.append(int(p))
            elif '-' in args.port:
                start, end = args.port.split('-')
                port_list = list(range(int(start.strip()), int(end.strip()) + 1))
            else:
                port_list = [int(args.port)]
        else:
            port_list = [80, 8080, 8009]
        
        print("[*] =========Task Start=========")
        
        for target_port in port_list:
            # 对所有端口检测cve-2020-1938（基于AJP协议，不区分HTTP/HTTPS）
            try:
                res = pocbase('cve_2020_1938', args.ip, target_port)
                if res and res[0] == 1:
                    loglog(res[1])
                    print(res[1])
            except Exception:
                pass
            
            if check_port_open(args.ip, target_port):
                try:
                    poc2_with_scheme(args.ip, target_port, 'http')
                except Exception:
                    pass
                
                try:
                    poc2_with_scheme(args.ip, target_port, 'https')
                except Exception:
                    pass
        
        print("[*] =========Task End==========")
    

    elif args.file:
        with open(args.file,'r') as f:
            for line in f:
                if 'https:'  in line or 'http' in line or 'HTTP' in line or 'HTTPS' in line:
                    a=line.strip('\n')
                    b=a.split("://")[1]
                    file10.append(b)
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
                sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sk.settimeout(1)
                try:
                    sk.connect((i, 8009))
                    file5.append(i)
                except Exception:
                    pass
                sk.close()

            if file5:
                for ip in file5:
                    port = 8009
                    try:
                        res = pocbase('cve_2020_1938', ip, port)
                        if res and res[0] == 1:
                            loglog(res[1])
                            print(res[1])
                    except Exception:
                        pass
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
                ip = i.split(":")[0]
                port = int(i.split(":")[1])
                target = normalize_target(ip, port)
                
                try:
                    res = pocbase('cve_2020_1938', ip, port)
                    if res and res[0] == 1:
                        loglog(res[1])
                        print(res[1])
                except Exception:
                    pass
                
                try:
                    poc2(ip, port)
                except Exception:
                    pass
            for i in file7:
                for i2 in tport3:
                    port = int(i2)
                    target = normalize_target(i, port)
                    
                    try:
                        res = pocbase('cve_2020_1938', i, port)
                        if res and res[0] == 1:
                            loglog(res[1])
                            print(res[1])
                    except Exception:
                        pass
                    
                    try:
                        poc2(i, port)
                    except Exception:
                        pass
            print("[*] ==========Task End==========")
    elif iplist!=[]:
        print ("[*] =========Task Start=========")
        for i in iplist:
            sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sk.settimeout(1)
            try:
                sk.connect((i, 8009))
                target = normalize_target(i, 8009)
                print('[+] [{}] server port 8009 open!'.format(target))
                iplist2.append(i)
            except Exception:
                pass
            sk.close()
        for i in iplist:
            for i2 in tport:
                sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sk.settimeout(1)
                port = int(i2)
                try:
                    sk.connect((i, port))
                    target = normalize_target(i, port)
                    print('[+] [{}] server port {} open!'.format(target, port))
                    iplist3.append(target)
                except Exception:
                    pass
                sk.close()
        for ip in iplist2:
            port = 8009
            try:
                res = pocbase('cve_2020_1938', ip, port)
                if res and res[0] == 1:
                    loglog(res[1])
                    print(res[1])
            except Exception:
                pass
        for i in iplist3:
            # i已经是URL格式，提取IP和端口
            parsed = urlparse(i)
            ip = parsed.hostname
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme == 'https' else 80
            
            try:
                res = pocbase('cve_2020_1938', ip, port)
                if res and res[0] == 1:
                    loglog(res[1])
                    print(res[1])
            except Exception:
                pass
            
            try:
                poc2(ip, port)
            except Exception:
                pass
        print("[*] ==========Task End==========")
