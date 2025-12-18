#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import argparse
import sys
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from config.config_logging import loglog
from config.config_requests import set_proxy, set_threads, get_threads
from poc.index import *

def pocbase(pocname, rip, rport):
    try:
        tmp, res = eval(pocname).run(rip, rport)
        return (tmp, res)
    except:
        pass

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

def parse_ip_input(ip_input):
    ip_list = []
    if ',' in ip_input:
        for ip in ip_input.split(','):
            ip = ip.strip()
            if '/' in ip:
                try:
                    network = ipaddress.ip_network(ip, strict=False)
                    ip_list.extend([str(host) for host in network.hosts()])
                except Exception:
                    pass
            else:
                ip_list.append(ip)
    elif '/' in ip_input:
        try:
            network = ipaddress.ip_network(ip_input, strict=False)
            ip_list.extend([str(host) for host in network.hosts()])
        except Exception:
            pass
    else:
        ip_list.append(ip_input)
    return ip_list

def Tomcat_Console():
    parser = argparse.ArgumentParser()
    scanner = parser.add_argument_group('Scanner')
    scanner.add_argument("-i", dest='ip', help="target ip, support multiple ips with comma, support cidr like 192.168.1.1/24")
    scanner.add_argument("-p", dest='port', help="target port, default: 80,8080,8009")
    scanner.add_argument("-f", dest='file', help="target list")
    scanner.add_argument("--proxy", dest='proxy', help="http proxy, e.g., 127.0.0.1:8080")
    scanner.add_argument("-t", dest='threads', type=int, default=10, help="thread number, default 10")
    args = parser.parse_args()
    
    if args.proxy:
        set_proxy(args.proxy)
    set_threads(args.threads)
    
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
    
    def scan_ip_port(ip, port):
        try:
            res = pocbase('cve_2020_1938', ip, port)
            if res and res[0] == 1:
                loglog(res[1])
                print(res[1])
        except Exception:
            pass
        
        if check_port_open(ip, port):
            for poc_name in pocindex:
                if poc_name != 'cve_2020_1938':
                    try:
                        res = pocbase(poc_name, ip, port)
                        if res and res[0] == 1:
                            loglog(res[1])
                            print(res[1])
                    except Exception:
                        pass

    if args.ip:
        ip_list = parse_ip_input(args.ip)
        print("[*] =========Task Start=========")
        tasks = [(ip, port) for ip in ip_list for port in port_list]
        threads = get_threads()
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(scan_ip_port, ip, port) for ip, port in tasks]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass
        print("[*] =========Task End==========")

    elif args.file:
        ip_list = []
        with open(args.file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    ip_list.append(line)
        
        print("[*] =========Task Start=========")
        tasks = [(ip, port) for ip in ip_list for port in port_list]
        threads = get_threads()
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(scan_ip_port, ip, port) for ip, port in tasks]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass
        print("[*] =========Task End==========")
