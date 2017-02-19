# -*- coding: utf-8 -*-

import urllib2
import urllib
import traceback
import os
import re
import sys
import cookielib
import time
import random
from StringIO import StringIO
import gzip
import logging
import threading

logger = logging.getLogger(__name__)

reload(sys)
sys.setdefaultencoding('utf-8')
if "" != os.path.dirname(sys.argv[0]):
    os.chdir(os.path.dirname(sys.argv[0]) + os.sep) 
    
class SmartRedirectHandler(urllib2.HTTPRedirectHandler):
    def __init__(self):
        self._reHost = 'http[s]*://([^/]+)'

    def http_error_302(self, req, fp, code, msg, headers):
        logger.debug(headers.getheader('Location'))
        new_host = re.match(self._reHost, headers.getheader('Location'))
        if new_host:
            req.add_header("Host", new_host.groups()[0])
        result = urllib2.HTTPRedirectHandler.http_error_302(
            self, req, fp, code, msg, headers)
        return result
    
class FlushRank():
    def __init__(self):
        self.cookies = cookielib.LWPCookieJar()
        handlers = [
            urllib2.HTTPHandler(),
            urllib2.HTTPSHandler(),
            urllib2.HTTPCookieProcessor(self.cookies),
            SmartRedirectHandler
            ]
        self.opener = urllib2.build_opener(*handlers)
    
    def getCookieString(self):
        cookieString = ""
        for cookie in self.cookies:
            value = '%s=%s; '%(cookie.name, cookie.value)
            cookieString += value
        return cookieString
    
    def handleRank(self, headStr):
        try:     
            ua, cookieStr = headStr.split('\r\n')
            data_map = {
                'op': 'videoshare',
                'logid': '670898'
            }
            
            postdata = urllib.urlencode(data_map)    
            for i in range(2000):
                cookieTime = int(time.time())
                head = {
                    'Host':'xdr.m2plus2000.com',           
                    "User-Agent":ua,
                    'Accept':'application/json, text/javascript, */*; q=0.01',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Accept-Language': 'zh-CN,en-US;q=0.8',
                    'Accept-Encoding':'gzip, deflate',
                    'Origin': 'http://xdr.m2plus2000.com',
                    'Referer': 'http://xdr.m2plus2000.com/xdr/index.php?logid=670898&from=singlemessage&isappinstalled=0&code=001fVzZ40Jd4kH1mQfY40zRvZ40fVzZv&state=STATE',
                    "Cookie": cookieStr,
                }           
                loginUrl = 'http://xdr.m2plus2000.com/xdr/api/ajax.php'
                req = urllib2.Request(url = loginUrl, data = postdata, headers = head)
                response = self.opener.open(req)
                pageData = ''
                if response.info()['content-encoding'] == 'gzip':
                    buf = StringIO(response.read())
                    f = gzip.GzipFile(fileobj=buf)
                    pageData = f.read()
                logger.info("cookie is %s, return:%s" % (cookieStr, pageData))
                if pageData.find("rank") == -1:
                    logger.debug("cookie is %s, return:%s" % (cookieStr, pageData))
                    logger.info("cookie is %s, kill:%d" % (cookieStr, i))
                    break
                
                time.sleep(random.randint(50, 60))
        except:
            logger.debug(traceback.format_exc())
            
class WxTask(threading.Thread):
    def __init__(self, strArgs = ""):
        threading.Thread.__init__(self)
        self.strArgs = strArgs
        
    def run(self):
        try:
            flush = FlushRank()
            flush.handleRank(self.strArgs)
        except:
            logger.debug(traceback.format_exc())    
            
def main(): 
    try:
        logging.basicConfig(level=getattr(logging, 'DEBUG'), format='%(asctime)s - %(levelname)s - pid:%(process)d - %(message)s')
        
        while True:
            for root, directories, files in os.walk('./result'):
                for filename in files:
                    if filename.endswith('.txt'):
                        filepath = os.path.join(root, filename)   
                        with open(filepath, 'rb') as f:
                            headStr = f.read()
                        threadItem = WxTask(headStr)
                        threadItem.start()
                        os.remove(filepath)
            time.sleep(30)
    except:
        logger.debug(traceback.format_exc())    

if __name__ == '__main__':
    main()
