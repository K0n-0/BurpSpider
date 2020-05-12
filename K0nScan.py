# -*- coding: utf-8 -*-
# 2020-05-06
# Author:K0n_

import re

from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpExtender,IHttpListener):
    def registerExtenderCallbacks(self,callbacks):
    # your extension code here

        print("[+] #####################################")
        print("[+]    K0n_Spider for burp V1.0")
        print("[+]    anthor: K0n_")
        print("[+]    github:https://github.com/K0n-0")
        print("[+] #####################################")

        self._callbcallbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("K0n_Spider")
        callbacks.registerHttpListener(self)
        return

    def processHttpMessage(self,toolFlag,messageIsRequest,messageInfo):
        if messageIsRequest:
            content = messageInfo.getRequest()
            all = self._helpers.analyzeRequest(content)
            #get请求url及参数
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            urlList=[]
            urlList.append(str(url))
            if self.forGetUrlParmeters(urlList):
                messageInfo.setHighlight('orange')
            if all.getMethod() == "POST":
                #post请求参数
                bodyList=[]
                body = content.tostring()[all.getBodyOffset():] 
                bodyList.append(body)
                if self.forPostParmeters(bodyList):
                    messageInfo.setHighlight('pink')

    def forPostParmeters(self,bodyList):
        final_params=[]
        all_params=[]
        for line in bodyList:
            all_params.append(line.split('&'))
        for line in all_params:
			for l in line:
				final_params.append(l.split('=')[0])
        unique_final=list(dict.fromkeys(final_params))
        for word in unique_final:
            dall = re.findall(r'(id)|(url)|(height)|(width)|(email)|(moblie)|(tel)|(include)|(dir)|(path)|(select)|(list)|(del)|(remove)|(add)|(query)',word)
            if dall != []:
                return True
            else:
                return False
    def forGetUrlParmeters(self,urlList):
        final_params=[]  #最终过滤完的参数名
        all_params=[]	 #首先过滤的参数和值

        for line in urlList:
			all_params.append(line.split('?')[1:][0].split('&'))

        for line in all_params:
            for l in line:
				final_params.append(l.split('=')[0])

        unique_final=list(dict.fromkeys(final_params))
        for word in unique_final:
            dall = re.findall(r'(id)|(url)|(height)|(width)|(email)|(moblie)|(tel)|(include)|(dir)|(path)|(select)|(list)|(del)|(remove)|(add)|(query)',word)
            if dall != []:
                return True
            else:
                return False
        