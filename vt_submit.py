#!/usr/bin/python

# Scan URL's and Files for VT reports. 
# Submit files if not found in VT

import urllib, urllib2
import json
import hashlib
import postfile
import argparse
import sys
import datetime

class VT():
  def __init__(self):
    self.key = '------------VT-API-KEY-----------'
    self.api = 'https://www.virustotal.com/vtapi/v2/' 
  
  def get(self, api_url, parameters):
    data = urllib.urlencode(parameters)
    data = data.encode('UTF-8')
    request = urllib2.Request(api_url, data)
    response = urllib2.urlopen(request)
    jsons = response.read()
    json_data = json.loads(jsons)
    return json_data

  def file_report(self, f, sub):
    o = open(str(f),'rb')
    m = hashlib.md5()
    m.update(o.read())
    o.close()
    h = m.hexdigest()
    url = self.api + 'file/report'
    parameters = {'resource': h, 'apikey': self.key}
    jsons = self.get(url, parameters)
  
    if jsons['response_code'] == 1:
      self.output(jsons)
    elif (jsons['response_code'] == 0) and (sub == True):
      self.file_submit(f)
    else:
      print('File not found in VT, plese use the -s flag to submit')
  
  def file_submit(self, f):
    host = 'www.virustotal.com'
    selector = self.api + 'file/scan'
    fields = [('apikey', self.key)]
    file_to_send = open(f, 'rb').read()
    files = [('file', f, file_to_send)]
    
    json_data = postfile.post_multipart(host, selector, fields, files)
    jsons = json.loads(json_data)

    print(jsons['verbose_msg'])
    print(jsons['permalink'])

  def file_rescan(self, h):
    url = self.api + 'file/rescan'
    parameters = {'resource': h, 'apikey': self.key}
    jsons = self.get(url, parameters)
    self.output(jsons)

  def url_scan(self, u):
    url = self.api + 'url/scan'
    parameters = {'url': u, 'apikey': self.key}    
    jsons = self.get(url, parameters)
    self.output(jsons)
  
  def url_report(self, u, sub):
    url = self.api + 'url/report'
    parameters = {'resource': u, 'apikey': self.key}    
    jsons = self.get(url, parameters)
    
    if jsons['response_code'] == 1:
      self.output(jsons)
    elif (jsons['response_code'] == 0) and (sub == True):
      self.url_scan(u)
    else:
      print('URL not found in VT, plese use the -s flag to submit')

  def output(self, j):
      print(json.dumps(j, sort_keys=True, indent=4, separators=(',', ': ')))

def main():
  p = argparse.ArgumentParser(description='Submit and retrieve information from the VirusTotal API')
  p.add_argument('-f', '--file', help='Possible malicious file for VT to scan')
  p.add_argument('-u', '--url', help='Possible malicious URL for VT to scan')
  p.add_argument('-m', '--hash', help='Hash of file for VT to scan')
  p.add_argument('-s', '--submit', action='store_true', help='Submit file or url to VT if not found')
  
  if len(sys.argv)<=2:
    p.print_help()
  
  args = p.parse_args()

  vt = VT()
  if args.hash:
    vt.file_rescan(args.hash)
  elif args.file:
    vt.file_report(args.file, args.submit)
  elif args.url:
    vt.url_report(args.url, args.submit)

if  __name__ =='__main__':
  main()
