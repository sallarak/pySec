#!/usr/bin/python

# Query the VT Api for IP and domaoin reports
# Resource: https://github.com/jpglab/virus-total-api

# Script to get DNS output from Virus Total

import argparse
import sys
import urllib, urllib2
import json

class VTDNS():
  
  def __init__(self):
    self.key = '---------VT-API-KEY------------'
    self.api = 'https://www.virustotal.com/vtapi/v2/'

  def get(self, p, u): 
    data = urllib.urlencode(p)
    response = urllib2.urlopen('%s?%s' %(u,data))
    jsons = response.read()
    json_data = json.loads(jsons)
    return json_data

  def ip_report(self, ip, pretty):
    url = self.api + 'ip-address/report'
    parameters = {'ip': ip, 'apikey': self.key}
    json_data = self.get(parameters, url)
    self.output(json_data, pretty)

  def domain_report(self, dns, pretty):
    url = self.api + 'domain/report'
    parameters = {'domain': dns, 'apikey': self.key}
    json_data = self.get(parameters, url)
    self.output(json_data, pretty)

  def output(self, j, pretty):
    if (pretty == True) and (j['response_code'] == (-1 or 0)):
      print('%s!' %j['verbose_msg'])  
    elif pretty == True:
      print('Resolutions\n')
      n = 0
      if 'hostname' in j['resolutions'][0]:
        for i in j['resolutions']:
          print('Hostname: %s\nDate: %s\n\n' %(j['resolutions'][n]['hostname'], j['resolutions'][n]['last_resolved']))
          n += n
      else: 
          print('Hostname: %s\nDate: %s\n\n' %(j['resolutions'][n]['ip_address'], j['resolutions'][n]['last_resolved']))
          n += n
    else:
      print(json.dumps(j, sort_keys=True, indent=4, separators=(',', ': ')))


def main():
  p = argparse.ArgumentParser(description='Returns IP and domain name resolutions from VT')
  p.add_argument('-i', '--ip', help='The IP address to scan')
  p.add_argument('-d', '--dns', help='The domain name to scan')
  p.add_argument('-j', '--json', action='store_true', help='Print raw json')
  args = p.parse_args()
  
  if sys.argv <=2:
    args.print_help()

  d = VTDNS()
  if args.ip:
    if args.json:
      d.ip_report(args.ip, False)
    else:
      d.ip_report(args.ip, True)
  
  if args.dns:
    if args.json:
      d.domain_report(args.dns, False)
    else:
      d.domain_report(args.dns, True)

if  __name__ == '__main__':
  main()
