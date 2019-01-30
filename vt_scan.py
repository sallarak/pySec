#!/usr/bin/python

# Resource: https://github.com/bloomer1016/VirusTotal-Scripts/blob/master/vt_url_report.py

import requests, json

print "What is the URL: ",
web_url = raw_input()

#Resource is the URL that you are looking for in VT
url_chk = {'apikey': '<API KEY>', 'resource':web_url}

#Post request to VT for the URL in question
vt_report = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=url_chk)

#Get response from VT
json_response = response.json()
#vt_report_output_string = json.dumps(json_response,sort_keys=True,indent=4)
print json_response

#vt_report_output = vt_report.json()
#vt_response_code = vt_report_output.get("response_code", {})

#print response_code

#if vt_response_code > 0:
#	vt_report_output_string = json.dumps(vt_report_output,sort_keys=True,indent=4)
#	print(vt_report_output_string) 
#else:
#	print "The URL you are looking for does not exist. Please try again"
