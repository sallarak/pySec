#!/usr/bin/python

# Resourse: https://github.com/bloomer1016/VirusTotal-Scripts/blob/master/vt_url_report.py



import requests, json

print "What is the URL: ",
web_url = raw_input()

#Resource is the URL that you are looking for in VT
url_chk = {'apikey': '<API KEY>', 'resource':web_url}

#Post request to VT for the URL in question
vt_report = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=url_chk)

#Get response from VT
json_response = response.json()
vt_report_output_string = json.dumps(json_response,sort_keys=True,indent=4)
print vt_report_output_string
