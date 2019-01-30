#!/usr/bin/python

# Resource: https://github.com/bloomer1016/VirusTotal-Scripts/blob/master/vt.py



import requests, json

print "Input the hash: ",
hash = raw_input()

# Resource is the hash/file_name that you are looking for in VT
hash_chk = {"resource": hash, "apikey": 'INSERT KEY HERE'}

# Post request to VT for the hash/file in question
vt_report = requests.post("https://www.virustotal.com/vtapi/v2/file/report", data=hash_chk)

# Get response code from VT
vt_report_output = vt_report.json()
vt_response_code = vt_report_output.get("response_code", {})

# print response_code

if vt_response_code > 0:
	vt_report_output_string = json.dumps(vt_report_output,sort_keys=True,indent=4)
	print(vt_report_output_string) 
else:
	print "The hash you are looking for does not exist. Please try again"
