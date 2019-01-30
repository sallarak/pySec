#!/usr/bin/python

# Resource: https://github.com/tbhaxor/virustotal-cli/blob/master/virustotal/url.py

import requests
from virustotal.settings import get
from dashtable import data2rst
from virustotal import globals
from virustotal import notations

api = {"report": "https://www.virustotal.com/vtapi/v2/url/report",
       "scan": "https://www.virustotal.com/vtapi/v2/url/scan", }

param = {"apikey": get("api")}


def report(url):
    print("{}URL REPORT LOADED".format(notations._run))
    print("{}Building Query".format(notations.star))
    param["resource"] = url
    try:
        print("{}Checking URL Connection".format(notations._run))
        r = requests.get(api["report"], params=param)
        print("{}Fetching the response".format(notations.star))
        data = dict(r.json())
        print("{}Formatting the response to human readable format".format(notations.star))
        table = []
        for x, y in data.items():
            x = x.replace("_", " ")
            x = x.title()
            if x == "Scans":
                continue
            elif x == "total":
                x = "Total Scans"
            table.append([x, y])
        print("{}Scan result for {}".format(notations.info, url))
        print(data2rst(table, use_headers=False))
        x = input("{}Do you want scan result of anti viruses [y/N] ".format(notations.ques)).lower()
        if x == "y":
            globals.showScanResult(data['scans'])
    except requests.ConnectionError:
        print("{}Can't connect to internet".format(notations._err))
        exit(1)
        pass
    except requests.HTTPError:
        print("{}Invalid URL".format(notations._err))
        exit(1)
    pass


def scan(url):
    print("{}URL SCAN LOADED".format(notations._run))
    print("{}Building Query".format(notations.star))
    param["url"] = url
    try:
        print("{}Checking URL Connection".format(notations.star))
        r = requests.post(api["scan"], params=param)
        print("{}Fetching the response".format(notations.star))
        data = r.json()
        table = []
        for x, y in data.items():
            x = x.replace("_", " ")
            x = x.title()
            if not x == "Response Code":
                table.append([x, y])
        if data["response_code"] == -1:
            raise requests.HTTPError
        print("{}Scan result for {}".format(notations.star, url))
        print(data2rst(table, use_headers=False))
        x = input("{}Do you want to retrieve scan report [y/N]".format(notations.ques)).lower()
        if x == "y":
            report(url)
    except requests.ConnectionError:
        print("{}Can't connect to internet".format(notations._err))
        exit(1)
        pass
    except requests.HTTPError:
        print("{}Invalid URL".format(notations._err))
        exit(1)

    pass

