#!/usr/bin/env python3

# API Python wrapper for The Next Generation Vulnerability & Threat Intelligence Database  - https://vfeed.io
# Copyright (C) 2013 - 2018 vFeed IO

import json

cve = "CVE-2017-5715"

# loading a vulnerability information
from core.Information import Information

info = Information(cve).get_info()
# printing the response (by default in JSON)
print(info)

# now printing only Idenfitier or any other specific key
# first we load the response with json.loads
info = json.loads(info)

# Access to key values.
for key in info['description']:
    for source in key:
        values = key[source]
        if "id" in source:
            print(values)
        if "parameters" in source:
            print(values['published'])
            print(values['modified'])
            print(values['summary'])

# now we load the references
reference = Information(cve).get_references()
print(reference)

reference = json.loads(reference)

for i in range(0, len(reference['references'])):
    print("The vendor and his url  ({}) = ({})".format(reference['references'][i]['vendor'],
                                                       reference['references'][i]['url']))

# loading a vulnerability targets
from core.Classification import Classification

cve = "CVE-2017-0199"
targets = Classification(cve).get_targets()
print(targets)

targets = json.loads(targets)

# looking for a specific target CPE Windows server 2012

for i in range(0, len(targets['targets'])):

    if "cpe:/o:microsoft:windows_server_2012:" in targets['targets'][i]['cpe2.2']:
        print(targets['targets'][i]['title'])
        print(targets['targets'][i]['cpe2.2'])
        print(targets['targets'][i]['cpe2.3'])

# loading a vulnerability weakeness
weaknesses = Classification(cve).get_weaknesses()
print(weaknesses)

# loading a vulnerability exploits
from core.Exploitation import Exploitation

cve = "CVE-2017-0199"

exploits = Exploitation(cve).get_exploits()

# printing the response (by default in JSON)
print(exploits)

# doing something more complicated ;)
# extracting exploit source, exploit id and exploit file
data = json.loads(exploits)

# here is the loop to use
for key in data['exploitation']:
    for source in key:
        print("--------")
        print(source)
        values = key[source]
        for value in values:
            print(value['id'])
            params = value['parameters']
            print(params['file'])

# Enumerating only preventive info (patches, bugs, fixes ....)
from core.Defense import Preventive

cve = "CVE-2017-5638"
advisory = Preventive(cve).get_advisory()
print(advisory)

# Listing only detectinve (IPS, IDS rules + other cool sources)
from core.Defense import Detective

cve = "CVE-2017-5638"
rules = Detective(cve).get_rules()
print(rules)

# Now lets do both
from core.Defense import Defense

cve = "CVE-2017-5638"
defense_data = Defense(cve).get_all()
print(defense_data)

# exporting to json
cve = "CVE-2017-0199"
from core.Export import Export

Export(cve).dump_json()

# update module
from lib.Update import Update

Update().update()

# search module
from lib.Search import Search

# search a CPE 2.2
cpe = "cpe:/a:apache:tomcat:7.0.5"
print(Search(cpe).search_cpe())

# search a CPE 2.3
cpe = "cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*"
print(Search(cpe).search_cpe())

# search a cve
cpe = "cve-2017-3100"
print(Search(cpe).search_cve())