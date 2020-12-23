#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2020 vFeed, Inc. - https://vfeed.io

import json

from lib.Database import Database
from common import utils as utility
from core.Information import Information
from core.Exploitation import Exploitation


class Search(object):
    def __init__(self, id):
        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def search_cve(self):
        """ basic search CVE identifiers """

        # set the CVE as uppercase
        self.id = self.id.upper()

        # check if valid CVE
        if not self.id.startswith('CVE-'):
            response = utility.serialize_error(False, self.id, "Not a valid CVE identifier")
            return response

        # load CVE data
        response = json.loads(Information(self.id).get_info())
        exploits = json.loads(Exploitation(self.id).get_exploits())

        if response['description'] != []:
            # new tag added to search whenever an exploits is available
            if exploits['exploitation'] != []:
                response.update(exploits)

            return utility.serialize_data(response)

    def search_cwe(self):
        """ basic search CWE identifiers """

        # set the CWE as uppercase
        self.cwe = self.id.upper()

        # check if valid CWE
        if not self.cwe.startswith('CWE-'):
            response = utility.serialize_error(False, self.id, "Not a valid CWE identifier")
            return response

        # query the database
        self.cur.execute("SELECT title,class,link  FROM cwe_db WHERE cwe_id=? ", (self.cwe,))
        cwe_data = self.cur.fetchone()

        if cwe_data:
            # set the CWE data
            title = cwe_data[0]
            cwe_class = cwe_data[1]
            url = cwe_data[2]

            # query the database
            self.cur.execute("SELECT cve_id from map_cwe_cve where cwe_id=? ORDER BY cve_id DESC", (self.cwe,))
            data = self.cur.fetchall()

            if data:
                # init dict
                cve = []
                for cve_id in data:
                    cve.append(cve_id[0])

                # set the response
                response = {"id": self.cwe, "parameters": {"title": title, "class": cwe_class, "url": url},
                            "vulnerability": cve}

                return utility.serialize_data(response)

    def search_cpe(self):
        """ basic search for CPE identifiers """

        if not self.id.startswith("cpe:/") and not self.id.startswith("cpe:2.3:"):
            response = utility.serialize_error(False, self.id, "Not a valid CPE identifier")
            return response

        # check whether is CPE 2.2 or CPE 2.3
        if "cpe:2.3" in self.id:
            col = "cpe23_id"

        if "cpe:/" in self.id:
            col = "cpe_id"

        # query the database
        self.cur.execute("SELECT cve_id FROM map_cpe_cve WHERE {tn} = ? ORDER BY cve_id DESC".format(tn=col),
                         self.query)
        data = self.cur.fetchall()

        if data:
            # init dict
            cve = []
            for cve_id in data:
                cve.append(cve_id[0])

            # set the response
            response = {"id": self.id, "vulnerability": cve}
            return utility.serialize_data(response)
