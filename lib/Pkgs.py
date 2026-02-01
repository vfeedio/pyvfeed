#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2026 Zetafence vFeed, Inc. - https://vfeed.io

import sys, json

from lib.Database import Database
from common import utils as utility
from core.Information import Information
from core.Exploitation import Exploitation

#
# Packages affected with vulnerabilities
#
class Pkgs(object):
    def __init__(self, id):
        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def search_pkgs(self):
        """ list CVEs for packages affected """
        pkg = sys.argv[2]
        version = "*"
        if len(sys.argv) == 4:
            version = sys.argv[3]
        if pkg == "" or pkg == "*":
            print("error: please search for specific package e.g. wordpress")
            return utility.serialize_data([{}])
        pkg = ":" + pkg + ":"
        print(f"Searching for vulnerabilities in package '{pkg}' version '{version}'")

        # query the database
        squery = f"""
        SELECT pkg.cve_id, pkg.cpe_id, pkg.version_start_incl, pkg.version_end_incl,
               cve_db.summary, cvss_scores.cvss3_vector
            FROM packages_affected AS pkg
            LEFT JOIN cve_db ON cve_db.cve_id = pkg.cve_id
            LEFT JOIN cvss_scores ON pkg.cve_id = cvss_scores.cve_id
            ORDER BY pkg.cve_id DESC;
        """
        self.cur.execute(squery)

        # fetch all data and iterate through
        responses = []
        for data in self.cur.fetchall():
            # package cpe match
            cpeid = str(data[1])
            if pkg not in cpeid:
                continue

            # append all if wildcard
            if version == "*":
                 responses.append({
                     "cve_id":  data[0],
                     "cpe_id": data[1],
                     "version_start_incl": data[2],
                     "pkg.version_end_incl": data[3],
                     "cve_summary": data[4] if data[4] else "none",
                     "cvss3_vector": data[5] if data[5] else "none",
                 })
            else:
                 version_start = str(data[2])
                 version_end   = str(data[3])
                 if version_start == "" and version_end == "":
                     continue
                 if version >= version_start and version <= version_end:
                     responses.append({
                         "cve_id":  data[0],
                         "cpe_id": cpeid,
                         "version_start_incl": data[2],
                         "pkg.version_end_incl": data[3],
                         "cve_summary": data[4] if data[4] else "none",
                         "cvss3_vector": data[5] if data[5] else "none",
                     })
        if len(responses) == 0:
            responses = [{}]
        return utility.serialize_data(responses)
