#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2026 Zetafence vFeed Threat Intelligence - https://vfeed.io

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
               cve_db.summary, cvss_scores.cvss3_vector,
               cvss4_scores.cvss4_vector, cvss4_scores.cvss4_base,
               cve_metadata.vuln_status, cve_metadata.source_identifier,
               cve_metadata.has_exploits, cve_metadata.has_kev_cisa,
               cve_metadata.has_patches, cve_metadata.has_advisory,
               cve_metadata.risk_score
            FROM packages_affected AS pkg
            LEFT JOIN cve_db        ON cve_db.cve_id = pkg.cve_id
            LEFT JOIN cvss_scores   ON pkg.cve_id = cvss_scores.cve_id
            LEFT JOIN cvss4_scores  ON pkg.cve_id = cvss4_scores.cve_id
            LEFT JOIN cve_metadata  ON pkg.cve_id = cve_metadata.cve_id
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

            def build_entry(cve_id, cpe_id, d):
                e = {
                    "cve_id":               cve_id,
                    "cpe_id":               cpe_id,
                    "version_start_incl":   d[2],
                    "pkg.version_end_incl": d[3],
                    "cve_summary":          d[4] if d[4] else "none",
                    "cvss3_vector":         d[5] if d[5] else "none",
                }
                if d[6]:
                    e["cvss4_vector"] = d[6]
                if d[7]:
                    e["cvss4_base"] = d[7]
                # include cve_metadata fields only when a row exists (vuln_status not NULL)
                if d[8] is not None:
                    e.update({
                        "vuln_status":       d[8],
                        "source_identifier": d[9],
                        "has_exploits":      bool(d[10]),
                        "has_kev_cisa":      bool(d[11]),
                        "has_patches":       bool(d[12]),
                        "has_advisory":      bool(d[13]),
                        "risk_score":        d[14],
                    })
                return e

            # append all if wildcard
            if version == "*":
                responses.append(build_entry(data[0], data[1], data))
            else:
                 version_start = str(data[2])
                 version_end   = str(data[3])
                 if version_start == "" and version_end == "":
                     continue
                 if version >= version_start and version <= version_end:
                     responses.append(build_entry(data[0], cpeid, data))
        if len(responses) == 0:
            responses = [{}]
        return utility.serialize_data(responses)
