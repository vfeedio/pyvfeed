#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2020 vFeed, Inc. - https://vfeed.io

import json

from lib.Database import Database
from common import utils as utility
from core.Information import Information
from core.Exploitation import Exploitation

#
# Language vulnerabilities
#
class Lang(object):
    def __init__(self, id):
        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_lang_cpe(self, lang):
        """ given lang, return CPE id """
        if lang is None:
            return None
        match str(lang).lower():
            case "c++" | "cpp" :
                return "glibc"
            case "python":
                return "python:python"
            case "javascript" | "golang" | "java":
                return lang
        return lang

    def search_lang(self):
        """ list CVEs for languages """

        # query the database
        lang_summary = self.id
        lang_cpe = self.get_lang_cpe(self.id)
        squery = f"""
        SELECT cve_db.cve_id, cve_db.summary, cvss_scores.cvss3_access_vector, map_cpe_cve.cpe23_id
            FROM cve_db
            LEFT JOIN cvss_scores ON cve_db.cve_id = cvss_scores.cve_id
            LEFT JOIN map_cpe_cve ON cve_db.cve_id = map_cpe_cve.cve_id
            WHERE cve_db.summary LIKE '%{lang_summary}%' OR map_cpe_cve.cpe23_id LIKE '%{lang_cpe}%'
            ORDER BY cve_db.cve_id DESC;
        """
        self.cur.execute(squery)

        # fetch all data and iterate through
        responses = []
        for data in self.cur.fetchall():
            responses.append({
                "cve_id":  data[0],
                "summary": data[1],
                "cvss3_access_vector": data[2],
                "cpe23_id": data[3],
            })
        return utility.serialize_data(responses)
