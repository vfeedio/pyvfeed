#!/usr/bin/env python3
# API Python wrapper for The Next Generation Vulnerability & Threat Intelligence Database  - https://vfeed.io
# Copyright (C) 2013 - 2018 vFeed IO

import json

from lib.Database import Database
from common import utils as utility
from core.Information import Information


class Search(object):
    def __init__(self, id):
        self.id = id
        self.result = []
        (self.cur, self.query) = Database(self.id).db_init()

    def search_cve(self):
        """ basic search CVE identifiers """

        self.result = json.loads(Information(self.id).get_info())

        if self.result['description'] != []:
            return utility.serialize_data(self.result)

    def search_cpe(self):
        """ basic search for CPE identifiers """

        if "cpe" not in self.id:
            response = utility.serialize_error(False, self.id, "Not a valid CPE identifier")
            return response

        # check whether is CPE 2.2 or CPE 2.3
        if "cpe:2.3" in self.id:
            col = "cpe23_id"

        if "cpe:/" in self.id:
            col = "cpe_id"

        self.cur.execute(
            "SELECT count(DISTINCT {tn}) FROM map_cpe_cve WHERE {tn} = ? ORDER BY cve_id DESC".format(tn=col),
            self.query)
        self.count_cpe = self.cur.fetchone()

        self.cur.execute("SELECT * FROM map_cpe_cve WHERE {tn} = ? ORDER BY cve_id DESC".format(tn=col), self.query)
        data = self.cur.fetchall()

        if data:
            for i in range(0, self.count_cpe[0]):
                # init dict
                cve = []
                self.cur.execute("SELECT cve_id FROM map_cpe_cve WHERE {tn} = ? ORDER BY cve_id DESC".format(tn=col),
                                 self.query)

                for cve_id in self.cur.fetchall():
                    cve.append(cve_id[0])

                item = {"id": self.id, "vulnerability": cve}
                self.result.append(item)

        return utility.serialize_data(self.result)
