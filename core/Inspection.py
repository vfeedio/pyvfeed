#!/usr/bin/env python3
# API Python wrapper for The Next Generation Vulnerability & Threat Intelligence Database  - https://vfeed.io
# Copyright (C) 2013 - 2018 vFeed IO

import json

from lib.Database import Database
from common import utils as utility


class Inspection(object):
    def __init__(self, id):
        """ init """
        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_remote(self):
        """ callable method - return remote scanners / VAT signatures and scripts """

        # init local list
        remote = []

        self.cur.execute("SELECT source FROM scanners_db WHERE source NOT LIKE '%oval%' GROUP BY source")

        for data in self.cur.fetchall():
            self.source = data[0].strip()
            responses = self.enum_scanners()
            if responses is not None:
                response = {self.source: responses}
                remote.append(response)

        # adding the appropriate tag.
        remote = {"remote": remote}

        return utility.serialize_data(remote)

    def get_local(self):
        """ callable method - return local scanners / VAT signatures and scripts """

        # init local list
        local = []

        self.cur.execute("SELECT source FROM scanners_db WHERE source LIKE '%oval%' GROUP BY source")

        for data in self.cur.fetchall():
            self.source = data[0].strip()
            responses = self.enum_scanners()
            if responses is not None:
                response = {self.source: responses}
                local.append(response)

        # adding the appropriate tag.
        local = {"local": local}

        return utility.serialize_data(local)

    def get_all(self):
        """ callable method - return both remote and local scanners signatures"""

        remote = json.loads(self.get_remote())
        local = json.loads(self.get_local())

        remote.update(local)

        # formatting the response
        response = {"inspection": remote}

        return utility.serialize_data(response)

    def enum_scanners(self):
        """ list information from different sources related to remote VAT scanners"""

        # init local list
        signatures = []

        # count
        self.cur.execute(
            "SELECT count(id) FROM scanners_db WHERE (source = '{tn}') and cve_id=? order by id".format(tn=self.source),
            self.query)
        self.count = self.cur.fetchone()

        self.cur.execute(
            "SELECT * FROM scanners_db WHERE (source = '{tn}') and cve_id=? order by id".format(tn=self.source),
            self.query)
        data = self.cur.fetchall()

        for i in range(0, self.count[0]):
            # setting scanner information
            sig_id = data[i][1]
            family = data[i][2]
            name = data[i][3]
            file = data[i][4]
            url = data[i][5]

            # formatting the response
            response = {"id": sig_id,
                        "parameters": {"class": family, "name": name,
                                       "file": file, "url": url}}

            signatures.append(response)

        return utility.check_list_data(signatures)
