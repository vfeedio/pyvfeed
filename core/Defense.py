#!/usr/bin/env python3
# API Python wrapper for The Next Generation Vulnerability & Threat Intelligence Database  - https://vfeed.io
# Copyright (C) 2013 - 2018 vFeed IO

import json

from lib.Database import Database
from common import utils as utility


class Defense(object):
    def __init__(self, id):
        """ init """

        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_all(self):
        """ callable method - return both remote and local scanners signatures"""

        advisory = json.loads(Preventive(self.id).get_advisory())
        rules = json.loads(Detective(self.id).get_rules())

        advisory.update(rules)

        # formatting the response
        response = {"defense": advisory}

        return utility.serialize_data(response)


class Preventive(object):
    def __init__(self, id):
        """ init """

        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_advisory(self):
        """ callable method - return bulletins and advisories data """

        # init local list
        advisory = []

        self.cur.execute("SELECT source FROM advisory_db GROUP BY source")

        for data in self.cur.fetchall():
            self.source = data[0].strip()
            responses = self.enum_bulletins()

            # get only responses with valid data. Otherwise the json will be huge (a lot of sources :) )
            if responses is not None:
                response = {self.source: responses}
                advisory.append(response)

        # adding the appropriate tag.
        advisory = {"preventive": advisory}

        return utility.serialize_data(advisory)

    def enum_bulletins(self):
        """ list information from different sources related to advisories and bulletins"""

        signatures = []

        # count
        self.cur.execute(
            "SELECT count(id) FROM advisory_db WHERE (source = '{tn}') and cve_id=? order by id".format(
                tn=self.source),
            self.query)
        self.count = self.cur.fetchone()

        self.cur.execute(
            "SELECT * FROM advisory_db WHERE (source = '{tn}') and cve_id=?".format(
                tn=self.source),
            self.query)
        data = self.cur.fetchall()

        # only sources with valid data

        for i in range(0, self.count[0]):
            # setting advisories information
            type = data[i][0]
            sig_id = data[i][2]
            url = data[i][3]

            # formatting the response
            response = {"id": sig_id, "parameters": {"class": type, "url": url}}
            signatures.append(response)

        return utility.check_list_data(signatures)


class Detective(object):
    def __init__(self, id):
        """ init """

        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_rules(self):
        """ callable method - return IPS and IDS signatures """

        # init local list
        rules = []

        self.cur.execute("SELECT source FROM detection_db GROUP BY source")

        for data in self.cur.fetchall():
            self.source = data[0].strip()
            responses = self.enum_rules()

            # get only responses with valid data. Otherwise the json will be huge (a lot of sources :) )
            if responses is not None:
                response = {self.source: responses}
                rules.append(response)

        # adding the appropriate tag.
        rules = {"detective": rules}

        return utility.serialize_data(rules)

    def enum_rules(self):
        """ list information from different sources related to IPS and IDS"""

        signatures = []

        # count
        self.cur.execute(
            "SELECT count(id) FROM detection_db WHERE (source = '{tn}') and cve_id=?".format(
                tn=self.source),
            self.query)
        self.count = self.cur.fetchone()

        self.cur.execute(
            "SELECT * FROM detection_db WHERE (source = '{tn}') and cve_id=?".format(tn=self.source),
            self.query)
        data = self.cur.fetchall()

        for i in range(0, self.count[0]):
            # setting rules information
            sig_id = data[i][1]
            family = data[i][2]
            title = data[i][3]
            url = data[i][4]

            # formatting the response
            response = {"id": sig_id,
                        "parameters": {"class": family, "title": title, "url": url}}
            signatures.append(response)

        return utility.check_list_data(signatures)
