#!/usr/bin/env python3
# API Python wrapper for The Next Generation Vulnerability & Threat Intelligence Database  - https://vfeed.io
# Copyright (C) 2013 - 2018 vFeed IO

import json

from lib.Database import Database
from collections import OrderedDict
from common import utils as utility


class Defense(object):
    def __init__(self, id):
        """ init """

        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_all(self):
        """ callable method - return both remote and local scanners signatures"""

        advisory = json.loads(Preventive(self.id).get_advisory(), object_pairs_hook=OrderedDict)
        rules = json.loads(Detective(self.id).get_rules(), object_pairs_hook=OrderedDict)

        advisory.update(rules)

        # format the response
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
        response = []

        self.cur.execute("SELECT source FROM advisory_db GROUP BY source")

        for source in self.cur.fetchall():
            source = source[0].strip()
            data = self.enum_bulletins(source)

            # get only responses with valid data.
            if data:
                # format the response
                tag = {source: data}
                response.append(tag)

        # set tag
        response = {"preventive": response}

        return utility.serialize_data(response)

    def enum_bulletins(self, source):
        """ list information from different sources related to advisories and bulletins"""

        # init local list
        response = []

        self.cur.execute("SELECT DISTINCT type,id,link FROM advisory_db WHERE source = '{0}' and cve_id=? ".format(source),
                         self.query)

        for data in self.cur.fetchall():
            type = data[0]
            id = data[1]
            url = data[2]

            # format the response
            bulletins = {"id": id, "parameters": {"class": type, "url": url}}
            response.append(bulletins)

        return response


class Detective(object):
    def __init__(self, id):
        """ init """

        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_rules(self):
        """ callable method - return IPS and IDS signatures """

        # init local list
        response = []

        self.cur.execute("SELECT source FROM detection_db GROUP BY source")

        for source in self.cur.fetchall():
            source = source[0].strip()
            data = self.enum_rules(source)

            # get only responses with valid data. Otherwise the json will be huge (a lot of sources :) )
            if data:
                tag = {source: data}
                response.append(tag)

        # set tag.
        response = {"detective": response}

        return utility.serialize_data(response)

    def enum_rules(self, source):
        """ list information from different sources related to IPS and IDS"""

        response = []

        self.cur.execute(
            "SELECT DISTINCT id,class,title,link FROM detection_db WHERE source = '{0}' and cve_id=?".format(source), self.query)

        for data in self.cur.fetchall():
            id = data[0]
            family = data[1]
            title = data[2]
            url = data[3]

            rules = {"id": id,
                     "parameters": {"class": family, "title": title, "url": url}}

            response.append(rules)

        return response
