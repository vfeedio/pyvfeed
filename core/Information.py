#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2020 vFeed, Inc. - https://vfeed.io

import json

from lib.Database import Database
from collections import OrderedDict
from common import utils as utility


class Information(object):
    def __init__(self, id):
        """ init """
        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_all(self):
        """ callable method - return basic and references as json"""

        info = json.loads(self.get_info(), object_pairs_hook=OrderedDict)
        references = json.loads(self.get_references(), object_pairs_hook=OrderedDict)
        # merge
        info.update(references)

        # format the response
        response = {"information": info}

        return utility.serialize_data(response)

    def get_info(self):
        """ callable method - return vulnerability basic info as JSON """

        # init local list
        response = []

        self.cur.execute('SELECT * FROM cve_db WHERE cve_id=?', self.query)

        for data in self.cur.fetchall():
            # format the response
            information = {"id": self.id, "parameters": {"published": data[1], "modified": data[2],
                                                         "summary": data[3]}}
            response.append(information)

        # set the tag
        response = {"description": response}

        return utility.serialize_data(response)

    def get_references(self):
        """ callable method -  return vulnerability references """

        # init local list
        response = []

        self.cur.execute('SELECT * FROM map_refs_cve WHERE cve_id=?', self.query)

        for data in self.cur.fetchall():
            # setting reference info
            vendor = data[0]
            url = data[1]

            # format the response
            references = {"vendor": vendor, "url": url}
            response.append(references)

        # set the tag
        response = {"references": response}

        return utility.serialize_data(response)
