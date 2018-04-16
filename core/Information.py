#!/usr/bin/env python3
# API Python wrapper for The Next Generation Vulnerability & Threat Intelligence Database  - https://vfeed.io
# Copyright (C) 2013 - 2018 vFeed IO

import json

from lib.Database import Database
from common import utils as utility


class Information(object):
    def __init__(self, id):
        """ init """
        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_info(self):
        """ callable method - return vulnerability basic info as JSON """

        # init local list
        info = []

        self.cur.execute('SELECT * FROM cve_db WHERE cve_id=?', self.query)

        for data in self.cur.fetchall():
            # formatting the response
            response = {"id": self.id, "parameters": {"published": data[1], "modified": data[2],
                        "summary": data[3]}}
            info.append(response)

        # adding the appropriate tag.
        info = {"description": info}

        return utility.serialize_data(info)

    def get_references(self):
        """ callable method -  return vulnerability references """

        # init local list
        references = []

        self.cur.execute('SELECT * FROM map_refs_cve WHERE cve_id=?', self.query)

        for data in self.cur.fetchall():
            # setting reference info
            vendor = data[0]
            url = data[1]
            # formatting the response
            response = {"vendor": vendor, "url": url}
            references.append(response)

        # adding the appropriate tag.
        references = {"references": references}

        return utility.serialize_data(references)

    def get_all(self):
        """ callable method - return basic and references as json"""

        info = json.loads(self.get_info())
        references = json.loads(self.get_references())
        # merge
        info.update(references)

        # formatting the response
        response = {"information": info}

        return utility.serialize_data(response)
