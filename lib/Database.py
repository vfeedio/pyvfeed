#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2020 vFeed, Inc. - https://vfeed.io

import json
import sys
import sqlite3

from common import utils as utility


class Database(object):
    def __init__(self, identifier, cursor="", query=""):

        # init test
        response = json.loads(utility.init())

        if not response["success"]:
            print(utility.serialize_data(response))
            sys.exit()

        # case CVE lower
        if "cve" in identifier:
            identifier = identifier.upper()

        self.identifier = identifier
        self.cur = cursor
        self.query = query
        self.db = utility.set_db_file()

    def db_init(self):
        try:
            self.conn = sqlite3.connect(self.db)
            self.cur = self.conn.cursor()
            self.query = (self.identifier,)
            return self.cur, self.query
        except sqlite3.OperationalError as e:
            response = utility.serialize_error(False, str(e), str(e))
            sys.exit(response)
