#!/usr/bin/env python3

import json

from lib.Database import Database
from collections import OrderedDict
from common import utils as utility


class Inspection(object):
    def __init__(self, id):
        """ init """
        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_all(self):
        """ callable method - return both remote and local scanners signatures"""

        remote = json.loads(self.get_remote(), object_pairs_hook=OrderedDict)
        local = json.loads(self.get_local(), object_pairs_hook=OrderedDict)

        remote.update(local)

        # set the tag
        response = {"inspection": remote}

        return utility.serialize_data(response)

    def get_remote(self):
        """  callable method - return both remote scanners signatures """

        # init response dict
        response = []

        self.cur.execute("SELECT source FROM scanners_db WHERE source NOT LIKE '%oval%' and cve_id=? GROUP BY source",
                         self.query)

        for source in self.cur.fetchall():
            source = source[0].strip()
            data = self.enum_signatures(source)

            tag = {source: data}
            response.append(tag)

        # set the tag
        response = {"remote": response}
        return utility.serialize_data(response)

    def get_local(self):
        """  callable method - local scanners signatures """

        # init response dict
        response = []

        self.cur.execute(
            "SELECT source FROM scanners_db WHERE source LIKE '%oval%' and cve_id=? GROUP BY source",
            self.query)

        for source in self.cur.fetchall():
            source = source[0].strip()
            data = self.enum_signatures(source)

            tag = {source: data}
            response.append(tag)

        # set the tag
        response = {"local": response}
        return utility.serialize_data(response)

    def enum_signatures(self, source):
        """ not callable method - enumerate data """

        # init signatures dict
        response = []

        self.cur.execute(
            "SELECT DISTINCT id,family, name, file, link FROM scanners_db WHERE source = '{0}' and cve_id=? ".format(source),
            self.query)

        for data in self.cur.fetchall():
            id = data[0]
            family = data[1]
            name = data[2]
            file = data[3]
            url = data[4]

            signatures = {"id": id,
                          "parameters": {"family": family, "name": name,
                                         "file": file, "url": url}}
            response.append(signatures)

        return response
