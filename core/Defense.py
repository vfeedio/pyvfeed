#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2020 vFeed, Inc. - https://vfeed.io

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

        # merging the json data
        advisory.update(rules)

        # format the response
        response = {"defense": advisory}

        return utility.serialize_data(response)


class Preventive(object):
    def __init__(self, id):
        """ init """

        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_patches(self):
        """ callable method - return patches & fixed packages data """

        # init local list
        response = []

        # get the list of available relevant vendors (sources)
        self.cur.execute("SELECT source FROM patches_db GROUP BY source")

        for source in self.cur.fetchall():
            source = source[0].strip()
            (data, date_published, description) = self.enum_patches(source)

            # get only responses with valid data.
            if data:
                # format the response
                tag = {source: {"date_published": date_published, "description": description, "packages": data}}
                response.append(tag)

        return utility.serialize_data(response)

    def enum_patches(self, source):
        """ list patches & affected packages from different sources """

        # init local list
        response = []
        date_published = False
        description = False

        self.cur.execute(
            "SELECT package FROM patches_db WHERE source = '{0}' and cve_id=? group by package".format(source),
            self.query)
        for package in self.cur.fetchall():
            package = package[0].strip()
            if package:
                self.cur.execute(
                    "SELECT DISTINCT date_published, description, product,version_fixed, version_not_fixed, "
                    "fix_status FROM "
                    "patches_db WHERE "
                    "package = '%s' AND source = '%s' AND cve_id = '%s'" % (package, source, self.query[0]))

                datas = self.cur.fetchall()

                # craft packaging for every loop
                packaging = []

                for data in datas:
                    date_published = data[0]
                    description = data[1]
                    product = data[2]
                    version_fixed = data[3]
                    version_not_fixed = data[4]
                    fix_status = data[5]

                    # format the patches response
                    patches = {"product": product, "version_fixed": version_fixed,
                               "version_not_fixed": version_not_fixed, "status": fix_status}
                    packaging.append(patches)

                # set the response tag for packages
                tag = {package: packaging}
                response.append(tag)

        return response, date_published, description

    def get_advisory(self):
        """ callable method - return bulletins and advisories data """

        # init local list
        response = []

        # get the list of available relevant sources
        self.cur.execute("SELECT source FROM advisory_db GROUP BY source")

        for source in self.cur.fetchall():
            source = source[0].strip()
            data = self.enum_bulletins(source)

            # get only responses with valid data.
            if data:
                # format the response
                tag = {source: data}
                response.append(tag)

        # load the patches data to be merged
        patches = json.loads(Preventive(self.id).get_patches(), object_pairs_hook=OrderedDict)

        # set the response tag
        response = {"preventive": {"bulletins": response, "patches": patches}}

        return utility.serialize_data(response)

    def enum_bulletins(self, source):
        """ list information from different sources related to advisories and bulletins"""

        # init local list
        response = []

        self.cur.execute(
            "SELECT DISTINCT type,id,link FROM advisory_db WHERE source = '{0}' and cve_id=? ".format(source),
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
            "SELECT DISTINCT id,class,title,link FROM detection_db WHERE source = '{0}' and cve_id=?".format(source),
            self.query)

        for data in self.cur.fetchall():
            id = data[0]
            family = data[1]
            title = data[2]
            url = data[3]

            rules = {"id": id,
                     "parameters": {"class": family, "title": title, "url": url}}

            response.append(rules)

        return response
