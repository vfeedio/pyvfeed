#!/usr/bin/env python3
# API Python wrapper for The Next Generation Vulnerability & Threat Intelligence Database  - https://vfeed.io
# Copyright (C) 2013 - 2018 vFeed IO

import json

from lib.Database import Database
from common import utils as utility


class Classification(object):
    def __init__(self, id):
        """ init """
        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_targets(self):
        """ callable method - return targets affected by vulnerability"""

        # init local list
        targets = []

        # count
        self.cur.execute('SELECT count(cpe_id) FROM map_cpe_cve WHERE cve_id=?', self.query)
        self.count = self.cur.fetchone()

        # getting data
        self.data = self.cur.execute('SELECT * FROM map_cpe_cve WHERE cve_id=?', self.query)
        self.data = self.cur.fetchall()

        for i in range(0, self.count[0]):
            try:
                # setting target title from CPE database
                self.cur.execute("SELECT title FROM cpe_db where cpe_id = ?", (self.data[i][0],))
                self.title = self.cur.fetchone()
                if self.title is not None:
                    self.title = self.title[0]

                response = {"title": self.title, "cpe2.2": self.data[i][0], "cpe2.3": self.data[i][1]}
                targets.append(response)

            except:
                pass

        # adding the appropriate tag.
        targets = {"targets": targets}

        return utility.serialize_data(targets)

    def get_weaknesses(self):
        """ callable method - return weaknesses affected by vulnerability"""

        # init local list
        weaknesses = []

        # count
        self.cur.execute('SELECT count(cwe_id) FROM map_cwe_cve WHERE cve_id=?', self.query)
        self.count = self.cur.fetchone()

        # getting data
        self.data = self.cur.execute('SELECT * FROM map_cwe_cve WHERE cve_id=?', self.query)
        self.data = self.cur.fetchall()

        # extracting CWE/CAPEC/WASC/CATEROGIES
        for i in range(0, self.count[0]):
            try:
                self.cwe_id = self.data[i][0]
                self.cur.execute(
                    "SELECT title,link,class,relations,capec_id FROM cwe_db WHERE cwe_id='%s' " % self.cwe_id)
                self.data_2 = self.cur.fetchall()

                # setting parameters
                self.title = self.data_2[0][0]
                self.url = self.data_2[0][1]
                self.cwe_class = self.data_2[0][2]
                self.relation = self.data_2[0][3]
                self.capec = self.data_2[0][4]

                # formatting the response
                response = {"id": self.data[i][0],
                            "parameters": {"class": self.cwe_class, "title": self.title,
                                           "relationship": self.relation, "url": self.url,
                                           "attack_patterns": self.enum_capec(),
                                           "ranking": {"category": self.enum_category(),
                                                       "wasc": self.enum_wasc()}}}

                weaknesses.append(response)

            except:
                pass
        # adding the appropriate tag.
        weaknesses = {"weaknesses": weaknesses}

        return utility.serialize_data(weaknesses)

    def get_all(self):
        """ callable method - return both targets and weaknesses affected by vulnerability"""

        targets = json.loads(self.get_targets())
        weaknesses = json.loads(self.get_weaknesses())

        targets.update(weaknesses)

        # formatting the response
        response = {"classification": targets}

        return utility.serialize_data(response)

    def enum_capec(self):
        """ return extra CAPEC data from CAPEC database """

        # init local list
        capec_list = []

        # Splitting identifiers
        capecs = self.capec.split(",")

        if (len(capecs[0])) != 0:
            for capec_id in capecs:
                self.cur.execute("SELECT title,link,attack_id FROM capec_db WHERE capec_id='%s' " % capec_id)
                data = self.cur.fetchall()

                # setting capec data
                title = data[0][0]
                url = data[0][1]
                attack_id = data[0][2]

                # formatting the response
                response = {
                    capec_id: {"parameters": {"title": title, "attack_id": attack_id, "url": url}}}

                capec_list.append(response)

        return utility.check_list_data(capec_list)

    def enum_wasc(self):
        """ return WASC identifiers from WASC database"""

        # init local list
        wasc_list = []

        self.cur.execute("SELECT count(wasc_id) FROM wasc_db WHERE cwe_id='%s' " % self.cwe_id)
        count = self.cur.fetchone()

        self.cur.execute("SELECT wasc_id,title,link FROM wasc_db WHERE cwe_id='%s' " % self.cwe_id)
        data = self.cur.fetchall()

        for i in range(0, count[0]):
            # setting wasc data
            wasc_id = data[i][0]
            title = data[i][1]
            url = data[i][2]

            # formatting the response
            response = {
                title: {"parameters": {"id": wasc_id, "url": url}}}

            wasc_list.append(response)

        return utility.check_list_data(wasc_list)

    def enum_category(self):
        """ return categories identifiers such Top 25 and OWASP Top etc .."""

        # init local list
        category_list = []

        self.cur.execute("SELECT cwe_id,title,link,relations FROM cwe_db where class = 'category' and relations like ?",
                         ('%' + self.cwe_id + '%',))

        for data in self.cur.fetchall():
            # setting category data
            category_id = data[0]
            title = data[1]
            url = data[2]
            relations = data[3].split(',')

            # listing only categories for the exact CWE id
            if self.cwe_id in relations:
                # formatting the response
                response = {title: {"parameters": {"id": category_id, "url": url}}}
                category_list.append(response)

        return utility.check_list_data(category_list)
