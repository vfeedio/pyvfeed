#!/usr/bin/env python3

import json

from lib.Database import Database
from collections import OrderedDict
from common import utils as utility


class Classification(object):
    def __init__(self, id):
        """ init """
        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_all(self):
        """ callable method - return both targets and weaknesses affected by vulnerability"""

        targets = json.loads(self.get_targets(), object_pairs_hook=OrderedDict)
        weaknesses = json.loads(self.get_weaknesses(), object_pairs_hook=OrderedDict)

        targets.update(weaknesses)

        # format the response
        response = {"classification": targets}

        return utility.serialize_data(response)

    def get_targets(self):
        """ callable method - return targets affected by vulnerability"""

        # init local list
        response = []

        self.cur.execute('SELECT * FROM map_cpe_cve WHERE cve_id=?', self.query)

        for data in self.cur.fetchall():
            # set the CPE identifiers
            cpe22_id = data[0]
            cpe23_id = data[1]

            # set the title
            self.cur.execute("SELECT title FROM cpe_db where cpe_id = ?", (cpe22_id,))
            title = self.cur.fetchone()

            if title is not None:
                title = title[0]

            # format the response
            targets = {"title": title, "cpe2.2": cpe22_id, "cpe2.3": cpe23_id}
            response.append(targets)

        # set the tag
        response = {"targets": response}

        return utility.serialize_data(response)

    def get_weaknesses(self):
        """ callable method - return weaknesses affected by vulnerability"""

        # init local list
        response = []

        self.cur.execute('SELECT * FROM map_cwe_cve WHERE cve_id=?', self.query)

        for data in self.cur.fetchall():
            cwe_id = data[0]
            self.cur.execute("SELECT title,link,class,relations,capec_id FROM cwe_db WHERE cwe_id='%s' " % cwe_id)
            cwe_data = self.cur.fetchall()

            if cwe_data:
                title = cwe_data[0][0]
                url = cwe_data[0][1]
                cwe_class = cwe_data[0][2]
                relationship = cwe_data[0][3]
                capec = cwe_data[0][4]

                # format the response
                weaknesses = {"id": cwe_id,
                              "parameters": {"class": cwe_class, "title": title,
                                             "relationship": relationship, "url": url,
                                             "attack_patterns": self.enum_capec(capec),
                                             "ranking": {"category": self.enum_category(cwe_id),
                                                         "wasc": self.enum_wasc(cwe_id)}}}
                response.append(weaknesses)

        # set the tag
        response = {"weaknesses": response}

        return utility.serialize_data(response)

    def enum_category(self, cwe_id):
        """ return categories identifiers such Top 25 and OWASP Top etc .."""

        # init local list
        response = []

        self.cur.execute("SELECT cwe_id,title,link,relations FROM cwe_db where class = 'category' and relations like ?",
                         ('%' + cwe_id + '%',))

        for data in self.cur.fetchall():
            # setting category data
            category_id = data[0]
            title = data[1]
            url = data[2]
            relations = data[3].split(',')

            # listing only categories for the exact CWE id
            if cwe_id in relations:
                # format the response
                category = {"id": category_id, "parameters": {"title": title, "url": url}}
                response.append(category)

        return response

    def enum_wasc(self, cwe_id):
        """ return WASC identifiers from WASC database"""

        # init local list
        response = []

        self.cur.execute("SELECT wasc_id,title,link FROM wasc_db WHERE cwe_id='%s' " % cwe_id)

        for data in self.cur.fetchall():
            # setting wasc data
            wasc_id = data[0]
            title = data[1]
            url = data[2]

            # format the response
            wasc = {"id": wasc_id, "parameters": {"title": title, "url": url}}

            response.append(wasc)

        return response

    def enum_capec(self, capec):
        """ return extra CAPEC data from CAPEC database """

        # init local list
        response = []

        # Splitting identifiers as they are packed in the database
        capecs = capec.split(",")

        # calling CAPEC data
        for capec_id in capecs:
            self.cur.execute("SELECT title,link,attack_id FROM capec_db WHERE capec_id='%s' " % capec_id)
            for data in self.cur.fetchall():
                title = data[0]
                url = data[1]
                attack_methods = data[2]

                # format the response
                capec = {"id": capec_id, "parameters": {"title": title, "attack_methods": attack_methods, "url": url}}
                response.append(capec)

        return response
