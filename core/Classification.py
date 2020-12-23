#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2020 vFeed, Inc. - https://vfeed.io

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
        packages = json.loads(self.get_packages(), object_pairs_hook=OrderedDict)
        weaknesses = json.loads(self.get_weaknesses(), object_pairs_hook=OrderedDict)

        targets.update(packages)
        targets.update(weaknesses)

        # format the response
        response = {"classification": targets}

        return utility.serialize_data(response)

    def get_packages(self):
        """ callable method - return affected packages & libraries (vendor, product, version) by vulnerability"""

        # init local list
        response = []

        self.cur.execute("SELECT vendor FROM packages_db WHERE cve_id=? GROUP BY vendor", self.query)

        for vendor in self.cur.fetchall():
            vendor = vendor[0].strip()
            data = self.enum_packages(vendor)

            # get only responses with valid data.
            if data:
                # format the response
                tag = {vendor: data}
                response.append(tag)

        # set tag
        response = {"packages": response}

        return utility.serialize_data(response)

    def get_targets(self):
        """ callable method - return targets affected by vulnerability"""

        # init local list
        response = []

        self.cur.execute(
            "SELECT configuration FROM map_cpe_cve where cve_id=? GROUP BY configuration order by configuration",
            self.query)

        for configs in self.cur.fetchall():
            self.cur.execute('''SELECT * FROM map_cpe_cve WHERE configuration="%s" and cve_id="%s"  ''' % (
                configs[0], self.query[0]))

            data = self.cur.fetchall()
            config_id = data[0][0]

            tag = {"id": config_id, "parameters": self.enum_cpe(data)}
            response.append(tag)

        # set tag
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
                                             "ranking": {"categorization": self.enum_category(cwe_id),
                                                         "wasc": self.enum_wasc(cwe_id),
                                                         "mitre_attack": self.enum_attack_mitre(capec)}}}
                response.append(weaknesses)

        # set the tag
        response = {"weaknesses": response}

        return utility.serialize_data(response)

    def enum_cpe(self, data):
        """ return CPEs identifiers"""

        # init local list
        response = []
        response_2 = []
        running_on = False

        for config in data:
            # extract the configuration data
            cpe22_id = config[1]
            cpe23_id = config[2]
            start_version = config[3]
            end_version = config[4]
            running = config[5]

            # set the title
            self.cur.execute("SELECT title FROM cpe_db where cpe_id = ?", (cpe22_id,))
            title = self.cur.fetchone()

            if title is not None:
                title = title[0]

            # format the response (general case)
            if running != "running_on_with":
                # format the response
                targets = {"title": title, "cpe2.2": cpe22_id, "cpe2.3": cpe23_id,
                           "version_affected": {"from": start_version, "to": end_version}}
                response.append(targets)

            # format the response (case running_on_with)
            if running == "running_on_with":
                running_on = True
                # format the response
                targets_on = {"title": title, "cpe2.2": cpe22_id, "cpe2.3": cpe23_id}
                response_2.append(targets_on)

        # merging the responses (whenever running_on_with is enabled)
        if running_on:
            targets = {"running_on": response_2}
            response.append(targets)

        return response

    def enum_category(self, cwe_id):
        """ return categories identifiers such Top 25 and OWASP Top etc .."""

        # init local list
        response = []

        # query the database
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
            self.cur.execute(
                "SELECT title,link,attack_method, mitigations FROM capec_db WHERE capec_id='%s' " % capec_id)
            for data in self.cur.fetchall():
                title = data[0]
                url = data[1]
                attack_methods = data[2]
                mitigations = data[3]

                # format the response
                capec = {"id": capec_id,
                         "parameters": {"title": title, "attack_methods": attack_methods, "mitigations": mitigations,
                                        "url": url}}
                response.append(capec)

        return response

    def enum_attack_mitre(self, capec):
        """ return extra Att&ck Mitre  """

        # init local list
        response = []
        attack_list = []

        # Splitting identifiers as they are packed in the database
        capecs = capec.split(",")

        # calling CAPEC data
        for capec_id in capecs:
            self.cur.execute("SELECT attack_mitre_id FROM capec_db WHERE capec_id='%s' " % capec_id)
            id = self.cur.fetchone()
            if id:
                id = id[0].split('|')
                [x for x in id if x != '' and attack_list.append(x)]

        # setting a clean list of ATT&CK identifiers
        attack_list = list(dict.fromkeys(attack_list))

        # generating the data
        for item in attack_list:
            self.cur.execute("SELECT * FROM attack_mitre_db WHERE id='%s' " % item)
            for data in self.cur.fetchall():
                attack_id = data[0]
                profile = data[1]
                name = data[2]
                description = data[3]
                tactic = data[4]
                permission_required = data[5]
                bypassed_defense = data[6]
                data_sources = data[7]
                url = data[8]
                file = data[9]

                # format the response
                attack_mitre = {"id": attack_id,
                                "parameters": {"profile": profile, "name": name, "description": description,
                                               "tactic": tactic, "permission_required": permission_required,
                                               "bypassed_defenses": bypassed_defense, "data_sources": data_sources,
                                               "url": url, "file": file}}
                response.append(attack_mitre)

        return response

    def enum_packages(self, vendor):
        """ list relevant packages """

        # init local list
        response = []

        self.cur.execute('''SELECT product FROM packages_db WHERE vendor="%s" and cve_id="%s" group by product''' % (
            vendor, self.query[0]))

        for product in self.cur.fetchall():
            product = product[0].strip()

            if product:
                self.cur.execute(
                    '''SELECT DISTINCT version_affected, affected_condition FROM packages_db WHERE product="%s" and 
                    cve_id="%s" ''' % (product, self.query[0]))

                datas = self.cur.fetchall()

                # craft packaging for every loop
                packaging = []

                for data in datas:
                    version_affected = data[0]
                    affected_condition = data[1]

                    # format the versions affected / conditions response
                    versions = {"affected": version_affected, "condition": affected_condition}
                    packaging.append(versions)

                # set the response tag for packages
                tag = {product: packaging}
                response.append(tag)

        return response