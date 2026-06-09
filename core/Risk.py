#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2026 Zetafence vFeed Threat Intelligence - https://vfeed.io

import json

from lib.Database import Database
from common import utils as utility


class Risk(object):
    def __init__(self, id):
        """ init """
        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_kev_cisa(self):
        """ callable method - return CISA KEV Catalog"""
        # init
        response = {}

        # getting cvss data
        self.cur.execute('SELECT * FROM kev_cisa_db WHERE cve_id=?', self.query)
        self.datas = self.cur.fetchall()

        for data in self.datas:
            # setting cvss2 vectors
            self.kev_id = data[0]
            self.date_added = data[1]
            self.date_due = data[2]
            self.vuln_name = data[3]
            self.vendor = data[4]
            self.product = data[5]
            self.action = data[6]
            self.url = data[7]

            # format the response
            response = {"id": self.kev_id,
                        "parameters": {"date_added": self.date_added, "date_due": self.date_due,
                                       "name": self.vuln_name, "vendor": self.vendor,
                                       "product": self.product, "required_action": self.action,
                                       "url": self.url}}

        # adding the appropriate tag.
        response = {"kev": response}

        return utility.serialize_data(response)

    def get_epss(self):
        """ callable method - return EPSS scoring"""
        # init
        response = {}

        # getting cvss data
        self.cur.execute('SELECT * FROM epss_scoring WHERE cve_id=?', self.query)
        self.datas = self.cur.fetchall()

        for data in self.datas:
            # setting cvss2 vectors
            self.epss_probability = data[0]
            self.percentile_rank = data[1]

            response = {"probability": self.epss_probability, "percentile": self.percentile_rank}

        # adding the appropriate tag.
        response = {"epss": response}

        return utility.serialize_data(response)

    def get_cvss2(self):
        """ callable method - return  CVSS 2 score"""

        # init
        response = {}

        # getting cvss data
        self.cur.execute('SELECT * FROM cvss_scores WHERE cve_id=?', self.query)
        self.datas = self.cur.fetchall()

        for data in self.datas:
            # setting cvss2 vectors
            self.cvss2_base = data[0]
            self.cvss2_impact = data[1]
            self.cvss2_exploit = data[2]
            self.cvss2_vector = data[3]
            self.cvss2_access_vector = data[4]
            self.cvss2_access_complexity = data[5]
            self.cvss2_authentication = data[6]
            self.cvss2_conf_impact = data[7]
            self.cvss2_int_impact = data[8]
            self.cvss2_avail_impact = data[9]

            # formatting the response
            response = {"vector": self.cvss2_vector, "base_score": self.cvss2_base,
                        "impact_score": self.cvss2_impact,
                        "exploit_score": self.cvss2_exploit, "access_vector": self.cvss2_access_vector,
                        "access_complexity": self.cvss2_access_complexity,
                        "authentication": self.cvss2_authentication,
                        "confidentiality_impact": self.cvss2_conf_impact,
                        "integrity_impact": self.cvss2_int_impact, "availability_impact": self.cvss2_avail_impact}

        # adding the appropriate tag.
        response = {"cvss2": response}

        return utility.serialize_data(response)

    def get_cvss3(self):
        """ callable method - return CVSS 3 score"""

        # init
        response = {}

        # getting cvss data
        self.cur.execute('SELECT * FROM cvss_scores WHERE cve_id=?', self.query)
        self.datas = self.cur.fetchall()

        for data in self.datas:
            # setting cvss3 vectors
            self.cvss3_base = data[10]
            self.cvss3_impact = data[11]
            self.cvss3_exploit = data[12]
            self.cvss3_vector = data[13]
            self.cvss3_attack_vector = data[14]
            self.cvss3_attack_complexity = data[15]
            self.cvss3_privileges_required = data[16]
            self.cvss3_user_interaction = data[17]
            self.cvss3_scope = data[18]
            self.cvss3_conf_impact = data[19]
            self.cvss3_int_impact = data[20]
            self.cvss3_avail_impact = data[21]

            # formatting the response
            response = {"vector": self.cvss3_vector, "base_score": self.cvss3_base,
                        "impact_score": self.cvss3_impact,
                        "exploit_score": self.cvss3_exploit, "attack_vector": self.cvss3_attack_vector,
                        "attack_complexity": self.cvss3_attack_complexity,
                        "privileges_required": self.cvss3_privileges_required,
                        "user_interaction": self.cvss3_user_interaction, "score": self.cvss3_scope,
                        "confidentiality_impact": self.cvss3_conf_impact,
                        "integrity_impact": self.cvss3_int_impact, "availability_impact": self.cvss3_avail_impact}

        # adding the appropriate tag.
        response = {"cvss3": response}

        return utility.serialize_data(response)

    def get_cvss4(self):
        """ callable method - return CVSS 4 score """

        # init
        response = {}

        self.cur.execute('SELECT * FROM cvss4_scores WHERE cve_id=?', self.query)
        self.datas = self.cur.fetchall()

        for data in self.datas:
            response = {
                "vector":                               data[0],
                "base_score":                           data[1],
                "attack_vector":                        data[2],
                "attack_complexity":                    data[3],
                "attack_requirements":                  data[4],
                "privileges_required":                  data[5],
                "user_interaction":                     data[6],
                "vuln_confidentiality_impact":          data[7],
                "vuln_integrity_impact":                data[8],
                "vuln_availability_impact":             data[9],
                "sub_confidentiality_impact":           data[10],
                "sub_integrity_impact":                 data[11],
                "sub_availability_impact":              data[12],
                "exploit_maturity":                     data[13],
                "confidentiality_requirement":          data[14],
                "integrity_requirement":                data[15],
                "availability_requirement":             data[16],
                "modified_attack_vector":               data[17],
                "modified_attack_complexity":           data[18],
                "modified_attack_requirements":         data[19],
                "modified_privileges_required":         data[20],
                "modified_user_interaction":            data[21],
                "modified_vuln_confidentiality_impact": data[22],
                "modified_vuln_integrity_impact":       data[23],
                "modified_vuln_availability_impact":    data[24],
                "modified_sub_confidentiality_impact":  data[25],
                "modified_sub_integrity_impact":        data[26],
                "modified_sub_availability_impact":     data[27],
                "safety":                               data[28],
                "automatable":                          data[29],
                "recovery":                             data[30],
                "value_density":                        data[31],
                "vulnerability_response_effort":        data[32],
                "provider_urgency":                     data[33],
            }

        response = {"cvss4": response}

        return utility.serialize_data(response)

    def get_cvss(self):
        """ callable method - return CVSS 2, 3 and 4 scores"""

        cvss_2 = json.loads(self.get_cvss2())
        cvss_3 = json.loads(self.get_cvss3())
        cvss_4 = json.loads(self.get_cvss4())
        cvss_2.update(cvss_3)
        if cvss_4.get("cvss4"):
            cvss_2.update(cvss_4)

        # formatting the response
        response = {"cvss": cvss_2}

        return utility.serialize_data(response)

    def get_risk(self):
        """ callable method - return all risks"""
        response = json.loads(Risk(self.id).get_cvss())
        epss = json.loads(Risk(self.id).get_epss())
        kev_cisa = json.loads(Risk(self.id).get_kev_cisa())

        # formatting the response
        response.update(epss)
        response.update(kev_cisa)
        response = {"risk": response}

        return utility.serialize_data(response)
