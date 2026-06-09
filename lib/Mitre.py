#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2026 Zetafence vFeed Threat Intelligence - https://vfeed.io

from lib.Database import Database
from common import utils as utility


class Mitre(object):
    def __init__(self, id):
        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_mitre(self):
        """ return MITRE CWE weaknesses and ATT&CK techniques for a given CVE """

        self.cur.execute("SELECT cwe_id FROM map_cwe_cve WHERE cve_id=?", self.query)

        weaknesses = []
        for (cwe_id,) in self.cur.fetchall():
            self.cur.execute(
                "SELECT title, link, class, relations, capec_id FROM cwe_db WHERE cwe_id=?",
                (cwe_id,)
            )
            cwe_row = self.cur.fetchone()
            if not cwe_row:
                continue

            title, link, cwe_class, relations, capec = cwe_row
            weaknesses.append({
                "cwe_id": cwe_id,
                "title": title,
                "class": cwe_class,
                "url": link,
                "attack_techniques": self._enum_attack(capec),
            })

        return utility.serialize_data({"cve_id": self.id, "weaknesses": weaknesses})

    def _enum_attack(self, capec):
        """ resolve CAPEC ids to ATT&CK techniques via capec_db → attack_mitre_db """

        attack_ids = []
        for capec_id in capec.split(","):
            capec_id = capec_id.strip()
            if not capec_id:
                continue
            self.cur.execute(
                "SELECT attack_mitre_id FROM capec_db WHERE capec_id=?", (capec_id,)
            )
            row = self.cur.fetchone()
            if row:
                attack_ids.extend(x for x in row[0].split("|") if x)

        # deduplicate while preserving order
        seen = set()
        techniques = []
        for atk_id in attack_ids:
            if atk_id in seen:
                continue
            seen.add(atk_id)
            self.cur.execute("SELECT * FROM attack_mitre_db WHERE id=?", (atk_id,))
            for data in self.cur.fetchall():
                techniques.append({
                    "id":                   data[0],
                    "profile":              data[1],
                    "name":                 data[2],
                    "description":          data[3],
                    "tactic":               data[4],
                    "permission_required":  data[5],
                    "bypassed_defenses":    data[6],
                    "data_sources":         data[7],
                    "url":                  data[8],
                    "file":                 data[9],
                })
        return techniques
