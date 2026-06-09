#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2026 Zetafence vFeed Threat Intelligence - https://vfeed.io

from lib.Database import Database
from common import utils as utility

ADVISORY_LIMIT = 10


class Advisory(object):
    def __init__(self, id):
        self.id = id
        (self.cur, self.query) = Database(self.id).db_init()

    def get_advisory(self):
        """ return top ADVISORY_LIMIT advisories from advisory_db for a given CVE """

        self.cur.execute(
            "SELECT type, source, id, link FROM advisory_db WHERE cve_id = ? LIMIT ?",
            (self.id, ADVISORY_LIMIT)
        )

        responses = []
        for data in self.cur.fetchall():
            responses.append({
                "type":   data[0],
                "source": data[1],
                "id":     data[2],
                "link":   data[3],
            })
        return utility.serialize_data(responses)
