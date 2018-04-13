#!/usr/bin/env python3
# API Python wrapper for The Next Generation Vulnerability & Threat Intelligence Database  - https://vfeed.io
# Copyright (C) 2013 - 2018 vFeed IO

import json
from common import config as cfg


class APIversion(object):
    def __init__(self):
        self.title = json.dumps({'title': cfg.vfeed["title"]}, sort_keys=True, indent=2)
        self.build = json.dumps({'build': cfg.vfeed["build"]}, sort_keys=True, indent=2)
        self.email = json.dumps({'support': cfg.vfeed["email"]}, sort_keys=True, indent=2)

    def api_title(self):
        """ return API title """
        return self.title

    def api_build(self):
        """ return API build version """
        return self.build

    def api_support(self):
        """ return API main support contact  """
        return self.email

    def api_all_info(self):
        """ return all API info """

        all_info = json.loads(self.title)
        support = json.loads(self.email)
        build = json.loads(self.build)
        build.update(support)
        all_info.update(build)

        return json.dumps(all_info, indent=2)
