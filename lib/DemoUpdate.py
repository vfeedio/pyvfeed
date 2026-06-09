#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2026 Zetafence vFeed Threat Intelligence - https://vfeed.io

import os
import sys
import shutil
import base64

from common import config as cfg
from common import utils as utility

try:
    import tarfile
    import urllib.request
    import urllib.error
except ImportError as e:
    module = str(e).split("'")
    response = utility.serialize_error(False, module[1], module[0])
    sys.exit(response)

def _d(s):
    return base64.b64decode(s).decode()

DEMO_CDN_BASE    = _d("aHR0cHM6Ly9kMnF3MXk1cGlib2Y2Yy5jbG91ZGZyb250Lm5ldA==")
DEMO_DB_KEY      = _d("dmZlZWQuZGIudGd6")
DEMO_UPDATE_KEY  = _d("dXBkYXRl")

class DemoUpdate(object):
    def __init__(self):
        self.db = cfg.database["file"]
        self.path = cfg.database["path"]
        self.local_db = os.path.join(self.path, self.db)
        self.target = os.path.join(self.path, DEMO_DB_KEY)

    def download_demo(self):
        """ download demo vFeed DB """

        print("[+] Checking demo DB update status ...")

        remote_sha = self.fetch_remote_sha()
        if remote_sha is None:
            return

        print(f"\t[-] Remote checksum: {remote_sha}")

        if os.path.isfile(self.local_db) and remote_sha == utility.checksum(self.local_db):
            print("\t[-] Already up to date.")
            return

        print(f"\t[-] Downloading demo DB '{DEMO_DB_KEY}' ...")
        try:
            urllib.request.urlretrieve(f"{DEMO_CDN_BASE}/{DEMO_DB_KEY}", self.target)
        except urllib.error.HTTPError as e:
            response = utility.serialize_error(False, str(e), f"HTTP {e.code}: {e.reason}")
            sys.exit(response)
        except urllib.error.URLError as e:
            response = utility.serialize_error(False, str(e), str(e.reason))
            sys.exit(response)

        self.unpack_database()

    def fetch_remote_sha(self):
        """ fetch SHA from remote update file; returns None on failure """

        url = f"{DEMO_CDN_BASE}/{DEMO_UPDATE_KEY}"
        print(f"\t[-] Fetching remote checksum from '{url}' ...")

        try:
            with urllib.request.urlopen(url) as resp:
                return resp.read().decode().strip()
        except urllib.error.HTTPError as e:
            response = utility.serialize_error(False, str(e), f"HTTP {e.code}: {e.reason}")
            sys.exit(response)
        except urllib.error.URLError as e:
            response = utility.serialize_error(False, str(e), str(e.reason))
            sys.exit(response)

    def unpack_database(self):
        """ extract downloaded demo DB archive """

        print(f"\t[-] Unpacking {self.target} ...")

        try:
            tar = tarfile.open(self.target, "r:gz")
            tar.extractall(".")
        except Exception as e:
            response = utility.serialize_error(False, str(e), str(e))
            sys.exit(response)

        shutil.move(self.db, self.local_db)
        self.clean()

    def clean(self):
        """ remove downloaded archive """
        print("[+] Cleaning tmp downloads ...")

        try:
            if os.path.exists(self.target):
                os.remove(self.target)
        except Exception as e:
            utility.serialize_error(False, "already cleaned", str(e))
