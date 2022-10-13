#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2022 vFeed, Inc. - https://vfeed.io


import os
import yaml
import json
import shutil
import hashlib

from common import config as cfg


def init():
    """ init test """

    global db_file
    global db_path
    global export_path

    db_file = cfg.database["file"]
    db_path = cfg.database["path"]
    export_path = cfg.export["path"]

    db = set_db_file()

    (response, reason) = check_file(db)
    return serialize_error(response, db, reason)


def set_db_file():
    """ set db file name"""

    return os.path.join(db_path, db_file)


def check_file(file):
    """ file test """

    if not (os.path.isfile(file) or os.access(file, os.R_OK)):
        reason = "permission denied or object not found"
        return False, reason
    if os.stat(file).st_size == 0:
        reason = "empty_size"
        return False, reason
    else:
        reason = "found"
        return True, reason


def create_json(response, file):
    """ create and move JSON file to the export repository"""

    output_file = open(file, "w")
    dest_file = os.path.join(export_path, file)
    json.dump(response, output_file, indent=2)

    if os.path.exists(dest_file):
        os.remove(dest_file)

    shutil.move(file, export_path)

    return


def create_yaml(response, file):
    """ create and move YAML file to the export repository"""

    output_file = open(file, "w")
    dest_file = os.path.join(export_path, file)
    yaml.dump(response, output_file, default_flow_style=False, allow_unicode=True)

    if os.path.exists(dest_file):
        os.remove(dest_file)

    shutil.move(file, export_path)

    return


def serialize_error(success, object, reason):
    """ serialiaze response as JSON """

    return json.dumps({"success": success, "object": object, "status": reason}, indent=2, sort_keys=True)


def serialize_data(response):
    """ return json data or null"""

    if len(response) != 0:
        return json.dumps(response, indent=2)
    else:
        return json.dumps(None, indent=2)


def checksum(file):
    """ return checksum with algorithm sha-256"""

    cksm = hashlib.sha256()
    f = open(file, 'rb')
    try:
        cksm.update(f.read())
    finally:
        f.close()
    return cksm.hexdigest()
