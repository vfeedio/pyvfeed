#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2026 Zetafence vFeed Threat Intelligence - https://vfeed.io


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


def _resolve_export_path():
    """Return cwd if writable, otherwise fall back to configured export path."""
    cwd = os.getcwd()
    if os.access(cwd, os.W_OK):
        return cwd
    return export_path


def create_json(response, file):
    """ create and move JSON file to the export repository"""

    out_dir = _resolve_export_path()
    dest_file = os.path.join(out_dir, file)
    with open(dest_file, "w") as output_file:
        json.dump(response, output_file, indent=2)

    return dest_file


def create_yaml(response, file):
    """ create and move YAML file to the export repository"""

    out_dir = _resolve_export_path()
    dest_file = os.path.join(out_dir, file)
    with open(dest_file, "w") as output_file:
        yaml.dump(response, output_file, default_flow_style=False, allow_unicode=True)

    return dest_file


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
