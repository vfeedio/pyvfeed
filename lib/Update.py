#!/usr/bin/env python3
# API Python wrapper for The Next Generation Vulnerability & Threat Intelligence Database  - https://vfeed.io
# Copyright (C) 2013 - 2018 vFeed IO

import os
import sys
import shutil

from common import config as cfg
from common import utils as utility

try:
    import tarfile
    from boto3.session import Session
    from botocore.exceptions import ClientError
except ImportError as e:
    module = str(e).split("'")
    response = utility.serialize_error(False, module[1], module[0])
    sys.exit(response)


class Update(object):
    def __init__(self):

        # database init
        self.db = cfg.database["file"]
        self.path = cfg.database["path"]

        self.local_db = os.path.join(self.path, self.db)

        self.access_key = cfg.subscription["access_key"]
        self.secret_key = cfg.subscription["secret_key"]
        self.plan_license = cfg.subscription["plan"]

    def update(self):
        """ callable method - initiate the database update in accordance with plan validity """

        # init authorization
        files = self.authorization()

        try:
            for self.file in files:

                if "update" in self.file:
                    self.update_file = self.file
                else:
                    self.remote_db = self.file

            if not os.path.isfile(self.local_db):
                print("[+] Deploying new database ...")
                self.download(self.remote_db)
                self.unpack_database()

            else:
                print("[+] Checking update status ...")
                self.download(self.update_file)
                self.check_status(self.update_file)

        except Exception as e:
            response = utility.serialize_error(False, str(e), str(e))
            sys.exit(response)

    def check_status(self, file):
        """ check if new db is available"""

        # set the target file
        file = os.path.join(self.path, file)

        try:

            with open(file, 'r') as f:
                checksum_remote = f.read().strip()

                print("\t[-] Checksum verification", checksum_remote)

                if checksum_remote == utility.checksum(self.local_db):
                    print("\t[-] Already updated")
                    self.clean()

                else:
                    print("\t[-] Database update available")
                    self.download(self.remote_db)
                    self.unpack_database()

        except Exception as e:
            response = utility.serialize_error(False, str(e), str(e))
            sys.exit(response)

    def download(self, file):
        """ download files"""

        print("\t[-] Downloading", file)

        # set the target file
        self.target = os.path.join(self.path, file)

        try:
            self.bucket.download_file(file, self.target)

        except Exception as e:
            response = utility.serialize_error(False, str(e), str(e))
            sys.exit(response)

    def unpack_database(self):
        """ extract database """

        print("\t[-] Unpacking", self.target)

        try:
            tar = tarfile.open(self.target, 'r:gz')
            tar.extractall('.')
        except Exception as e:
            response = utility.serialize_error(False, str(e), str(e))
            sys.exit(response)

        shutil.move(self.db, self.local_db)
        self.clean()

    def authorization(self):
        """ check authorization """

        # init files dict
        files = []

        try:
            session = Session(aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key)
            s3 = session.resource('s3')
            self.bucket = s3.Bucket(self.plan_license)

            for file in self.bucket.objects.all():
                files.append(file.key)

        except Exception as e:

            if "Could not connect" in str(e):
                reason = "Connectivity error"
            else:
                code_error = e.response["Error"]["Code"]

                if code_error == "403":
                    reason = "Access suspended to: %s" % self.plan_license

                if code_error == "AccessDenied":
                    reason = "Access denied to plan: %s" % self.plan_license

                if code_error == "InvalidAccessKeyId":
                    reason = "Error on access key: %s" % self.access_key

                if code_error == "SignatureDoesNotMatch":
                    reason = "Error on secret key: %s" % self.secret_key

                if code_error == "AuthorizationHeaderMalformed":
                    reason = "Empty access key"

                if code_error == "NoSuchBucket":
                    reason = "Licensed plan not specified."

            response = utility.serialize_error(False, reason, str(e))
            sys.exit(response)

        return files

    def clean(self):
        """ clean directory"""
        print("[+] Cleaning tmp downloads ...")

        try:
            for file in os.listdir(self.path):
                if "tgz" in file or "update" in file:
                    os.remove(os.path.join(self.path, file))
                else:
                    pass

        except Exception as e:
            utility.serialize_error(False, "already cleaned", str(e))
