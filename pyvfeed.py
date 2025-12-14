#!/usr/bin/env python3
# API Python wrapper for The Vulnerability & Threat Intelligence Feed Service
# Copyright (C) 2013 - 2022 vFeed, Inc. - https://vfeed.io

import sys
import argparse
import importlib

sys.path.append("..")

try:
    from core.Risk import Risk
    from lib.Update import Update
    from lib.Search import Search
    from lib.Lang import Lang
    from core.Export import Export
    from core.Defense import Defense
    from lib.Version import APIversion
    from common import utils as utility
    from core.Inspection import Inspection
    from core.Information import Information
    from core.Exploitation import Exploitation
    from core.Classification import Classification
except ImportError as e:
    module = str(e).split("'")
    response = utility.serialize_error(False, module[1], module[0])
    sys.exit(response)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--version", help="API info", action="store_true", required=False)
    parser.add_argument("--update", help="Database update", action="store_true", required=False)
    parser.add_argument("--information", metavar="CVE, CPE", type=str, help="Get information data",
                        nargs=1)
    parser.add_argument("--classification", metavar="CVE, CPE", type=str, help="Get classification data",
                        nargs=1)
    parser.add_argument("--risk", metavar="CVE, CPE", type=str, help="Get risk data",
                        nargs=1)
    parser.add_argument("--inspection", metavar="CVE, CPE", type=str, help="Get Vulnerability testing data",
                        nargs=1)
    parser.add_argument("--exploitation", metavar="CVE, CPE", type=str, help="Get exploits and PoCs data",
                        nargs=1)
    parser.add_argument("--defense", metavar="CVE, CPE", type=str, help="Get detective, reactive & preventive data",
                        nargs=1)
    parser.add_argument("--search", metavar="cve|cpe|cwe", type=str,
                        help="Search for CVE, CPE2.2 | CPE2.3 or CWE",
                        nargs=2)
    parser.add_argument("--lang", metavar="cpp | python | javascript | golang", type=str,
                        help="List language vulnerabilities",
                        nargs=1)
    parser.add_argument("--export", metavar="CVE, CPE", type=str, help="Export all metadata to JSON file",
                        nargs=1)
    parser.add_argument("--plugin", metavar="Plugin name", type=str, help="Load third party plugins",
                        nargs=2)
    args = parser.parse_args()

    if args.version:
        ver = APIversion()
        print(ver.api_all_info())

    if args.update:
        update = Update()
        update.update()

    if args.information:
        id = args.information[0]
        print(Information(id).get_all())

    if args.classification:
        id = args.classification[0]
        from core.Classification import Classification
        #print(Classification(id).get_packages())
        print(Classification(id).get_all())

    if args.risk:
        id = args.risk[0]
        print(Risk(id).get_risk())

    if args.inspection:
        id = args.inspection[0]
        print(Inspection(id).get_all())

    if args.exploitation:
        id = args.exploitation[0]
        print(Exploitation(id).get_exploits())

    if args.defense:
        id = args.defense[0]
        print(Defense(id).get_all())

    if args.export:
        id = args.export[0]
        Export(id).dump_json()
        # Export(id).dump_yaml()

    if args.search:
        type = args.search[0]
        type = str.join('_', ("search", type))
        id = args.search[1]

        result = getattr(Search(id), type)
        print(result())

    # language vulns
    if args.lang:
        id = args.lang[0]
        print(Lang(id).search_lang())

    if args.plugin:
        plg_name = args.plugin[0]
        target = args.plugin[1]
        module = str.join('.', ('plugins', plg_name, 'api'))

        api_class = getattr(importlib.import_module(module), "api")
        api_class().test()

    if len(sys.argv) < 2:
        parser.print_help()
