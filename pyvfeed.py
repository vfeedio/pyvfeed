#!/usr/bin/env python3
# Python CLI for vFeed Vulnerability and Threat Intelligence - Pro Edition
# Copyright (C) 2013 - 2026 Zetafence vFeed Threat Intelligence - https://vfeed.io

import os
import sys
import json
import sqlite3
import argparse
import importlib

sys.path.append("..")

RC_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".pyvfeedrc")
_VALID_SEARCH_TYPES = {"cve", "cpe", "cwe"}


# ---------------------------------------------------------------------------
# RC file helpers
# ---------------------------------------------------------------------------

def load_rc():
    """Read dbfile path from .pyvfeedrc; return None if absent or malformed."""
    try:
        with open(RC_FILE) as f:
            return json.load(f).get("dbfile")
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_rc(dbfile):
    """Persist dbfile path to .pyvfeedrc."""
    with open(RC_FILE, "w") as f:
        json.dump({"dbfile": dbfile}, f, indent=2)
    print(f"[+] DB file saved to {RC_FILE}: {dbfile}")


def apply_db_config(cfg, dbfile):
    """Override cfg.database with the resolved absolute path of dbfile."""
    path = os.path.abspath(dbfile)
    cfg.database["path"] = os.path.dirname(path)
    cfg.database["file"] = os.path.basename(path)


# ---------------------------------------------------------------------------
# Imports — utility first so it is available for error reporting
# ---------------------------------------------------------------------------

try:
    from common import utils as utility
except ImportError as e:
    sys.exit(f"Fatal: cannot import utility module: {e}")

try:
    from common import config as cfg
    from common import utils as utility
    from core.Risk import Risk
    from core.Export import Export
    from core.Defense import Defense
    from core.Inspection import Inspection
    from core.Information import Information
    from core.Exploitation import Exploitation
    from core.Classification import Classification
    from lib.Lang import Lang
    from lib.Pkgs import Pkgs
    from lib.Mitre import Mitre
    from lib.Search import Search
    from lib.Update import Update
    from lib.Advisory import Advisory
    from lib.Version import APIversion
    from lib.DemoUpdate import DemoUpdate
except ImportError as e:
    parts = str(e).split("'")
    sys.exit(utility.serialize_error(False, parts[1] if len(parts) > 1 else str(e), str(e)))


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="pyvfeed",
        description="Python CLI for vFeed Vulnerability and Threat Intelligence - Pro Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    db_grp = parser.add_argument_group("database")
    db_grp.add_argument("--db", metavar="FILE",
                        help="SQLite3 DB file to use (overrides config and .pyvfeedrc)")
    db_grp.add_argument("--set-dbfile", metavar="FILE",
                        help="Permanently save DB file path to .pyvfeedrc")
    db_grp.add_argument("--schema", action="store_true",
                        help="Print DB schema to stdout")
    db_grp.add_argument("--update", action="store_true",
                        help="Update the vFeed database")
    db_grp.add_argument("--download-demo-db", action="store_true",
                        help="Download demo vFeed DB")

    q_grp = parser.add_argument_group("vulnerability queries")
    q_grp.add_argument("--information", metavar="CVE|CPE",
                       help="Get information data")
    q_grp.add_argument("--classification", metavar="CVE|CPE",
                       help="Get classification data")
    q_grp.add_argument("--risk", metavar="CVE|CPE",
                       help="Get risk and CVSS data")
    q_grp.add_argument("--inspection", metavar="CVE|CPE",
                       help="Get vulnerability testing data")
    q_grp.add_argument("--exploitation", metavar="CVE|CPE",
                       help="Get exploits and PoCs")
    q_grp.add_argument("--defense", metavar="CVE|CPE",
                       help="Get detective, reactive and preventive data")
    q_grp.add_argument("--advisory", metavar="CVE",
                       help="Get top advisories for a CVE")
    q_grp.add_argument("--mitre", metavar="CVE",
                       help="Get MITRE CWE weaknesses and ATT&CK techniques")
    q_grp.add_argument("--export", metavar="CVE|CPE",
                       help="Export all metadata to a JSON file")

    s_grp = parser.add_argument_group("search")
    s_grp.add_argument("--search", metavar=("TYPE", "ID"), nargs=2,
                       help=f"Search by type ({', '.join(sorted(_VALID_SEARCH_TYPES))}) and identifier")
    s_grp.add_argument("--lang", metavar="LANGUAGE",
                       help="List CVEs for a language (cpp, python, javascript, golang, java)")
    s_grp.add_argument("--pkgs", metavar="PACKAGE", nargs="+",
                       help="List CVEs for a package and optional version")

    misc_grp = parser.add_argument_group("miscellaneous")
    misc_grp.add_argument("--version", action="store_true",
                          help="Show version and build info")
    misc_grp.add_argument("--plugin", metavar=("NAME", "TARGET"), nargs=2,
                          help="Load and run a third-party plugin")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # config-only operation — exit immediately after writing
    if args.set_dbfile:
        save_rc(os.path.abspath(args.set_dbfile))
        sys.exit(0)

    # DB resolution order: config.py < .pyvfeedrc < --db
    rc_dbfile = load_rc()
    if rc_dbfile:
        apply_db_config(cfg, rc_dbfile)
    if args.db:
        apply_db_config(cfg, args.db)

    if args.version:
        print(APIversion().api_all_info())

    if args.update:
        Update().update()

    if args.download_demo_db:
        DemoUpdate().download_demo()

    if args.schema:
        db_path = os.path.join(cfg.database["path"], cfg.database["file"])
        try:
            conn = sqlite3.connect(db_path)
            rows = conn.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name"
            ).fetchall()
            conn.close()
            print("\n\n".join(row[0] for row in rows))
        except sqlite3.OperationalError as e:
            sys.exit(utility.serialize_error(False, db_path, str(e)))

    if args.information:
        print(Information(args.information).get_all())

    if args.classification:
        print(Classification(args.classification).get_all())

    if args.risk:
        print(Risk(args.risk).get_risk())

    if args.inspection:
        print(Inspection(args.inspection).get_all())

    if args.exploitation:
        print(Exploitation(args.exploitation).get_exploits())

    if args.defense:
        print(Defense(args.defense).get_all())

    if args.advisory:
        print(Advisory(args.advisory).get_advisory())

    if args.mitre:
        print(Mitre(args.mitre).get_mitre())

    if args.export:
        Export(args.export).dump_json()

    if args.search:
        search_type, search_id = args.search
        if search_type not in _VALID_SEARCH_TYPES:
            sys.exit(utility.serialize_error(
                False, search_type,
                f"Invalid search type '{search_type}'. Valid: {', '.join(sorted(_VALID_SEARCH_TYPES))}"
            ))
        print(getattr(Search(search_id), f"search_{search_type}")())

    if args.lang:
        print(Lang(args.lang).search_lang())

    if args.pkgs:
        print(Pkgs(args.pkgs[0]).search_pkgs())

    if args.plugin:
        plugin_name, target = args.plugin
        try:
            api_class = getattr(importlib.import_module(f"plugins.{plugin_name}.api"), "api")
            api_class().test()
        except (ImportError, AttributeError) as e:
            sys.exit(utility.serialize_error(False, plugin_name, str(e)))


if __name__ == "__main__":
    main()
