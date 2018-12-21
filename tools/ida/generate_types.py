#!/usr/bin/env python

import argparse
import fnmatch
import json
import os
import re

# Regex patterns
exp_ident = '[A-Za-z_][A-Za-z_0-9]+'
exp_type = '{ei}(?:[\t ]+{ei})*'.format(ei=exp_ident)

pattern_type = re.compile(
    'typedef\s+({et}[\s\*]+)({ei})'.format(
        et=exp_type, ei=exp_ident))
pattern_func = re.compile(
    '({et}[\s\*]+(sce[A-Z][A-Za-z0-9_]+)\s*\([A-Za-z0-9_\*,\s]*\)\s*);'.format(
        et=exp_type))
pattern_attr = re.compile(
    '(?:_SCE[0-9A-Z_]+|[0-9A-Z_]+_DECLARE|__inline__)')

def generate_types(path):
    types = {}
    # Scan for headers
    headers = []
    for root, dirnames, filenames in os.walk(path):
        for filename in fnmatch.filter(filenames, '*.h'):
            headers.append(os.path.join(root, filename))
    # Process headers
    for header in headers:
        print(header)
        with open(header, 'r', encoding='utf-8') as f:
            code = f.read()
        matches_type = re.findall(pattern_type, code)
        matches_func = re.findall(pattern_func, code)
        # Fix function declarations
        for mf in matches_func:
            func_key = mf[1]
            func_val = mf[0].strip()
            for mt in matches_type:
                type_key = mt[1]
                type_val = mt[0].strip()
                func_val = func_val.replace(type_key, type_val)
            func_val = re.sub(pattern_attr, '', func_val)
            func_val = re.sub(r'\s+', ' ', func_val)
            func_val = func_val.replace('( ', '(')
            func_val = func_val.replace(' )', ')')
            types[func_key] = func_val.strip()
    return types


### Main ###

def main():
    # Parse arguments
    parser = argparse.ArgumentParser()

    parser.add_argument("--db", type=str, help="path to json database (default: db_types.json)",
                        metavar="database", default="db_types.json")
    parser.add_argument("--update", type=str, help="behavior while updating database (default: keep)",
                        metavar="update", choices=["keep","overwrite"], default="keep")
    parser.add_argument("sdk", type=str, help="path to official/unofficial sdk",
                        metavar="sdk")
    args = parser.parse_args()
    # Generate types and merge into existing database, if any
    db = {}
    if os.path.exists(args.db):
        with open(args.db, 'r') as f:
            db = json.load(f)
    types = generate_types(args.sdk)
    for key, val in types.items():
        if args.update == 'overwrite' or key not in db:
            db[key] = val
    with open(args.db, 'w') as f:
        json.dump(db, f, indent=2, sort_keys=True)    

if __name__ == '__main__':
    main()
