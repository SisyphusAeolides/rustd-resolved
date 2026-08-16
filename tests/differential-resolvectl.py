#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import subprocess
import json
import sys
import difflib
from pathlib import Path

def run_cmd(cmd, env=None):
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        return res.returncode, res.stdout, res.stderr
    except Exception as e:
        return -1, "", str(e)

def diff_output(name, expected, actual):
    if expected == actual:
        return True
    
    print(f"--- {name} Differ ---")
    diff = difflib.unified_diff(
        expected.splitlines(keepends=True),
        actual.splitlines(keepends=True),
        fromfile='upstream',
        tofile='candidate',
    )
    sys.stdout.writelines(diff)
    return False

def compare(cmd_args, upstream_bin, candidate_bin):
    print(f"Running: {' '.join(cmd_args)}")
    
    up_code, up_out, up_err = run_cmd([upstream_bin] + cmd_args)
    cand_code, cand_out, cand_err = run_cmd([candidate_bin] + cmd_args)
    
    match = True
    if up_code != cand_code:
        print(f"Exit code mismatch: upstream={up_code}, candidate={cand_code}")
        match = False
        
    if "--json" in cmd_args or "-j" in cmd_args:
        try:
            up_json = json.loads(up_out) if up_out.strip() else None
            cand_json = json.loads(cand_out) if cand_out.strip() else None
            if up_json != cand_json:
                print("JSON mismatch")
                match = False
        except json.JSONDecodeError as e:
            print(f"JSON Parse error: {e}")
            match = False
    else:
        match &= diff_output("STDOUT", up_out, cand_out)
    
    match &= diff_output("STDERR", up_err, cand_err)
    
    return match

def main():
    parser = argparse.ArgumentParser(description="Differential testing for resolvectl")
    parser.add_argument("--upstream", default="resolvectl", help="Path to upstream resolvectl")
    parser.add_argument("--candidate", default="target/debug/resolvectl", help="Path to candidate resolvectl")
    parser.add_argument("cmd_args", nargs=argparse.REMAINDER, help="Arguments to pass to resolvectl")
    
    args = parser.parse_args()
    
    if not args.cmd_args:
        print("Please provide arguments to test")
        sys.exit(1)
        
    if not compare(args.cmd_args, args.upstream, args.candidate):
        sys.exit(1)
        
    print("MATCH")
    sys.exit(0)

if __name__ == "__main__":
    main()
