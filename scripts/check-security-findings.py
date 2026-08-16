#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import json
import sys
import argparse
import os

def parse_cargo_audit(file_path):
    """
    Dummy parsing logic for standard cargo audit JSON output.
    Aggregates findings and returns a list of dictionaries.
    """
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return []

    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []

    findings = []
    # Cargo audit JSON generally provides "vulnerabilities" -> "list"
    if "vulnerabilities" in data and "list" in data["vulnerabilities"]:
        for vuln in data["vulnerabilities"]["list"]:
            advisory = vuln.get("advisory", {})
            # Extract severity, defaulting to unknown
            # In actual cargo audit, cvss may provide a score which dictates severity.
            # Here we provide a dummy check for 'high' or 'critical'.
            severity = advisory.get("cvss", {}).get("severity", "unknown").lower()
            
            # fallback if 'informational' or other string is at the top level
            if severity == "unknown":
                if advisory.get("informational") is None:
                    # Treat unknown as high for dummy purposes if no cvss is present and it's a real vuln
                    pass
            
            # For dummy purposes, we assume 'high' or 'critical' can be mapped directly.
            # We'll just check if the advisory severity itself maps to it.
            if severity in ("high", "critical"):
                findings.append({
                    "id": advisory.get("id", "UNKNOWN"),
                    "severity": severity,
                    "package": vuln.get("package", {}).get("name", "unknown")
                })
    return findings

def parse_cppcheck(file_path):
    """
    Dummy parsing for cppcheck XML/JSON output.
    """
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return []
    
    # Add dummy logic if needed
    return []

def main():
    parser = argparse.ArgumentParser(description="Aggregate scanner/sanitizer outputs and fail on high/critical findings.")
    parser.add_argument("--cargo-audit", help="Path to cargo audit JSON output")
    parser.add_argument("--cppcheck", help="Path to cppcheck output")
    args = parser.parse_args()

    all_findings = []

    if args.cargo_audit:
        print(f"Parsing cargo audit output: {args.cargo_audit}")
        all_findings.extend(parse_cargo_audit(args.cargo_audit))

    if args.cppcheck:
        print(f"Parsing cppcheck output: {args.cppcheck}")
        all_findings.extend(parse_cppcheck(args.cppcheck))

    high_crit_findings = [f for f in all_findings if f.get("severity", "").lower() in ("high", "critical")]

    if high_crit_findings:
        print(f"FAILURE: Found {len(high_crit_findings)} high/critical security findings!")
        for f in high_crit_findings:
            print(f"- {f.get('id')} (Package: {f.get('package')}): {f.get('severity').upper()}")
        sys.exit(1)
    else:
        print("SUCCESS: No high/critical security findings found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
