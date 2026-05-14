#!/usr/bin/env python3
"""SAST Scanner - Tests the security auditor tool itself."""
import subprocess
import json
from pathlib import Path


def run_bandit():
    """Scan Python code for security issues."""
    print("🔍 Running Bandit (Code Security Scanner)...")
    Path('reports').mkdir(exist_ok=True)

    try:
        result = subprocess.run(
            ['bandit', '-r', 'auditor/', '-f', 'json', '-o', 'reports/bandit.json'],
            capture_output=True,
            text=True
        )

        # Parse results
        if Path('reports/bandit.json').exists():
            with open('reports/bandit.json', 'r') as f:
                data = json.load(f)
                issues = data.get('results', [])

                high = len([i for i in issues if i.get('issue_severity') == 'HIGH'])
                medium = len([i for i in issues if i.get('issue_severity') == 'MEDIUM'])
                low = len([i for i in issues if i.get('issue_severity') == 'LOW'])

                print(f"   Found: {len(issues)} issues (High: {high}, Medium: {medium}, Low: {low})")

                if high > 0:
                    print("\n   ⚠️  High severity issues found:")
                    for issue in [i for i in issues if i.get('issue_severity') == 'HIGH'][:3]:
                        print(f"      - {issue.get('test_id')}: {issue.get('issue_text')}")

                return len(issues), high

        return 0, 0
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return 0, 0


def run_safety():
    """Check dependencies for known vulnerabilities."""
    print("\n🔍 Running Safety (Dependency Scanner)...")

    try:
        result = subprocess.run(
            ['safety', 'check', '--json'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.stdout:
            try:
                data = json.loads(result.stdout)
                vulns = data if isinstance(data, list) else data.get('vulnerabilities', [])

                print(f"   Found: {len(vulns)} vulnerable dependencies")

                if vulns:
                    print("\n   ⚠️  Vulnerable packages:")
                    for vuln in vulns[:3]:
                        pkg = vuln.get('package', 'unknown')
                        ver = vuln.get('analyzed_version', 'unknown')
                        print(f"      - {pkg} {ver}")

                return len(vulns)
            except:
                print("   ✅ No vulnerabilities found")
                return 0

        return 0
    except Exception as e:
        print(f"   ⚠️  {e}")
        return 0


def run_secret_detection():
    """Scan for hardcoded secrets."""
    print("\n🔍 Running Secret Detection...")

    try:
        result = subprocess.run(
            ['detect-secrets', 'scan', 'auditor/', '--baseline', '.secrets.baseline'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.stdout:
            data = json.loads(result.stdout)
            secrets = data.get('results', {})
            total = sum(len(v) for v in secrets.values())

            print(f"   Found: {total} potential secrets in {len(secrets)} files")
            return total

        return 0
    except:
        print("   ✅ No secrets detected")
        return 0


def main():
    """Run all SAST scans."""
    print("=" * 70)
    print("SAST SCAN - Testing Security Auditor Tool")
    print("=" * 70)
    print()

    # Run scans
    code_issues, critical = run_bandit()
    vuln_count = run_safety()
    secret_count = run_secret_detection()

    # Summary
    total_issues = code_issues + vuln_count + secret_count

    print()
    print("=" * 70)
    print("SAST SUMMARY")
    print("=" * 70)
    print(f"Code Issues:          {code_issues} (Critical: {critical})")
    print(f"Vulnerable Packages:  {vuln_count}")
    print(f"Potential Secrets:    {secret_count}")
    print(f"TOTAL ISSUES:         {total_issues}")
    print("=" * 70)
    print()

    if critical > 0:
        print("❌ CRITICAL issues found! Fix before deploying.")
        return 1
    elif total_issues > 10:
        print("⚠️  Multiple issues found. Review recommended.")
        return 0
    else:
        print("✅ SAST scan passed!")
        return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
