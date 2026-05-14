#!/usr/bin/env python3
"""Azure Security Auditor - Command Line Interface"""
import asyncio
import argparse
import logging
import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent))

from auditor.core.azure_client import AzureClient
from auditor.core.engine import AuditEngine
from auditor.reports.json_report import JSONReport

# Import ALL available controls
from auditor.frameworks.cis_azure.storage_controls import (
    CIS_Azure_3_1_SecureTransferRequired,
    CIS_Azure_3_2_StorageEncryptionEnabled,
    CIS_Azure_3_3_PublicAccessDisabled,
    CIS_Azure_3_7_SoftDeleteEnabled,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Azure Security Auditor - CIS Azure Benchmark Scanner'
    )

    parser.add_argument('--subscription-id', help='Azure subscription ID')
    parser.add_argument('--tenant-id', help='Azure AD tenant ID')
    parser.add_argument('--client-id', help='Service principal client ID')
    parser.add_argument('--client-secret', help='Service principal secret')

    parser.add_argument('--controls', nargs='+', help='Specific control IDs')
    parser.add_argument('--services', nargs='+', help='Filter by services')
    parser.add_argument('--output', '-o', default='./reports', help='Output directory')
    parser.add_argument('--fail-on-findings', action='store_true', help='Exit with error on findings')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('--version', action='version', version='Azure Security Auditor 1.0.0')

    return parser.parse_args()


def load_controls(args) -> List:
    """Load security controls based on filters."""
    all_controls = [
        # CIS Azure Storage Controls (4 controls)
        CIS_Azure_3_1_SecureTransferRequired(),
        CIS_Azure_3_2_StorageEncryptionEnabled(),
        CIS_Azure_3_3_PublicAccessDisabled(),
        CIS_Azure_3_7_SoftDeleteEnabled(),
    ]

    # Filter by specific control IDs
    if args.controls:
        all_controls = [c for c in all_controls if c.control_id in args.controls]

    # Filter by services
    if args.services:
        all_controls = [c for c in all_controls if c.service in args.services]

    return all_controls


async def main():
    """Main entry point."""
    args = parse_arguments()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print("=" * 60)
    print("Azure Security Auditor")
    print("=" * 60)
    print()

    try:
        # Connect to Azure
        print("🔗 Connecting to Azure...")
        client = AzureClient(
            subscription_id=args.subscription_id,
            tenant_id=args.tenant_id,
            client_id=args.client_id,
            client_secret=args.client_secret
        )

        print(f"✅ Connected to subscription: {client.subscription_id}")
        print()

        # Load controls
        controls = load_controls(args)

        if not controls:
            print("❌ No controls matched your filters!")
            sys.exit(1)

        print(f"📋 Loaded {len(controls)} security controls")
        for control in controls:
            print(f"   - {control.control_id}: {control.title}")
        print()

        # Run audit
        print("🔍 Running security audit...")
        engine = AuditEngine(cloud_client=client, controls=controls, parallel=True)
        results = await engine.run_audit()

        # Display summary
        summary = results['summary']

        print()
        print("=" * 60)
        print("AUDIT SUMMARY")
        print("=" * 60)
        print(f"Subscription:      {client.subscription_id}")
        print(f"Total Findings:    {summary['total_findings']}")
        print(f"Passed:           {summary['passed']}")
        print(f"Failed:           {summary['failed']}")
        print(f"Warnings:         {summary['warnings']}")
        print(f"Errors:           {summary['errors']}")
        print(f"Compliance Rate:  {summary['compliance_rate']:.2f}%")
        print(f"Duration:         {summary['duration_seconds']:.2f}s")
        print("=" * 60)

        # Generate reports
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)

        print()
        json_path = output_dir / 'azure_audit.json'
        JSONReport(results).generate(str(json_path))
        print(f"📄 JSON report: {json_path}")

        # Show failed findings
        failed = [f for f in results['findings'] if f['status'] == 'FAIL']
        if failed:
            print()
            print("❌ Failed Controls:")
            for finding in failed[:10]:
                resource = finding.get('resource_id', 'N/A')
                print(f"   - {finding['control_id']}: {resource}")

        print()
        print("✅ Audit complete!")
        print()

        if args.fail_on_findings and summary['failed'] > 0:
            sys.exit(1)

        sys.exit(0)

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=args.verbose)
        print(f"\n❌ ERROR: {e}\n")
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())
