#!/usr/bin/env python3
"""
AWS Security Compliance Auditor
Supports: CIS AWS Foundations, SOC1, SOC2
"""

import json
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
import logging
import argparse
import csv

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class AWSAuditResult:
    control_id: str
    framework: str
    control_name: str
    description: str
    status: str
    resource_id: str
    resource_type: str
    finding: str
    severity: str
    timestamp: str
    remediation: str = ""
    remediation_code: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


class AWSSecurityAuditor:
    def __init__(self, controls_file: str, aws_profile: str = None):
        self.controls_file = Path(controls_file)
        self.controls = []
        self.results: List[AWSAuditResult] = []

        session_kwargs = {}
        if aws_profile:
            session_kwargs['profile_name'] = aws_profile

        self.session = boto3.Session(**session_kwargs)

        try:
            self.account_id = self.session.client('sts').get_caller_identity()['Account']
            logger.info(f"Connected to AWS Account: {self.account_id}")
        except Exception as e:
            logger.error(f"Failed to connect to AWS: {e}")
            raise

    def load_controls(self) -> None:
        try:
            with open(self.controls_file) as f:
                data = json.load(f)
                self.controls = data.get('controls', [])
            logger.info(f"Loaded {len(self.controls)} controls from {self.controls_file}")
        except FileNotFoundError:
            logger.error(f"Controls file not found: {self.controls_file}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in controls file: {e}")
            raise

    def execute_check(self, control: Dict) -> List[AWSAuditResult]:
        check_type = control.get('check_type')

        if check_type == 'iam_password_policy':
            return self.check_iam_password_policy(control)
        elif check_type == 'iam_mfa_enabled':
            return self.check_iam_mfa(control)
        elif check_type == 'iam_root_access_keys':
            return self.check_iam_root_access_keys(control)
        elif check_type == 'iam_root_mfa':
            return self.check_iam_root_mfa(control)
        elif check_type == 'iam_unused_credentials':
            return self.check_iam_unused_credentials(control)
        elif check_type == 's3_bucket_public':
            return self.check_s3_public_access(control)
        elif check_type == 's3_enforce_ssl':
            return self.check_s3_enforce_ssl(control)
        elif check_type == 'cloudtrail_enabled':
            return self.check_cloudtrail(control)
        elif check_type == 'ec2_security_group':
            return self.check_security_groups(control)
        elif check_type == 'rds_encryption':
            return self.check_rds_encryption(control)
        else:
            return [self.create_error_result(control, f"Unknown check type: {check_type}")]

    def check_iam_password_policy(self, control: Dict) -> List[AWSAuditResult]:
        """Check IAM password policy configuration"""
        try:
            iam = self.session.client('iam')
            policy = iam.get_account_password_policy()['PasswordPolicy']

            min_length = policy.get('MinimumPasswordLength', 0)
            expected_length = control.get('expected_value', 14)
            passed = min_length >= expected_length

            return [AWSAuditResult(
                control_id=control['id'],
                framework=control['framework'],
                control_name=control['name'],
                description=control['description'],
                status='PASS' if passed else 'FAIL',
                resource_id=f"arn:aws:iam::{self.account_id}:account-password-policy",
                resource_type='IAM Password Policy',
                finding=f"Minimum length is {min_length} (expected >= {expected_length})",
                severity=control['severity'],
                timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                remediation=control.get('remediation', ''),
                remediation_code=control.get('remediation_code', '')
            )]

        # FIX: Use ClientError instead of iam.exceptions.NoSuchEntityException
        # (the latter fails when iam is a MagicMock in tests)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return [self.create_fail_result(
                    control, "N/A", "IAM Password Policy", "No password policy configured"
                )]
            return [self.create_error_result(control, str(e))]
        except Exception as e:
            return [self.create_error_result(control, str(e))]

    def check_iam_mfa(self, control: Dict) -> List[AWSAuditResult]:
        results = []
        try:
            iam = self.session.client('iam')
            users = iam.list_users()['Users']

            if not users:
                return [self.create_fail_result(control, "N/A", "IAM Users", "No IAM users found")]

            for user in users:
                username = user['UserName']
                mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                passed = len(mfa_devices) > 0

                results.append(AWSAuditResult(
                    control_id=control['id'],
                    framework=control['framework'],
                    control_name=control['name'],
                    description=f"Check MFA for user: {username}",
                    status='PASS' if passed else 'FAIL',
                    resource_id=user['Arn'],
                    resource_type='IAM User',
                    finding=f"MFA {'enabled' if passed else 'NOT enabled'}",
                    severity=control['severity'],
                    timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    remediation=self.safe_format(control.get('remediation', ''), username=username),
                    remediation_code=self.safe_format(control.get('remediation_code', ''), username=username)
                ))

            return results

        except Exception as e:
            return [self.create_error_result(control, str(e))]

    def check_iam_root_access_keys(self, control: Dict) -> List[AWSAuditResult]:
        try:
            iam = self.session.client('iam')
            summary = iam.get_account_summary()['SummaryMap']
            root_keys = summary.get('AccountAccessKeysPresent', 0)
            passed = root_keys == 0

            return [AWSAuditResult(
                control_id=control['id'],
                framework=control['framework'],
                control_name=control['name'],
                description=control['description'],
                status='PASS' if passed else 'FAIL',
                resource_id=f"arn:aws:iam::{self.account_id}:root",
                resource_type='Root Account',
                finding=f"Root access keys: {'None' if passed else 'EXIST (delete them!)'}",
                severity=control['severity'],
                timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                remediation=control.get('remediation', ''),
                remediation_code=control.get('remediation_code', '')
            )]

        except Exception as e:
            return [self.create_error_result(control, str(e))]

    def check_iam_root_mfa(self, control: Dict) -> List[AWSAuditResult]:
        try:
            iam = self.session.client('iam')
            summary = iam.get_account_summary()['SummaryMap']
            root_mfa = summary.get('AccountMFAEnabled', 0)
            passed = root_mfa == 1

            return [AWSAuditResult(
                control_id=control['id'],
                framework=control['framework'],
                control_name=control['name'],
                description=control['description'],
                status='PASS' if passed else 'FAIL',
                resource_id=f"arn:aws:iam::{self.account_id}:root",
                resource_type='Root Account',
                finding=f"Root MFA: {'Enabled' if passed else 'NOT enabled'}",
                severity=control['severity'],
                timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                remediation=control.get('remediation', ''),
                remediation_code=control.get('remediation_code', '')
            )]

        except Exception as e:
            return [self.create_error_result(control, str(e))]

    def check_iam_unused_credentials(self, control: Dict) -> List[AWSAuditResult]:
        results = []
        max_age_days = control.get('expected_value', 90)

        try:
            iam = self.session.client('iam')
            users = iam.list_users()['Users']

            for user in users:
                username = user['UserName']

                try:
                    iam.get_login_profile(UserName=username)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchEntity':
                        pass

                access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']

                for key in access_keys:
                    key_id = key['AccessKeyId']
                    created = key['CreateDate']
                    age_days = (datetime.now(timezone.utc) - created).days

                    try:
                        last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
                        last_used_date = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                        days_since_use = (datetime.now(timezone.utc) - last_used_date).days if last_used_date else age_days
                        passed = days_since_use < max_age_days

                        results.append(AWSAuditResult(
                            control_id=control['id'],
                            framework=control['framework'],
                            control_name=control['name'],
                            description=f"Check unused credentials for {username}",
                            status='PASS' if passed else 'FAIL',
                            resource_id=f"arn:aws:iam::{self.account_id}:user/{username}",
                            resource_type='IAM Access Key',
                            finding=f"Key {key_id[-6:]}: Last used {days_since_use} days ago",
                            severity=control['severity'],
                            timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                            remediation=self.safe_format(control.get('remediation', ''), username=username, key_id=key_id),
                            remediation_code=self.safe_format(control.get('remediation_code', ''), username=username, key_id=key_id)
                        ))
                    except Exception:
                        pass

            return results if results else [self.create_error_result(control, "No access keys found")]

        except Exception as e:
            return [self.create_error_result(control, str(e))]

    def check_s3_public_access(self, control: Dict) -> List[AWSAuditResult]:
        """Check for publicly accessible S3 buckets"""
        results = []

        try:
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()['Buckets']

            if not buckets:
                return [self.create_fail_result(control, "N/A", "S3 Buckets", "No S3 buckets found")]

            for bucket in buckets:
                bucket_name = bucket['Name']

                try:
                    public_block = s3.get_public_access_block(Bucket=bucket_name)
                    config = public_block['PublicAccessBlockConfiguration']

                    is_blocked = (
                        config.get('BlockPublicAcls', False) and
                        config.get('BlockPublicPolicy', False) and
                        config.get('IgnorePublicAcls', False) and
                        config.get('RestrictPublicBuckets', False)
                    )

                    results.append(AWSAuditResult(
                        control_id=control['id'],
                        framework=control['framework'],
                        control_name=control['name'],
                        description=f"Check public access for: {bucket_name}",
                        status='PASS' if is_blocked else 'FAIL',
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_type='S3 Bucket',
                        finding=f"Public access {'blocked' if is_blocked else 'NOT blocked'}",
                        severity=control['severity'],
                        timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                        remediation=self.safe_format(control.get('remediation', ''), bucket=bucket_name),
                        remediation_code=self.safe_format(control.get('remediation_code', ''), bucket=bucket_name)
                    ))

                # FIX: Removed the broken try/except/else — the else clause was running
                # when no exception occurred but referenced undefined variable 'error_code',
                # causing a NameError that was swallowed by the outer except as ERROR.
                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'NoSuchPublicAccessBlockConfiguration':
                        results.append(self.create_fail_result(
                            control,
                            f"arn:aws:s3:::{bucket_name}",
                            "S3 Bucket",
                            "No public access block configured"
                        ))
                    else:
                        logger.warning(f"Could not check bucket {bucket_name}: {error_code}")
                except Exception as e:
                    logger.warning(f"Could not check bucket {bucket_name}: {e}")

            return results if results else [self.create_error_result(control, "No S3 buckets to check")]

        except Exception as e:
            return [self.create_error_result(control, str(e))]

    def check_s3_enforce_ssl(self, control: Dict) -> List[AWSAuditResult]:
        results = []

        try:
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()['Buckets']

            for bucket in buckets:
                bucket_name = bucket['Name']

                try:
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    policy_text = policy['Policy']
                    has_ssl_enforcement = 'aws:SecureTransport' in policy_text and 'Deny' in policy_text

                    results.append(AWSAuditResult(
                        control_id=control['id'],
                        framework=control['framework'],
                        control_name=control['name'],
                        description=f"Check SSL enforcement for: {bucket_name}",
                        status='PASS' if has_ssl_enforcement else 'FAIL',
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_type='S3 Bucket',
                        finding=f"SSL enforcement: {'Yes' if has_ssl_enforcement else 'No'}",
                        severity=control['severity'],
                        timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                        remediation=self.safe_format(control.get('remediation', ''), bucket=bucket_name),
                        remediation_code=self.safe_format(control.get('remediation_code', ''), bucket=bucket_name)
                    ))

                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'NoSuchBucketPolicy':
                        results.append(self.create_fail_result(
                            control,
                            f"arn:aws:s3:::{bucket_name}",
                            "S3 Bucket",
                            "No bucket policy (SSL not enforced)"
                        ))
                    else:
                        logger.warning(f"Could not check SSL for bucket {bucket_name}: {error_code}")

            return results if results else [self.create_error_result(control, "No S3 buckets to check")]

        except Exception as e:
            return [self.create_error_result(control, str(e))]

    def check_cloudtrail(self, control: Dict) -> List[AWSAuditResult]:
        try:
            cloudtrail = self.session.client('cloudtrail')
            trails = cloudtrail.describe_trails()['trailList']

            if not trails:
                return [self.create_fail_result(control, "N/A", "CloudTrail", "No CloudTrail trails configured")]

            results = []
            for trail in trails:
                trail_name = trail['Name']
                trail_arn = trail['TrailARN']
                is_multi_region = trail.get('IsMultiRegionTrail', False)

                try:
                    status = cloudtrail.get_trail_status(Name=trail_name)
                    is_logging = status.get('IsLogging', False)

                    results.append(AWSAuditResult(
                        control_id=control['id'],
                        framework=control['framework'],
                        control_name=control['name'],
                        description=f"Check CloudTrail: {trail_name}",
                        status='PASS' if (is_logging and is_multi_region) else 'FAIL',
                        resource_id=trail_arn,
                        resource_type='CloudTrail',
                        finding=f"Logging: {is_logging}, Multi-region: {is_multi_region}",
                        severity=control['severity'],
                        timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                        remediation=control.get('remediation', ''),
                        remediation_code=control.get('remediation_code', '')
                    ))
                except Exception as e:
                    logger.warning(f"Could not get status for trail {trail_name}: {e}")

            return results

        except Exception as e:
            return [self.create_error_result(control, str(e))]

    def check_security_groups(self, control: Dict) -> List[AWSAuditResult]:
        results = []
        port = control.get('port', 22)
        cidr = control.get('cidr', '0.0.0.0/0')

        try:
            ec2 = self.session.client('ec2')
            security_groups = ec2.describe_security_groups()['SecurityGroups']

            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']

                for permission in sg.get('IpPermissions', []):
                    from_port = permission.get('FromPort')
                    to_port = permission.get('ToPort')

                    if from_port and to_port and from_port <= port <= to_port:
                        for ip_range in permission.get('IpRanges', []):
                            if ip_range.get('CidrIp') == cidr:
                                results.append(AWSAuditResult(
                                    control_id=control['id'],
                                    framework=control['framework'],
                                    control_name=control['name'],
                                    description=f"Security group {sg_name} allows {cidr} on port {port}",
                                    status='FAIL',
                                    resource_id=f"arn:aws:ec2:{self.session.region_name}:{self.account_id}:security-group/{sg_id}",
                                    resource_type='Security Group',
                                    finding=f"Allows {cidr} on port {port} (security risk)",
                                    severity=control['severity'],
                                    timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                                    remediation=self.safe_format(control.get('remediation', ''), sg_id=sg_id),
                                    remediation_code=self.safe_format(control.get('remediation_code', ''), sg_id=sg_id)
                                ))

            if not results:
                results.append(AWSAuditResult(
                    control_id=control['id'],
                    framework=control['framework'],
                    control_name=control['name'],
                    description=f"No security groups allow {cidr} on port {port}",
                    status='PASS',
                    resource_id="N/A",
                    resource_type='Security Groups',
                    finding=f"No security groups with {cidr} on port {port}",
                    severity=control['severity'],
                    timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                ))

            return results

        except Exception as e:
            return [self.create_error_result(control, str(e))]

    def check_rds_encryption(self, control: Dict) -> List[AWSAuditResult]:
        results = []
        try:
            rds = self.session.client('rds')
            instances = rds.describe_db_instances()['DBInstances']

            if not instances:
                return [self.create_fail_result(control, "N/A", "RDS Instances", "No RDS instances found")]

            for instance in instances:
                db_id = instance['DBInstanceIdentifier']
                db_arn = instance['DBInstanceArn']
                encrypted = instance.get('StorageEncrypted', False)

                results.append(AWSAuditResult(
                    control_id=control['id'],
                    framework=control['framework'],
                    control_name=control['name'],
                    description=f"Check encryption for RDS: {db_id}",
                    status='PASS' if encrypted else 'FAIL',
                    resource_id=db_arn,
                    resource_type='RDS Instance',
                    finding=f"Encryption: {'Enabled' if encrypted else 'NOT enabled'}",
                    severity=control['severity'],
                    timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    remediation=self.safe_format(control.get('remediation', ''), db_id=db_id),
                    remediation_code=self.safe_format(control.get('remediation_code', ''), db_id=db_id)
                ))

            return results

        except Exception as e:
            return [self.create_error_result(control, str(e))]

    def run_audit(self) -> None:
        logger.info("Starting AWS security audit...")

        for control in self.controls:
            control_id = control.get('id')
            logger.info(f"Checking: {control_id} - {control.get('name')}")

            try:
                findings = self.execute_check(control)
                self.results.extend(findings)

                passed = sum(1 for f in findings if f.status == 'PASS')
                failed = sum(1 for f in findings if f.status == 'FAIL')
                logger.info(f"  Result: {passed} passed, {failed} failed")

            except Exception as e:
                logger.error(f"  Error checking {control_id}: {e}")
                self.results.append(self.create_error_result(control, str(e)))

    def generate_json_report(self, output_file: str) -> None:
        report = {
            "audit_metadata": {
                "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                "aws_account_id": self.account_id,
                "controls_file": str(self.controls_file),
                "total_checks": len(self.results),
                "passed": sum(1 for r in self.results if r.status == 'PASS'),
                "failed": sum(1 for r in self.results if r.status == 'FAIL'),
                "errors": sum(1 for r in self.results if r.status == 'ERROR'),
                "frameworks": list(set(r.framework for r in self.results))
            },
            "results": sorted(
                [r.to_dict() for r in self.results],
                key=lambda x: (x['framework'], x['control_id'])
            )
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, sort_keys=True)

        logger.info(f"JSON report saved to: {output_file}")

    def generate_csv_report(self, output_file: str) -> None:
        if not self.results:
            logger.warning("No results to write to CSV")
            return

        with open(output_file, 'w', newline='') as f:
            fieldnames = ['control_id', 'framework', 'control_name', 'status',
                          'resource_id', 'resource_type', 'finding', 'severity', 'timestamp']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for result in self.results:
                row = result.to_dict()
                writer.writerow({k: row[k] for k in fieldnames})

        logger.info(f"CSV report saved to: {output_file}")

    def generate_terraform_remediation(self, output_file: str) -> None:
        failed = [r for r in self.results if r.status == 'FAIL' and r.remediation_code]

        if not failed:
            logger.info("No failures with remediation code")
            return

        with open(output_file, 'w') as f:
            f.write("# AWS Security Remediation - Terraform\n")
            f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}Z\n")
            f.write(f"# Account: {self.account_id}\n\n")

            for result in failed:
                f.write(f"# {result.control_id}: {result.control_name}\n")
                f.write(f"# Resource: {result.resource_id}\n")
                f.write(f"# Finding: {result.finding}\n")
                f.write(f"{result.remediation_code}\n\n")

        logger.info(f"Terraform remediation saved to: {output_file}")

    def print_summary(self) -> None:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.status == 'PASS')
        failed = sum(1 for r in self.results if r.status == 'FAIL')
        errors = sum(1 for r in self.results if r.status == 'ERROR')

        print("\n" + "="*60)
        print("AWS SECURITY COMPLIANCE AUDIT SUMMARY")
        print("="*60)
        print(f"Account ID:    {self.account_id}")
        print(f"Total Checks:  {total}")
        print(f"Passed:        {passed} ({passed/total*100:.1f}%)" if total > 0 else "Passed: 0")
        print(f"Failed:        {failed} ({failed/total*100:.1f}%)" if total > 0 else "Failed: 0")
        print(f"Errors:        {errors}")
        print("="*60)

        if failed > 0:
            print("\nFailed Controls:")
            for result in self.results:
                if result.status == 'FAIL':
                    print(f"  - {result.control_id}: {result.control_name} [{result.severity}]")
                    print(f"    Resource: {result.resource_id}")
        print()

    def safe_format(self, template: str, **kwargs) -> str:
        """Safely substitute {key} placeholders without breaking Terraform/JSON curly braces.
        Only replaces exact {key} matches from kwargs, leaves everything else untouched."""
        for key, value in kwargs.items():
            template = template.replace('{' + key + '}', str(value))
        return template

    def create_error_result(self, control: Dict, error: str) -> AWSAuditResult:
        return AWSAuditResult(
            control_id=control['id'],
            framework=control.get('framework', 'UNKNOWN'),
            control_name=control['name'],
            description=control['description'],
            status='ERROR',
            resource_id='N/A',
            resource_type='N/A',
            finding=f"Error: {error}",
            severity=control.get('severity', 'MEDIUM'),
            timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        )

    def create_fail_result(self, control: Dict, resource_id: str,
                           resource_type: str, finding: str) -> AWSAuditResult:
        return AWSAuditResult(
            control_id=control['id'],
            framework=control.get('framework', 'UNKNOWN'),
            control_name=control['name'],
            description=control['description'],
            status='FAIL',
            resource_id=resource_id,
            resource_type=resource_type,
            finding=finding,
            severity=control.get('severity', 'MEDIUM'),
            timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            remediation=control.get('remediation', ''),
            remediation_code=control.get('remediation_code', '')
        )


def main():
    parser = argparse.ArgumentParser(description='AWS Security Compliance Auditor')
    parser.add_argument('-c', '--controls', default='aws_controls.json')
    parser.add_argument('-o', '--output-dir', default='reports')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--framework', choices=['CIS', 'SOC1', 'SOC2', 'ALL'], default='ALL')

    args = parser.parse_args()

    try:
        auditor = AWSSecurityAuditor(args.controls, args.profile)
        auditor.load_controls()

        if args.framework != 'ALL':
            auditor.controls = [c for c in auditor.controls if c.get('framework') == args.framework]
            logger.info(f"Filtered to {len(auditor.controls)} {args.framework} controls")

        auditor.run_audit()

        Path(args.output_dir).mkdir(exist_ok=True, parents=True)
        auditor.generate_json_report(f"{args.output_dir}/aws_audit_report.json")
        auditor.generate_csv_report(f"{args.output_dir}/aws_audit_report.csv")
        auditor.generate_terraform_remediation(f"{args.output_dir}/remediation.tf")

        auditor.print_summary()

        failed_count = sum(1 for r in auditor.results if r.status == 'FAIL')
        return 1 if failed_count > 0 else 0

    except Exception as e:
        logger.error(f"Audit failed: {e}")
        import traceback
        traceback.print_exc()
        return 2


if __name__ == '__main__':
    exit(main())
