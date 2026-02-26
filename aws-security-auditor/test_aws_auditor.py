"""
Unit and integration tests for AWS Security Auditor
Run with: pytest test_aws_auditor.py -v
Coverage: pytest --cov=aws_auditor --cov-report=html test_aws_auditor.py
"""

import pytest
import json
import boto3
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock
from moto import mock_iam, mock_s3, mock_cloudtrail, mock_ec2, mock_sts

# Import the main module
import sys
sys.path.insert(0, str(Path(__file__).parent))
from aws_auditor import AWSSecurityAuditor, AWSAuditResult


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def sample_controls_file(tmp_path):
    """Create a temporary controls JSON file for testing"""
    controls = {
        "metadata": {
            "version": "1.0",
            "frameworks": ["CIS", "SOC2"]
        },
        "controls": [
            {
                "id": "TEST-IAM-1",
                "framework": "CIS",
                "name": "Test IAM Password Policy",
                "description": "Verify password policy exists",
                "check_type": "iam_password_policy",
                "expected_value": 14,
                "severity": "HIGH",
                "remediation": "Set password policy with minimum length 14",
                "remediation_code": "resource \"aws_iam_account_password_policy\" \"strict\" { minimum_password_length = 14 }"
            },
            {
                "id": "TEST-IAM-2",
                "framework": "CIS",
                "name": "Test IAM MFA",
                "description": "Verify MFA enabled for users",
                "check_type": "iam_mfa_enabled",
                "severity": "CRITICAL",
                "remediation": "Enable MFA for user: {username}",
                "remediation_code": "# Enable MFA via Console"
            },
            {
                "id": "TEST-S3-1",
                "framework": "CIS",
                "name": "Test S3 Public Access",
                "description": "Verify S3 buckets block public access",
                "check_type": "s3_bucket_public",
                "severity": "HIGH",
                "remediation": "Block public access for bucket: {bucket}",
                "remediation_code": "resource \"aws_s3_bucket_public_access_block\" \"block\" { block_public_acls = true }"
            },
            {
                "id": "TEST-CT-1",
                "framework": "SOC2",
                "name": "Test CloudTrail Enabled",
                "description": "Verify CloudTrail is logging",
                "check_type": "cloudtrail_enabled",
                "expected_value": True,
                "severity": "HIGH",
                "remediation": "Enable CloudTrail logging",
                "remediation_code": "resource \"aws_cloudtrail\" \"main\" { enable_logging = true }"
            },
            {
                "id": "TEST-EC2-1",
                "framework": "CIS",
                "name": "Test Security Group Rules",
                "description": "Check for open SSH access",
                "check_type": "ec2_security_group",
                "port": 22,
                "cidr": "0.0.0.0/0",
                "severity": "CRITICAL",
                "remediation": "Remove 0.0.0.0/0 from port 22",
                "remediation_code": "# aws ec2 revoke-security-group-ingress"
            }
        ]
    }

    controls_file = tmp_path / "test_aws_controls.json"
    with open(controls_file, 'w') as f:
        json.dump(controls, f)

    return controls_file


@pytest.fixture
def mock_aws_credentials():
    """Mock AWS credentials for moto"""
    import os
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'


@pytest.fixture
def auditor(sample_controls_file, mock_aws_credentials):
    """Create an auditor instance with test controls"""
    with mock_sts():
        sts = boto3.client('sts', region_name='us-east-1')
        sts.get_caller_identity = MagicMock(return_value={'Account': '123456789012'})

        auditor = AWSSecurityAuditor(str(sample_controls_file))
        auditor.account_id = '123456789012'
        return auditor


# ============================================================================
# UNIT TESTS - AWSAuditResult
# ============================================================================

class TestAWSAuditResult:
    """Test AWSAuditResult dataclass"""

    def test_audit_result_creation(self):
        """Test creating an AWSAuditResult instance"""
        result = AWSAuditResult(
            control_id="CIS-1.1",
            framework="CIS",
            control_name="Test Control",
            description="Test description",
            status="PASS",
            resource_id="arn:aws:iam::123456789012:user/test",
            resource_type="IAM User",
            finding="Test finding",
            severity="HIGH",
            timestamp="2025-01-07T10:00:00Z"
        )

        assert result.control_id == "CIS-1.1"
        assert result.framework == "CIS"
        assert result.status == "PASS"
        assert result.severity == "HIGH"

    def test_audit_result_to_dict(self):
        """Test converting AWSAuditResult to dictionary"""
        result = AWSAuditResult(
            control_id="CIS-1.1",
            framework="CIS",
            control_name="Test Control",
            description="Test description",
            status="PASS",
            resource_id="arn:aws:iam::123456789012:user/test",
            resource_type="IAM User",
            finding="Test finding",
            severity="HIGH",
            timestamp="2025-01-07T10:00:00Z",
            remediation="Fix this",
            remediation_code="terraform code"
        )

        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert result_dict['control_id'] == "CIS-1.1"
        assert result_dict['status'] == "PASS"
        assert result_dict['remediation'] == "Fix this"
        assert result_dict['remediation_code'] == "terraform code"


# ============================================================================
# UNIT TESTS - AWSSecurityAuditor Initialization
# ============================================================================

class TestAuditorInitialization:
    """Test auditor initialization"""

    @mock_sts
    def test_auditor_initialization(self, sample_controls_file, mock_aws_credentials):
        """Test auditor initialization"""
        auditor = AWSSecurityAuditor(str(sample_controls_file))

        assert auditor.controls_file == Path(sample_controls_file)
        assert auditor.controls == []
        assert auditor.results == []
        assert auditor.session is not None

    def test_load_controls(self, auditor):
        """Test loading controls from JSON file"""
        auditor.load_controls()

        assert len(auditor.controls) == 5
        assert auditor.controls[0]['id'] == "TEST-IAM-1"
        assert auditor.controls[1]['framework'] == "CIS"

    def test_load_controls_file_not_found(self, mock_aws_credentials):
        """Test loading controls with non-existent file"""
        with mock_sts():
            auditor = AWSSecurityAuditor("nonexistent.json")
            with pytest.raises(FileNotFoundError):
                auditor.load_controls()

    def test_load_controls_invalid_json(self, tmp_path, mock_aws_credentials):
        """Test loading controls with invalid JSON"""
        invalid_file = tmp_path / "invalid.json"
        with open(invalid_file, 'w') as f:
            f.write("{ invalid json }")

        with mock_sts():
            auditor = AWSSecurityAuditor(str(invalid_file))
            with pytest.raises(json.JSONDecodeError):
                auditor.load_controls()


# ============================================================================
# UNIT TESTS - IAM Password Policy Check
# ============================================================================

class TestIAMPasswordPolicy:
    """Test IAM password policy checks"""

    @mock_iam
    def test_password_policy_exists_and_compliant(self, auditor):
        """Test password policy check when policy exists and is compliant"""
        # Create IAM client and set password policy
        iam = boto3.client('iam', region_name='us-east-1')
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            RequireNumbers=True,
            RequireSymbols=True
        )

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[0]  # TEST-IAM-1
        results = auditor.check_iam_password_policy(control)

        assert len(results) == 1
        assert results[0].status == 'PASS'
        assert results[0].control_id == 'TEST-IAM-1'
        assert '14' in results[0].finding

    @mock_iam
    def test_password_policy_exists_but_weak(self, auditor):
        """Test password policy check when policy is too weak"""
        iam = boto3.client('iam', region_name='us-east-1')
        iam.update_account_password_policy(MinimumPasswordLength=8)

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[0]
        results = auditor.check_iam_password_policy(control)

        assert len(results) == 1
        assert results[0].status == 'FAIL'
        assert '8' in results[0].finding

    @mock_iam
    def test_password_policy_not_configured(self, auditor):
        """Test password policy check when no policy exists"""
        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[0]
        results = auditor.check_iam_password_policy(control)

        assert len(results) == 1
        assert results[0].status == 'FAIL'
        assert 'No password policy' in results[0].finding


# ============================================================================
# UNIT TESTS - IAM MFA Check
# ============================================================================

class TestIAMMFA:
    """Test IAM MFA checks"""

    @mock_iam
    def test_user_with_mfa_enabled(self, auditor):
        """Test MFA check for user with MFA enabled"""
        iam = boto3.client('iam', region_name='us-east-1')

        # Create user
        iam.create_user(UserName='test-user')

        # Enable virtual MFA device
        iam.enable_mfa_device(
            UserName='test-user',
            SerialNumber='arn:aws:iam::123456789012:mfa/test-user',
            AuthenticationCode1='123456',
            AuthenticationCode2='654321'
        )

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[1]  # TEST-IAM-2
        results = auditor.check_iam_mfa(control)

        assert len(results) == 1
        assert results[0].status == 'PASS'
        assert 'test-user' in results[0].resource_id
        assert 'enabled' in results[0].finding.lower()

    @mock_iam
    def test_user_without_mfa(self, auditor):
        """Test MFA check for user without MFA"""
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_user(UserName='test-user-no-mfa')

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[1]
        results = auditor.check_iam_mfa(control)

        assert len(results) == 1
        assert results[0].status == 'FAIL'
        assert 'test-user-no-mfa' in results[0].resource_id
        assert 'NOT enabled' in results[0].finding

    @mock_iam
    def test_multiple_users_mixed_mfa(self, auditor):
        """Test MFA check with multiple users, some with MFA"""
        iam = boto3.client('iam', region_name='us-east-1')

        # User with MFA
        iam.create_user(UserName='user-with-mfa')
        iam.enable_mfa_device(
            UserName='user-with-mfa',
            SerialNumber='arn:aws:iam::123456789012:mfa/user-with-mfa',
            AuthenticationCode1='123456',
            AuthenticationCode2='654321'
        )

        # User without MFA
        iam.create_user(UserName='user-without-mfa')

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[1]
        results = auditor.check_iam_mfa(control)

        assert len(results) == 2

        # Check first user (with MFA)
        user_with_mfa_result = [r for r in results if 'user-with-mfa' in r.resource_id][0]
        assert user_with_mfa_result.status == 'PASS'

        # Check second user (without MFA)
        user_without_mfa_result = [r for r in results if 'user-without-mfa' in r.resource_id][0]
        assert user_without_mfa_result.status == 'FAIL'


# ============================================================================
# UNIT TESTS - S3 Public Access Check
# ============================================================================

class TestS3PublicAccess:
    """Test S3 public access checks"""

    @mock_s3
    def test_bucket_with_public_access_blocked(self, auditor):
        """Test S3 check when public access is blocked"""
        s3 = boto3.client('s3', region_name='us-east-1')

        # Create bucket
        s3.create_bucket(Bucket='test-secure-bucket')

        # Set public access block
        s3.put_public_access_block(
            Bucket='test-secure-bucket',
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[2]  # TEST-S3-1
        results = auditor.check_s3_public_access(control)

        assert len(results) == 1
        assert results[0].status == 'PASS'
        assert 'test-secure-bucket' in results[0].resource_id
        assert 'blocked' in results[0].finding.lower()

    @mock_s3
    def test_bucket_without_public_access_block(self, auditor):
        """Test S3 check when public access is NOT blocked"""
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='test-insecure-bucket')

        # Don't set public access block

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[2]
        results = auditor.check_s3_public_access(control)

        assert len(results) == 1
        assert results[0].status == 'FAIL'
        assert 'test-insecure-bucket' in results[0].resource_id

    @mock_s3
    def test_multiple_buckets_mixed_configuration(self, auditor):
        """Test S3 check with multiple buckets"""
        s3 = boto3.client('s3', region_name='us-east-1')

        # Secure bucket
        s3.create_bucket(Bucket='secure-bucket')
        s3.put_public_access_block(
            Bucket='secure-bucket',
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )

        # Insecure bucket
        s3.create_bucket(Bucket='insecure-bucket')

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[2]
        results = auditor.check_s3_public_access(control)

        assert len(results) == 2

        secure_result = [r for r in results if 'secure-bucket' in r.resource_id][0]
        assert secure_result.status == 'PASS'

        insecure_result = [r for r in results if 'insecure-bucket' in r.resource_id][0]
        assert insecure_result.status == 'FAIL'


# ============================================================================
# UNIT TESTS - CloudTrail Check
# ============================================================================

class TestCloudTrail:
    """Test CloudTrail checks"""

    @mock_cloudtrail
    @mock_s3
    def test_cloudtrail_enabled_and_logging(self, auditor):
        """Test CloudTrail check when trail exists and is logging"""
        # Create S3 bucket for CloudTrail
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='cloudtrail-logs')

        # Create CloudTrail
        cloudtrail = boto3.client('cloudtrail', region_name='us-east-1')
        cloudtrail.create_trail(
            Name='test-trail',
            S3BucketName='cloudtrail-logs',
            IsMultiRegionTrail=True
        )
        cloudtrail.start_logging(Name='test-trail')

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[3]  # TEST-CT-1
        results = auditor.check_cloudtrail(control)

        assert len(results) >= 1
        # At least one trail should be logging
        assert any(r.status == 'PASS' for r in results)

    @mock_cloudtrail
    def test_cloudtrail_not_configured(self, auditor):
        """Test CloudTrail check when no trail exists"""
        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[3]
        results = auditor.check_cloudtrail(control)

        # Should return FAIL when no trails exist
        assert len(results) >= 1
        assert any(r.status == 'FAIL' for r in results)


# ============================================================================
# UNIT TESTS - Security Group Check
# ============================================================================

class TestSecurityGroups:
    """Test EC2 security group checks"""

    @mock_ec2
    def test_security_group_with_open_ssh(self, auditor):
        """Test security group with 0.0.0.0/0 on port 22"""
        ec2 = boto3.client('ec2', region_name='us-east-1')

        # Create VPC and security group
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']

        sg = ec2.create_security_group(
            GroupName='test-sg-open',
            Description='Test SG with open SSH',
            VpcId=vpc_id
        )
        sg_id = sg['GroupId']

        # Add rule allowing 0.0.0.0/0 on port 22
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[4]  # TEST-EC2-1
        results = auditor.check_security_groups(control)

        assert len(results) >= 1
        sg_result = [r for r in results if sg_id in r.resource_id][0]
        assert sg_result.status == 'FAIL'
        assert '22' in sg_result.finding

    @mock_ec2
    def test_security_group_restricted_ssh(self, auditor):
        """Test security group with restricted SSH access"""
        ec2 = boto3.client('ec2', region_name='us-east-1')

        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']

        sg = ec2.create_security_group(
            GroupName='test-sg-secure',
            Description='Test SG with restricted SSH',
            VpcId=vpc_id
        )
        sg_id = sg['GroupId']

        # Add rule with specific IP
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '10.0.0.0/8'}]
            }]
        )

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[4]
        results = auditor.check_security_groups(control)

        # Should PASS because it's not 0.0.0.0/0
        sg_result = [r for r in results if sg_id in r.resource_id]
        if sg_result:
            assert sg_result[0].status == 'PASS'


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    """Integration tests for full audit workflow"""

    @mock_iam
    @mock_s3
    @mock_cloudtrail
    @mock_ec2
    def test_full_audit_workflow(self, auditor):
        """Test complete audit workflow"""
        # Setup AWS resources
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_user(UserName='test-user')

        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='test-bucket')

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()
        auditor.run_audit()

        # Verify results
        assert len(auditor.results) > 0
        assert all(isinstance(r, AWSAuditResult) for r in auditor.results)

        # Check that we have results for different check types
        control_ids = [r.control_id for r in auditor.results]
        assert 'TEST-IAM-1' in control_ids or 'TEST-IAM-2' in control_ids
        assert 'TEST-S3-1' in control_ids

    @mock_iam
    @mock_s3
    def test_generate_json_report(self, auditor, tmp_path):
        """Test generating JSON report"""
        # Setup and run audit
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_user(UserName='test-user')

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()
        auditor.run_audit()

        # Generate report
        report_file = tmp_path / "test_report.json"
        auditor.generate_json_report(str(report_file))

        assert report_file.exists()

        # Validate report structure
        with open(report_file) as f:
            report = json.load(f)

        assert 'audit_metadata' in report
        assert 'results' in report
        assert 'aws_account_id' in report['audit_metadata']
        assert report['audit_metadata']['total_checks'] > 0

    @mock_iam
    @mock_s3
    def test_generate_csv_report(self, auditor, tmp_path):
        """Test generating CSV report"""
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_user(UserName='test-user')

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()
        auditor.run_audit()

        report_file = tmp_path / "test_report.csv"
        auditor.generate_csv_report(str(report_file))

        assert report_file.exists()

        content = report_file.read_text()
        assert 'control_id' in content
        assert 'status' in content
        assert 'severity' in content

    @mock_iam
    def test_generate_terraform_remediation(self, auditor, tmp_path):
        """Test generating Terraform remediation code"""
        # Create user without MFA (will fail MFA check)
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_user(UserName='test-user-no-mfa')

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()
        auditor.run_audit()

        remediation_file = tmp_path / "remediation.tf"
        auditor.generate_terraform_remediation(str(remediation_file))

        # Only generated if there are failures
        if any(r.status == 'FAIL' for r in auditor.results):
            assert remediation_file.exists()
            content = remediation_file.read_text()
            assert '# AWS Security Remediation' in content


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class TestErrorHandling:
    """Test error handling scenarios"""

    def test_execute_check_unknown_check_type(self, auditor):
        """Test handling of unknown check type"""
        auditor.load_controls()

        unknown_control = {
            'id': 'TEST-UNKNOWN',
            'framework': 'TEST',
            'name': 'Unknown Check Type',
            'description': 'Test',
            'check_type': 'unknown_type',
            'severity': 'LOW'
        }

        results = auditor.execute_check(unknown_control)

        assert len(results) == 1
        assert results[0].status == 'ERROR'
        assert 'Unknown check type' in results[0].finding

    @mock_iam
    def test_iam_check_with_api_error(self, auditor):
        """Test IAM check when API call fails"""
        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        # Patch boto3 to raise exception
        with patch.object(auditor.session, 'client') as mock_client:
            mock_iam = MagicMock()
            mock_iam.get_account_password_policy.side_effect = Exception("API Error")
            mock_client.return_value = mock_iam

            control = auditor.controls[0]
            results = auditor.check_iam_password_policy(control)

            assert len(results) == 1
            assert results[0].status == 'ERROR'

    def test_continue_on_individual_check_failure(self, auditor):
        """Test that audit continues when individual checks fail"""
        auditor.load_controls()

        # Mock execute_check to fail on first control
        original_execute = auditor.execute_check
        call_count = [0]

        def mock_execute(control):
            call_count[0] += 1
            if call_count[0] == 1:
                return [auditor.create_error_result(control, "Test error")]
            return original_execute(control)

        with patch.object(auditor, 'execute_check', side_effect=mock_execute):
            auditor.run_audit()

        # Should have tried all controls despite first failure
        assert call_count[0] == len(auditor.controls)


# ============================================================================
# HELPER METHOD TESTS
# ============================================================================

class TestHelperMethods:
    """Test helper methods"""

    def test_create_error_result(self, auditor):
        """Test creating error result"""
        control = {
            'id': 'TEST-1',
            'framework': 'TEST',
            'name': 'Test Control',
            'description': 'Test',
            'severity': 'HIGH'
        }

        result = auditor.create_error_result(control, "Test error message")

        assert result.status == 'ERROR'
        assert result.control_id == 'TEST-1'
        assert 'Test error message' in result.finding

    def test_create_fail_result(self, auditor):
        """Test creating fail result"""
        control = {
            'id': 'TEST-1',
            'framework': 'TEST',
            'name': 'Test Control',
            'description': 'Test',
            'severity': 'HIGH',
            'remediation': 'Fix this'
        }

        result = auditor.create_fail_result(
            control,
            'arn:aws:iam::123456789012:user/test',
            'IAM User',
            'Test finding'
        )

        assert result.status == 'FAIL'
        assert result.control_id == 'TEST-1'
        assert result.resource_id == 'arn:aws:iam::123456789012:user/test'
        assert result.finding == 'Test finding'
        assert result.remediation == 'Fix this'


# ============================================================================
# EDGE CASE TESTS
# ============================================================================

class TestEdgeCases:
    """Test edge cases"""

    @mock_iam
    def test_no_iam_users_exist(self, auditor):
        """Test MFA check when no IAM users exist"""
        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[1]
        results = auditor.check_iam_mfa(control)

        # Should return empty list or handle gracefully
        assert isinstance(results, list)

    @mock_s3
    def test_no_s3_buckets_exist(self, auditor):
        """Test S3 check when no buckets exist"""
        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        control = auditor.controls[2]
        results = auditor.check_s3_public_access(control)

        assert isinstance(results, list)

    def test_empty_controls_file(self, tmp_path, mock_aws_credentials):
        """Test with empty controls file"""
        empty_controls = {"metadata": {}, "controls": []}
        controls_file = tmp_path / "empty.json"

        with open(controls_file, 'w') as f:
            json.dump(empty_controls, f)

        with mock_sts():
            auditor = AWSSecurityAuditor(str(controls_file))
            auditor.load_controls()
            auditor.run_audit()

            assert len(auditor.results) == 0


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

class TestPerformance:
    """Test performance characteristics"""

    @mock_iam
    @mock_s3
    def test_audit_completes_in_reasonable_time(self, auditor):
        """Test that audit completes in reasonable time"""
        import time

        # Setup multiple resources
        iam = boto3.client('iam', region_name='us-east-1')
        for i in range(5):
            iam.create_user(UserName=f'user-{i}')

        s3 = boto3.client('s3', region_name='us-east-1')
        for i in range(5):
            s3.create_bucket(Bucket=f'bucket-{i}')

        auditor.session = boto3.Session(region_name='us-east-1')
        auditor.load_controls()

        start_time = time.time()
        auditor.run_audit()
        end_time = time.time()

        # Should complete in under 30 seconds for 5 controls
        assert (end_time - start_time) < 30


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])