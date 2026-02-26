# AWS Security Remediation - Terraform
# Generated: 2026-02-20T00:30:15.002800+00:00Z
# Account: 704555300897

# CIS-1.4: Ensure no root account access key exists
# Resource: arn:aws:iam::704555300897:root
# Finding: Root access keys: EXIST (delete them!)
# Manual: AWS Console > IAM > Security Credentials

# CIS-4.1: Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
# Resource: arn:aws:ec2:us-east-1:704555300897:security-group/sg-0d030ad815b274e01
# Finding: Allows 0.0.0.0/0 on port 22 (security risk)
# Remove with: aws ec2 revoke-security-group-ingress --group-id sg-0d030ad815b274e01 --protocol tcp --port 22 --cidr 0.0.0.0/0

# SOC2-CC6.1: Logical Access Controls - MFA Required
# Resource: arn:aws:iam::704555300897:user/aws-security-auditor
# Finding: MFA NOT enabled
# See CIS-1.10

