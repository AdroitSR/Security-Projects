# test_credentials.py
import boto3

try:
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    print(f"✅ Connected as: {identity['Arn']}")
    print(f"Account ID: {identity['Account']}")
except Exception as e:
    print(f"❌ Error: {e}")
