
#!/usr/bin/env python3
import os
import sys

print("=" * 60)
print("Azure Authentication Diagnostic")
print("=" * 60)
print()

# Check environment variables
print("1. Environment Variables:")
vars_to_check = [
    'AZURE_SUBSCRIPTION_ID',
    'AZURE_TENANT_ID',
    'AZURE_CLIENT_ID',
    'AZURE_CLIENT_SECRET'
]

for var in vars_to_check:
    value = os.getenv(var)
    if value:
        # Mask secret for security
        if 'SECRET' in var:
            masked = value[:4] + '*' * (len(value) - 8) + value[-4:]
            print(f"  ✅ {var}: {masked} (length: {len(value)})")
        else:
            print(f"  ✅ {var}: {value}")
    else:
        print(f"  ❌ {var}: NOT SET")

print()
print("2. Secret Value Check:")
secret = os.getenv('AZURE_CLIENT_SECRET', '')
if secret:
    print(f"  Length: {len(secret)} characters")
    print(f"  Has ~: {'✅' if '~' in secret else '❌'}")
    print(f"  Has .: {'✅' if '.' in secret else '❌'}")
    print(f"  Mixed case: {'✅' if secret != secret.lower() else '❌'}")

    if len(secret) < 40:
        print("  ⚠️  SECRET TOO SHORT - You might have copied the Secret ID!")
    elif '~' not in secret and '.' not in secret:
        print("  ⚠️  NO SPECIAL CHARS - You might have copied the Secret ID!")
    else:
        print("  ✅ Secret format looks correct!")
else:
    print("  ❌ No secret set")

print()
print("3. Testing Azure Connection:")
try:
    from auditor.core.azure_client import AzureClient
    client = AzureClient()
    print(f"  ✅ SUCCESS! Connected to subscription: {client.subscription_id}")
except Exception as e:
    print(f"  ❌ FAILED: {str(e)[:200]}")
    if "AADSTS7000215" in str(e):
        print()
        print("  🔴 ERROR: Invalid client secret!")
        print("  You likely copied the Secret ID instead of the Secret Value.")
        print("  Go to Azure Portal and create a NEW secret, then copy the VALUE.")

print()
print("=" * 60)

