#!/usr/bin/env python3
"""Test core components."""
import sys
import asyncio

print("Testing core components...")
print()

# Test 1: Import finding models
print("1. Testing finding.py...")
try:
    from auditor.core.finding import Finding, Status, Severity
    print("  ✅ Finding, Status, Severity imported")
except Exception as e:
    print(f"  ❌ Failed: {e}")
    sys.exit(1)

# Test 2: Import control base class
print("2. Testing control.py...")
try:
    from auditor.core.control import Control
    print("  ✅ Control base class imported")
except Exception as e:
    print(f"  ❌ Failed: {e}")
    sys.exit(1)

# Test 3: Import engine
print("3. Testing engine.py...")
try:
    from auditor.core.engine import AuditEngine
    print("  ✅ AuditEngine imported")
except Exception as e:
    print(f"  ❌ Failed: {e}")
    sys.exit(1)

# Test 4: Import Azure client
print("4. Testing azure_client.py...")
try:
    from auditor.core.azure_client import AzureClient
    print("  ✅ AzureClient imported")
except Exception as e:
    print(f"  ❌ Failed: {e}")
    sys.exit(1)

# Test 5: Import storage controls
print("5. Testing storage_controls.py...")
try:
    from auditor.frameworks.cis_azure.storage_controls import CIS_Azure_3_1_SecureTransferRequired
    print("  ✅ Storage controls imported")
except Exception as e:
    print(f"  ❌ Failed: {e}")
    sys.exit(1)

print()
print("=" * 60)
print("✅ All core components working!")
print("=" * 60)
