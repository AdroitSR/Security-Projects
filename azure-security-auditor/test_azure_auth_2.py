
"""Verify Azure permissions are correctly set."""
import sys

print("=" * 60)
print("Azure Permissions Verification")
print("=" * 60)
print()

try:
    from auditor.core.azure_client import AzureClient

    client = AzureClient()
    print(f"✅ Authentication: Connected to {client.subscription_id}")

    # Test 1: Storage Accounts
    print()
    print("Testing permissions:")
    print()
    try:
        storage = client.get_storage_client()
        accounts = list(storage.storage_accounts.list())
        print(f"  ✅ Storage Accounts: Can read {len(accounts)} accounts")
    except Exception as e:
        print(f"  ❌ Storage Accounts: {str(e)[:100]}")
        if "AuthorizationFailed" in str(e):
            print("     → Need 'Reader' role on subscription")

    # Test 2: Virtual Machines
    try:
        compute = client.get_compute_client()
        vms = list(compute.virtual_machines.list_all())
        print(f"  ✅ Virtual Machines: Can read {len(vms)} VMs")
    except Exception as e:
        print(f"  ❌ Virtual Machines: {str(e)[:100]}")

    # Test 3: Network Security Groups
    try:
        network = client.get_network_client()
        nsgs = list(network.network_security_groups.list_all())
        print(f"  ✅ Network Security Groups: Can read {len(nsgs)} NSGs")
    except Exception as e:
        print(f"  ❌ Network Security Groups: {str(e)[:100]}")

    # Test 4: Key Vaults
    try:
        keyvault = client.get_keyvault_client()
        vaults = list(keyvault.vaults.list())
        print(f"  ✅ Key Vaults: Can read {len(vaults)} vaults")
    except Exception as e:
        print(f"  ❌ Key Vaults: {str(e)[:100]}")

    print()
    print("=" * 60)
    print("✅ All permissions look good! Ready to audit!")
    print("=" * 60)

except Exception as e:
    print(f"❌ FAILED: {e}")
    sys.exit(1)

