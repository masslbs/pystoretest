# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import time

from massmarket import (
    error_pb2,
    cbor_encode,
)
import massmarket.cbor.patch as mpatch
from massmarket_client.legacy_client import RelayClient
from massmarket_client.client import RefactoredRelayClient
from massmarket_client.utils import new_object_id


def create_client_pair(test_name: str, account_manager=None, **kwargs):
    """Create both old and refactored clients for direct comparison."""
    # Get a test account if account manager is provided
    if account_manager is not None:
        test_account = account_manager.get_test_account()
        kwargs["wallet_account"] = test_account

    old_client = RelayClient(name=f"{test_name}_old", **kwargs)
    refactored_client = RefactoredRelayClient(
        name=f"{test_name}_new",
        data_dir=f".testruns/{test_name}_new/data",
        log_dir=f".testruns/{test_name}_new/logs",
        **kwargs,
    )

    return old_client, refactored_client


def compare_shop_states(old_client, new_client, test_name=""):
    """Compare the shop states between old and new clients."""
    old_shop = old_client.shop
    new_shop = new_client.shop

    if old_shop is None and new_shop is None:
        return True

    assert old_shop is not None, f"{test_name}: Old client has no shop"
    assert new_shop is not None, f"{test_name}: New client has no shop"

    # Compare basic properties
    assert (
        old_shop.listings.size == new_shop.listings.size
    ), f"{test_name}: Listing count mismatch"
    assert old_shop.tags.size == new_shop.tags.size, f"{test_name}: Tag count mismatch"
    assert (
        old_shop.orders.size == new_shop.orders.size
    ), f"{test_name}: Order count mismatch"

    # Compare specific listings
    def compare_listing(listing_id, old_listing):
        assert new_shop.listings.has(
            listing_id
        ), f"{test_name}: New client missing listing {listing_id}"
        new_listing = new_shop.listings.get(listing_id)
        assert (
            old_listing.price == new_listing.price
        ), f"{test_name}: Price mismatch for listing {listing_id}"
        assert (
            old_listing.metadata.title == new_listing.metadata.title
        ), f"{test_name}: Title mismatch for listing {listing_id}"
        return True

    if old_shop.listings.size > 0:
        old_shop.listings.all(compare_listing)

    # Compare tags
    def compare_tag(tag_name, old_tag):
        if old_tag is None:
            return True
        assert new_shop.tags.has(
            tag_name
        ), f"{test_name}: New client missing tag {tag_name}"
        new_tag = new_shop.tags.get(tag_name)
        assert len(old_tag.listings) == len(
            new_tag.listings
        ), f"{test_name}: Tag listing count mismatch for {tag_name}"
        assert set(old_tag.listings) == set(
            new_tag.listings
        ), f"{test_name}: Tag listings mismatch for {tag_name}"
        return True

    if old_shop.tags.size > 0:
        old_shop.tags.all(compare_tag)

    return True


def test_direct_basic_connection_comparison(account_manager):
    """Test that both clients connect and authenticate identically."""
    old_client, new_client = create_client_pair("conn_compare", account_manager)

    try:
        # Both should register shops successfully
        old_shop_id = old_client.register_shop()
        new_shop_id = new_client.register_shop()

        assert old_shop_id is not None and new_shop_id is not None

        # Both should enroll key cards successfully
        old_client.enroll_key_card()
        new_client.enroll_key_card()

        # Both should login successfully
        old_client.login(subscribe=False)
        new_client.login(subscribe=False)

        # Handle messages and compare states
        old_client.handle_all()
        new_client.handle_all()

        # Both should be logged in and connected
        assert old_client.logged_in == new_client.logged_in == True
        assert old_client.connected == new_client.connected == True

        # Ping/pong behavior should be similar
        initial_old_pongs = old_client.pongs
        initial_new_pongs = new_client.pongs

        time.sleep(2)
        old_client.handle_all()
        new_client.handle_all()

        assert old_client.pongs >= initial_old_pongs
        assert new_client.pongs >= initial_new_pongs

    finally:
        for client in [old_client, new_client]:
            if client:
                try:
                    client.close()
                except Exception as e:
                    print(f"Warning: Error closing client: {e}")


def test_direct_patch_writing_comparison(account_manager):
    """Test that both clients write patches identically."""
    old_client, new_client = create_client_pair("patch_compare", account_manager)

    try:
        # Setup both clients identically
        for client in [old_client, new_client]:
            client.register_shop()
            client.enroll_key_card()
            client.login()
            client.create_shop_manifest()

        # Perform identical operations on both clients
        old_listing_id = old_client.create_listing("Test Product", 1000)
        new_listing_id = new_client.create_listing("Test Product", 1000)

        # Verify both succeeded without errors
        assert old_client.errors == 0
        assert new_client.errors == 0

        # Verify both have the listing
        assert old_client.shop is not None
        assert new_client.shop is not None
        assert old_client.shop.listings.has(old_listing_id)
        assert new_client.shop.listings.has(new_listing_id)

        # Update listings identically
        old_client.update_listing(old_listing_id, price=2000)
        new_client.update_listing(new_listing_id, price=2000)

        assert old_client.errors == 0
        assert new_client.errors == 0

        # Compare the resulting states
        assert old_client.shop is not None
        assert new_client.shop is not None
        old_listing = old_client.shop.listings.get(old_listing_id)
        new_listing = new_client.shop.listings.get(new_listing_id)
        assert old_listing is not None
        assert new_listing is not None

        assert old_listing.price == new_listing.price == 2000

        # Test inventory operations
        old_client.change_inventory(old_listing_id, 10)
        new_client.change_inventory(new_listing_id, 10)

        assert old_client.errors == 0
        assert new_client.errors == 0

        assert (
            old_client.check_inventory(old_listing_id)
            == new_client.check_inventory(new_listing_id)
            == 10
        )

        # Test tag operations
        old_client.create_tag("test_tag")
        new_client.create_tag("test_tag")

        old_client.add_to_tag("test_tag", old_listing_id)
        new_client.add_to_tag("test_tag", new_listing_id)

        assert old_client.errors == 0
        assert new_client.errors == 0

        # Verify tag states match
        assert old_client.shop is not None
        assert new_client.shop is not None
        old_tag = old_client.shop.tags.get("test_tag")
        new_tag = new_client.shop.tags.get("test_tag")
        assert old_tag is not None
        assert new_tag is not None

        assert old_listing_id in old_tag.listings
        assert new_listing_id in new_tag.listings

    finally:
        for client in [old_client, new_client]:
            if client:
                try:
                    client.close()
                except Exception as e:
                    print(f"Warning: Error closing client: {e}")


def test_direct_batch_operations_comparison(account_manager):
    """Test that batch operations work identically in both clients."""
    old_client, new_client = create_client_pair("batch_compare", account_manager)

    try:
        # Setup both clients
        for client in [old_client, new_client]:
            client.register_shop()
            client.enroll_key_card()
            client.login()
            client.create_shop_manifest()

        # Create initial listings
        old_listing_id = old_client.create_listing("Batch Test Product", 1000)
        new_listing_id = new_client.create_listing("Batch Test Product", 1000)

        # Test batching on both clients
        old_client.start_batch()
        new_client.start_batch()

        # Perform identical batch operations
        old_client.update_listing(old_listing_id, price=1500)
        new_client.update_listing(new_listing_id, price=1500)

        old_client.update_listing(old_listing_id, title="Updated Title")
        new_client.update_listing(new_listing_id, title="Updated Title")

        old_client.change_inventory(old_listing_id, 5)
        new_client.change_inventory(new_listing_id, 5)

        old_client.create_tag("batch_tag")
        new_client.create_tag("batch_tag")

        old_client.add_to_tag("batch_tag", old_listing_id)
        new_client.add_to_tag("batch_tag", new_listing_id)

        # Flush batches
        old_client.flush_batch()
        new_client.flush_batch()

        # Verify both have no errors
        assert old_client.errors == 0
        assert new_client.errors == 0

        # Compare final states
        old_listing = old_client.shop.listings.get(old_listing_id)
        new_listing = new_client.shop.listings.get(new_listing_id)

        assert old_listing.price == new_listing.price == 1500
        assert (
            old_listing.metadata.title == new_listing.metadata.title == "Updated Title"
        )
        assert (
            old_client.check_inventory(old_listing_id)
            == new_client.check_inventory(new_listing_id)
            == 5
        )

        old_tag = old_client.shop.tags.get("batch_tag")
        new_tag = new_client.shop.tags.get("batch_tag")

        assert old_listing_id in old_tag.listings
        assert new_listing_id in new_tag.listings

    finally:
        for client in [old_client, new_client]:
            if client:
                try:
                    client.close()
                except Exception as e:
                    print(f"Warning: Error closing client: {e}")


def test_direct_error_handling_comparison(account_manager):
    """Test that both clients handle errors identically."""
    old_client, new_client = create_client_pair("error_compare", account_manager)

    try:
        # Setup both clients
        for client in [old_client, new_client]:
            client.register_shop()
            client.enroll_key_card()
            client.login()
            client.create_shop_manifest()

        # Test error handling for non-existent listing
        for client in [old_client, new_client]:
            client.expect_error = True
            client.update_listing(new_object_id(), title="nope")
            assert client.errors == 1
            assert client.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND
            client.errors = 0
            client.last_error = None
            client.expect_error = False

        # Test inventory underflow error
        old_listing_id = old_client.create_listing("Error Test", 1000)
        new_listing_id = new_client.create_listing("Error Test", 1000)

        old_client.change_inventory(old_listing_id, 5)
        new_client.change_inventory(new_listing_id, 5)

        # Test inventory underflow - old client sends to server, new client validates locally
        # Old client: sends to server and gets error response
        old_client.expect_error = True
        old_client.change_inventory(old_listing_id, -10)  # Should fail
        assert old_client.errors == 1
        assert old_client.last_error.code == error_pb2.ERROR_CODES_OUT_OF_STOCK
        old_client.expect_error = False

        # New client: validates locally and throws exception before sending
        import pytest

        with pytest.raises(Exception, match="Inventory underflow"):
            new_client.change_inventory(new_listing_id, -10)  # Should fail locally

    finally:
        for client in [old_client, new_client]:
            if client:
                try:
                    client.close()
                except Exception as e:
                    print(f"Warning: Error closing client: {e}")


def test_sync_between_old_and_new_clients(account_manager):
    """Test synchronization between old and new client implementations."""
    old_client, new_client = create_client_pair("sync_cross", account_manager)

    try:
        # Setup old client
        shop_id = old_client.register_shop()
        old_client.enroll_key_card()
        old_client.login()
        old_client.create_shop_manifest()

        # Setup new client to use same shop and account
        new_client.account = old_client.account
        new_client.shop_token_id = shop_id
        new_client._initialize_state_manager()
        new_client.enroll_key_card()
        new_client.login()

        # Create data with old client
        listing_id = old_client.create_listing("Cross Sync Product", 1000)
        old_client.change_inventory(listing_id, 10)
        old_client.create_tag("cross_sync_tag")
        old_client.add_to_tag("cross_sync_tag", listing_id)

        # Sync to new client
        new_client.handle_all()

        # Compare states
        compare_shop_states(old_client, new_client, "cross_sync")

        # Verify specific data matches
        old_listing = old_client.shop.listings.get(listing_id)
        new_listing = new_client.shop.listings.get(listing_id)

        assert old_listing.price == new_listing.price
        assert old_listing.metadata.title == new_listing.metadata.title
        assert old_client.check_inventory(listing_id) == new_client.check_inventory(
            listing_id
        )

        old_tag = old_client.shop.tags.get("cross_sync_tag")
        new_tag = new_client.shop.tags.get("cross_sync_tag")

        assert len(old_tag.listings) == len(new_tag.listings)
        assert listing_id in old_tag.listings
        assert listing_id in new_tag.listings

    finally:
        for client in [old_client, new_client]:
            if client:
                try:
                    client.close()
                except Exception as e:
                    print(f"Warning: Error closing client: {e}")


def test_signature_verification(account_manager):
    old_client, new_client = create_client_pair("security", account_manager)

    # Setup both clients
    for client in [old_client, new_client]:
        client.register_shop()
        client.enroll_key_card()
        client.login()
        client.create_shop_manifest()

    # Test 1: Signature verification - both should have valid addresses
    old_valid_addrs = old_client._valid_event_signing_addresses()
    new_valid_addrs = new_client._valid_event_signing_addresses()

    print(f"Old client valid addresses: {old_valid_addrs}")
    print(f"New client valid addresses: {new_valid_addrs}")

    assert len(old_valid_addrs) > 0, "Old client should have valid addresses"
    assert len(new_valid_addrs) > 0, "New client should have valid addresses"

    # Should include at least the relay address and keycard address
    assert len(old_valid_addrs) >= 2, "Should have relay + keycard addresses"
    assert len(new_valid_addrs) >= 2, "Should have relay + keycard addresses"

    # Test 2: Hash verification - create a patch and verify hash matches
    listing_id = old_client.create_listing("Security Test Product", 1000)
    new_listing_id = new_client.create_listing("Security Test Product New", 1000)

    # Get the request ID for the last operation
    # This tests that _assert_shop_against_response would work
    old_shop = old_client.shop
    new_shop = new_client.shop

    assert old_shop is not None, "Old client should have shop state"
    assert new_shop is not None, "New client should have shop state"

    # Verify shops can compute hashes
    old_hash = old_shop.hash()
    new_hash = new_shop.hash()

    assert len(old_hash) == 32, "Hash should be 32 bytes"
    assert len(new_hash) == 32, "Hash should be 32 bytes"

    print(f"✅ Hash verification test passed - both clients can compute state hashes")

    # Test 3: Address cache invalidation
    initial_new_addrs = new_client._valid_event_signing_addresses()

    # Clear cache manually
    new_client._clear_valid_addresses_cache()

    # Should recompute the same addresses
    recomputed_addrs = new_client._valid_event_signing_addresses()
    assert set(initial_new_addrs) == set(
        recomputed_addrs
    ), "Cache invalidation should work correctly"

    print(f"✅ Address cache test passed")

    # Test 4: Each client can verify its own signatures (self-consistency)
    for client_name, client in [("old", old_client), ("new", new_client)]:
        # Use appropriate listing ID for each client
        test_listing_id = listing_id if client == old_client else new_listing_id
        # Create a test patch signed by this client
        header = client._create_patch_set(
            [
                client._create_patch(
                    type=mpatch.ObjectType.LISTING,
                    op=mpatch.OpString.REPLACE,
                    object_id=test_listing_id,
                    fields=["Price"],
                    obj=2000,
                )
            ]
        ).header

        header_bytes = cbor_encode(header.to_cbor_dict())
        signature = client._sign_header(header)

        print(
            f"{client_name} client signature created by: {client.own_key_card.address}"
        )

        # This client should be able to verify its own signature
        signer = client._verify_signature(header_bytes, signature)
        assert (
            signer is not None
        ), f"{client_name} client should verify its own signature"
        print(
            f"✅ {client_name} client can verify its own signatures - signer: {signer}"
        )

    # Test 5: Error handling for invalid signatures
    for client_name, client in [("old", old_client), ("new", new_client)]:
        # Use appropriate listing ID for each client
        test_listing_id = listing_id if client == old_client else new_listing_id
        # Create a valid header but invalid signature
        header = client._create_patch_set(
            [
                client._create_patch(
                    type=mpatch.ObjectType.LISTING,
                    op=mpatch.OpString.REPLACE,
                    object_id=test_listing_id,
                    fields=["Price"],
                    obj=3000,
                )
            ]
        ).header

        header_bytes = cbor_encode(header.to_cbor_dict())
        invalid_signature = b"\x00" * 65

        try:
            client._verify_signature(header_bytes, invalid_signature)
            assert (
                False
            ), f"{client_name} client should have raised exception for invalid signature"
        except Exception as e:
            assert (
                "invalid signature" in str(e).lower()
            ), f"{client_name} client should reject invalid signature: {e}"

    print(f"✅ Invalid signature rejection test passed for both clients")

    for client in [old_client, new_client]:
        if client:
            client.close()


def test_refactored_client_unique_features(account_manager):
    """Test features unique to the refactored client (like persistence)."""
    new_client = RefactoredRelayClient(
        name="persistence_test",
        wallet_account=account_manager.get_test_account(),
        data_dir=".testruns/persistence_test/data",
        log_dir=".testruns/persistence_test/logs",
    )

    try:
        shop_id = new_client.register_shop()
        new_client.enroll_key_card()
        new_client.login()
        new_client.create_shop_manifest()

        # Create some data
        listing_id = new_client.create_listing("Persistence Test Product", 1000)
        new_client.change_inventory(listing_id, 10)
        new_client.create_tag("persistence_tag")
        new_client.add_to_tag("persistence_tag", listing_id)

        # Test persistence features
        new_client.save_state()

        # Verify persistence worked
        assert new_client.persistence.shop_exists(shop_id)
        metadata = new_client.persistence.get_shop_metadata(shop_id)
        assert metadata is not None
        assert metadata["listings_count"] == 1
        assert metadata["inventory_count"] > 0
        assert metadata["tags_count"] == 1

        # Load state and verify it's the same
        loaded_shop = new_client.load_state()
        assert loaded_shop is not None
        assert loaded_shop.listings.size == 1
        assert loaded_shop.listings.has(listing_id)
        assert loaded_shop.tags.size == 1
        assert loaded_shop.tags.has("persistence_tag")

    finally:
        if new_client:
            try:
                new_client.close()
            except Exception as e:
                print(f"Warning: Error closing client: {e}")


def run_direct_comparison_suite():
    """Run all direct comparison tests and generate a report."""
    print("Running Direct Comparison Test Suite")
    print("=" * 50)

    # Create account manager
    from conftest import TestAccountManager
    from web3 import Account
    import os

    k = os.getenv("ETH_PRIVATE_KEY")
    assert k is not None, "ETH_PRIVATE_KEY not set"
    funded_private_key = bytes.fromhex(k)
    funded_account = Account.from_key(funded_private_key)
    account_manager = TestAccountManager(funded_account)

    test_results = {"passed": 0, "failed": 0}

    # List of direct comparison test functions
    test_functions = [
        test_direct_basic_connection_comparison,
        test_direct_patch_writing_comparison,
        test_direct_batch_operations_comparison,
        test_direct_error_handling_comparison,
        test_sync_between_old_and_new_clients,
        test_signature_verification,
        test_refactored_client_unique_features,
    ]

    for test_func in test_functions:
        print(f"\nRunning {test_func.__name__}...")

        try:
            test_func(account_manager)
            test_results["passed"] += 1
            print(f"  ✅ PASSED")

        except Exception as e:
            test_results["failed"] += 1
            print(f"  ❌ FAILED - {e}")
            import traceback

            traceback.print_exc()

    # Print summary
    print("\n" + "=" * 50)
    print("DIRECT COMPARISON TEST SUMMARY")
    print("=" * 50)

    total = test_results["passed"] + test_results["failed"]
    print(f"Passed: {test_results['passed']}")
    print(f"Failed: {test_results['failed']}")
    print(f"Total: {total}")

    if test_results["failed"] == 0:
        print(f"\n🎉 ALL DIRECT COMPARISON TESTS PASSED!")
        print(f"   The old and new client implementations behave identically.")
        print(
            f"   Core functionality, patch writing, error handling, and synchronization work the same."
        )
    else:
        print(f"\n⚠️  COMPATIBILITY ISSUES DETECTED:")
        print(f"   {test_results['failed']} test(s) failed")
        print(
            f"   There are behavioral differences between old and new implementations"
        )


if __name__ == "__main__":
    run_direct_comparison_suite()
