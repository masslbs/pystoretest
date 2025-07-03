# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import os
import pytest
import time
import tempfile
import shutil


from massmarket_client.client import RefactoredRelayClient
from massmarket_client.persistence import ShopPersistence


@pytest.fixture
def temp_persistence_dir():
    """Create a temporary directory for persistence testing."""
    temp_dir = tempfile.mkdtemp(prefix="test_persistence_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def make_refactored_client(account_manager, temp_persistence_dir):
    """Create a refactored client with persistence in a temporary directory."""
    created_clients = []

    def _make_client(
        name: str,
        shop_id=None,
        data_dir=None,
        log_dir=None,
        guest: bool = False,
        private_key: bytes = None,
        auto_connect: bool = True,
        validate_patches: bool = True,
    ):
        if data_dir is None:
            data_dir = os.path.join(temp_persistence_dir, f"{name}_data")
        if log_dir is None:
            log_dir = os.path.join(temp_persistence_dir, f"{name}_logs")

        acc = None
        if not private_key:
            acc = account_manager.get_test_account()

        client = RefactoredRelayClient(
            name=name,
            guest=guest,
            wallet_account=acc,
            wallet_private_key=private_key,
            auto_connect=auto_connect,
            validate_patches=validate_patches,
            data_dir=data_dir,
            log_dir=log_dir,
        )

        if shop_id is not None:
            client.shop_token_id = shop_id
            client._initialize_state_manager()

        created_clients.append(client)
        return client

    yield _make_client

    for client in created_clients:
        client.close()
    print(f"{len(created_clients)} refactored clients closed")


def test_basic_persistence_save_load(make_refactored_client, temp_persistence_dir):
    """Test basic shop persistence save and load functionality."""
    # Create a client and set up a shop
    client = make_refactored_client("alice")
    shop_id = client.register_shop()
    client.enroll_key_card()
    client.login()
    client.handle_all()

    # Create some shop data
    client.create_shop_manifest()
    listing_id = client.create_listing("Test Item", 1000)
    client.create_tag("electronics")
    client.add_to_tag("electronics", listing_id)
    client.change_inventory(listing_id, 50)

    assert client.errors == 0
    assert client.shop is not None
    assert client.shop.listings.size == 1
    assert client.shop.tags.size == 1

    # Save shop state manually
    client.state_manager.save_shop()

    # Create a new persistence instance and load the shop
    persistence = ShopPersistence(os.path.join(temp_persistence_dir, "alice_data"))
    loaded_shop = persistence.load_shop(shop_id)

    assert loaded_shop is not None
    assert loaded_shop.listings.size == 1
    assert loaded_shop.tags.size == 1

    # Verify listing data matches
    original_listing = client.shop.listings.get(listing_id)
    loaded_listing = loaded_shop.listings.get(listing_id)
    assert loaded_listing is not None
    assert loaded_listing.metadata.title == original_listing.metadata.title
    assert loaded_listing.price == original_listing.price

    # Verify tag data matches
    original_tag = client.shop.tags.get("electronics")
    loaded_tag = loaded_shop.tags.get("electronics")
    assert loaded_tag is not None
    assert loaded_tag.listings == original_tag.listings

    client.close()


def test_client_reconnection_with_events_during_disconnect(make_refactored_client):
    """Test that a client can reconnect and sync events that happened while disconnected."""
    # Create first client (alice1) and set up shop
    alice1 = make_refactored_client("alice1")
    shop_id = alice1.register_shop()
    alice1.enroll_key_card()
    alice1.login()
    alice1.handle_all()

    # Create basic shop data
    alice1.create_shop_manifest()
    assert alice1.errors == 0

    # Create second client (alice2) using same account but different keycard
    alice2 = make_refactored_client(
        "alice2", shop_id=shop_id, private_key=alice1.account.key
    )
    alice2.enroll_key_card()
    alice2.login()
    alice2.handle_all()

    # Verify both clients see the same initial state
    assert alice2.errors == 0
    assert alice1.shop.manifest.shop_id == alice2.shop.manifest.shop_id

    # Alice2 goes offline (close connection but keep state)
    alice2.close()

    # Alice1 creates events while alice2 is offline
    listing1_id = alice1.create_listing("Laptop", 150000)
    listing2_id = alice1.create_listing("Mouse", 2500)
    alice1.create_tag("computers")
    alice1.add_to_tag("computers", listing1_id)
    alice1.change_inventory(listing1_id, 5)
    alice1.change_inventory(listing2_id, 20)

    assert alice1.errors == 0
    assert alice1.shop.listings.size == 2
    assert alice1.shop.tags.size == 1

    # Alice2 reconnects (create new client instance with same data directory)
    alice2_reconnected = make_refactored_client(
        "alice2_reconnected",
        shop_id=shop_id,
        data_dir=alice2.persistence.data_dir,
        log_dir=alice2.patch_logger.log_dir,
        private_key=alice1.account.key,
    )
    alice2_reconnected.enroll_key_card()
    alice2_reconnected.login()

    # Wait for synchronization
    max_retries = 20
    retries = 0
    while alice2_reconnected.shop.listings.size < 2 and retries < max_retries:
        alice2_reconnected.handle_all()
        time.sleep(0.5)
        retries += 1

    # Verify alice2 caught up with all changes
    assert alice2_reconnected.errors == 0
    assert alice2_reconnected.shop.listings.size == 2
    assert alice2_reconnected.shop.tags.size == 1

    # Verify specific listing data matches
    alice1_laptop = alice1.shop.listings.get(listing1_id)
    alice2_laptop = alice2_reconnected.shop.listings.get(listing1_id)
    assert alice2_laptop is not None
    assert alice2_laptop.metadata.title == alice1_laptop.metadata.title
    assert alice2_laptop.price == alice1_laptop.price

    # Verify tag consistency
    alice1_tag = alice1.shop.tags.get("computers")
    alice2_tag = alice2_reconnected.shop.tags.get("computers")
    assert alice2_tag is not None
    assert alice2_tag.listings == alice1_tag.listings

    alice1.close()
    alice2_reconnected.close()


def test_state_consistency_after_multiple_disconnections(make_refactored_client):
    """Test state consistency when multiple clients disconnect and reconnect at different times."""
    # Create initial client and shop
    alice = make_refactored_client("alice")
    shop_id = alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.handle_all()
    alice.create_shop_manifest()

    # Create two additional clients
    bob = make_refactored_client("bob", shop_id=shop_id, private_key=alice.account.key)
    bob.enroll_key_card()
    bob.login()
    bob.handle_all()

    charlie = make_refactored_client(
        "charlie", shop_id=shop_id, private_key=alice.account.key
    )
    charlie.enroll_key_card()
    charlie.login()
    charlie.handle_all()

    # All clients should see the initial manifest
    assert alice.errors == 0
    assert bob.errors == 0
    assert charlie.errors == 0

    # Phase 1: Alice creates some items while Bob and Charlie are online
    listing1_id = alice.create_listing("Book", 2000)
    alice.create_tag("education")
    alice.add_to_tag("education", listing1_id)

    # Let everyone sync
    for client in [alice, bob, charlie]:
        client.handle_all()

    assert alice.shop.listings.size == 1
    assert bob.shop.listings.size == 1
    assert charlie.shop.listings.size == 1

    # Phase 2: Bob disconnects, Alice and Charlie continue
    bob_data_dir = bob.persistence.data_dir
    bob_log_dir = bob.patch_logger.log_dir
    bob.close()

    listing2_id = alice.create_listing("Pen", 500)
    alice.change_inventory(listing2_id, 100)
    charlie.handle_all()

    assert alice.shop.listings.size == 2
    assert charlie.shop.listings.size == 2

    # Phase 3: Charlie disconnects, Alice continues alone
    charlie_data_dir = charlie.persistence.data_dir
    charlie_log_dir = charlie.patch_logger.log_dir
    charlie.close()

    listing3_id = alice.create_listing("Notebook", 1500)
    alice.update_listing(listing1_id, price=2500)  # Update existing item

    assert alice.shop.listings.size == 3

    # Phase 4: Bob reconnects (should see listings 1, 2, 3)
    bob_reconnected = make_refactored_client(
        "bob_reconnected",
        shop_id=shop_id,
        data_dir=bob_data_dir,
        log_dir=bob_log_dir,
        private_key=alice.account.key,
    )
    bob_reconnected.enroll_key_card()
    bob_reconnected.login()

    # Wait for Bob to sync
    max_retries = 20
    retries = 0
    while bob_reconnected.shop.listings.size < 3 and retries < max_retries:
        bob_reconnected.handle_all()
        time.sleep(0.5)
        retries += 1

    assert bob_reconnected.errors == 0
    assert bob_reconnected.shop.listings.size == 3

    # Phase 5: Charlie reconnects (should see all listings)
    charlie_reconnected = make_refactored_client(
        "charlie_reconnected",
        shop_id=shop_id,
        data_dir=charlie_data_dir,
        log_dir=charlie_log_dir,
        private_key=alice.account.key,
    )
    charlie_reconnected.enroll_key_card()
    charlie_reconnected.login()

    # Wait for Charlie to sync
    retries = 0
    while charlie_reconnected.shop.listings.size < 3 and retries < max_retries:
        charlie_reconnected.handle_all()
        time.sleep(0.5)
        retries += 1

    assert charlie_reconnected.errors == 0
    assert charlie_reconnected.shop.listings.size == 3

    # Verify all clients have consistent state
    for listing_id in [listing1_id, listing2_id, listing3_id]:
        alice_listing = alice.shop.listings.get(listing_id)
        bob_listing = bob_reconnected.shop.listings.get(listing_id)
        charlie_listing = charlie_reconnected.shop.listings.get(listing_id)

        assert alice_listing is not None
        assert bob_listing is not None
        assert charlie_listing is not None

        # Check prices match (including the updated price for listing1)
        assert alice_listing.price == bob_listing.price == charlie_listing.price
        assert (
            alice_listing.metadata.title
            == bob_listing.metadata.title
            == charlie_listing.metadata.title
        )

    # Verify updated price was properly synced
    updated_listing = charlie_reconnected.shop.listings.get(listing1_id)
    assert updated_listing.price == 2500  # Updated price

    alice.close()
    bob_reconnected.close()
    charlie_reconnected.close()


def test_patch_logging_and_replay_functionality(
    make_refactored_client, temp_persistence_dir
):
    """Test that patch operations are properly logged and can be replayed."""
    client = make_refactored_client("alice")
    shop_id = client.register_shop()
    client.enroll_key_card()
    client.login()
    client.handle_all()

    # Create shop data that generates patches
    client.create_shop_manifest()
    listing_id = client.create_listing("Test Product", 5000)
    client.update_listing(listing_id, title="Updated Product")
    client.update_listing(listing_id, price=6000)
    client.change_inventory(listing_id, 10)

    assert client.errors == 0

    # Force save to ensure patches are logged
    client.state_manager.save_shop()

    # Check that patch log file exists
    log_files = list(client.patch_logger.log_dir.glob("*.cbor"))
    assert len(log_files) > 0, "No patch log files found"

    # Read and verify patch log content
    import cbor2

    with open(log_files[0], "rb") as f:
        log_data = cbor2.loads(f.read())

    assert isinstance(log_data, list)
    assert len(log_data) > 0

    # Check log structure
    header = log_data[0]
    assert header["type"] == "session_header"
    assert header["client_name"] == "alice"
    assert header["shop_id"] == shop_id

    # Count patch entries
    patch_entries = [entry for entry in log_data if entry.get("type") == "patch"]
    assert len(patch_entries) > 0, "No patch entries found in log"

    client.close()


def test_persistence_with_order_operations(make_refactored_client):
    """Test persistence with order creation and modification operations."""
    # Create client and shop
    alice = make_refactored_client("alice")
    shop_id = alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.handle_all()

    alice.create_shop_manifest()
    listing_id = alice.create_listing("Product", 1000)
    alice.change_inventory(listing_id, 50)

    # Create an order
    order_id = alice.create_order()
    alice.add_to_order(order_id, listing_id, 2)

    assert alice.errors == 0
    assert alice.shop.orders.size == 1

    # Save state and close
    alice.state_manager.save_shop()
    alice_data_dir = alice.persistence.data_dir
    alice_log_dir = alice.patch_logger.log_dir
    alice.close()

    # Create new client instance and verify order persisted
    alice_reconnected = make_refactored_client(
        "alice_reconnected",
        shop_id=shop_id,
        data_dir=alice_data_dir,
        log_dir=alice_log_dir,
        private_key=alice.account.key,
    )
    alice_reconnected.enroll_key_card()
    alice_reconnected.login()
    alice_reconnected.handle_all()

    assert alice_reconnected.errors == 0
    assert alice_reconnected.shop.orders.size == 1

    # Verify order details
    order = alice_reconnected.shop.orders.get(order_id)
    assert order is not None
    assert len(order.items) == 1
    assert order.items[0].listing_id == listing_id
    assert order.items[0].quantity == 2

    alice_reconnected.close()


def test_persistence_metadata_tracking(make_refactored_client, temp_persistence_dir):
    """Test that persistence metadata is correctly tracked and maintained."""
    client = make_refactored_client("alice")
    shop_id = client.register_shop()
    client.enroll_key_card()
    client.login()
    client.handle_all()

    client.create_shop_manifest()
    listing1_id = client.create_listing("Product 1", 1000)
    client.create_listing("Product 2", 2000)
    client.create_tag("category1")
    client.add_to_tag("category1", listing1_id)

    # Save and get metadata
    client.state_manager.save_shop()
    metadata = client.persistence.get_shop_metadata(shop_id)

    assert metadata is not None
    assert metadata["shop_id"] == shop_id
    assert metadata["schema_version"] == 5
    assert metadata["listings_count"] == 2
    assert metadata["tags_count"] == 1
    assert "last_updated" in metadata

    # Check that shop exists
    assert client.persistence.shop_exists(shop_id)

    # Check shop listing
    shop_ids = client.persistence.list_shops()
    assert shop_id in shop_ids

    client.close()


def test_persistence_with_complex_listing_updates(make_refactored_client):
    """Test persistence with complex listing operations like options and variations."""
    alice = make_refactored_client("alice")
    shop_id = alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.handle_all()

    alice.create_shop_manifest()
    listing_id = alice.create_listing("T-Shirt", 2500)

    # Add options and variations
    from massmarket.cbor.listing import ListingOption, ListingVariation, ListingMetadata

    # Create size option with variations
    size_option = ListingOption(
        title="Size",
        variations={
            "S": ListingVariation(
                variation_info=ListingMetadata(title="Small", description="Small size")
            ),
            "M": ListingVariation(
                variation_info=ListingMetadata(
                    title="Medium", description="Medium size"
                )
            ),
            "L": ListingVariation(
                variation_info=ListingMetadata(title="Large", description="Large size")
            ),
        },
    )

    alice.update_listing(listing_id, add_option=("Size", size_option))
    alice.update_listing(
        listing_id,
        add_variation=(
            "Size",
            (
                "XL",
                ListingVariation(
                    variation_info=ListingMetadata(
                        title="Extra Large", description="Extra large size"
                    )
                ),
            ),
        ),
    )

    # Add inventory for variations
    alice.change_inventory(listing_id, 10, variations=["S"])
    alice.change_inventory(listing_id, 15, variations=["M"])
    alice.change_inventory(listing_id, 8, variations=["L"])

    assert alice.errors == 0

    # Save and reconnect
    alice.state_manager.save_shop()
    alice_data_dir = alice.persistence.data_dir
    alice_log_dir = alice.patch_logger.log_dir
    alice.close()

    # Reconnect and verify complex data persisted
    alice_reconnected = make_refactored_client(
        "alice_reconnected",
        shop_id=shop_id,
        data_dir=alice_data_dir,
        log_dir=alice_log_dir,
        private_key=alice.account.key,
    )
    alice_reconnected.enroll_key_card()
    alice_reconnected.login()
    alice_reconnected.handle_all()

    assert alice_reconnected.errors == 0

    # Verify listing with options persisted
    listing = alice_reconnected.shop.listings.get(listing_id)
    assert listing is not None
    assert listing.options is not None
    assert "Size" in listing.options
    assert len(listing.options["Size"].variations) == 4  # S, M, L, XL

    # Verify inventory variations persisted
    assert alice_reconnected.check_inventory(listing_id, ["S"]) == 10
    assert alice_reconnected.check_inventory(listing_id, ["M"]) == 15
    assert alice_reconnected.check_inventory(listing_id, ["L"]) == 8

    alice_reconnected.close()


def test_persistence_cleanup_and_deletion(make_refactored_client):
    """Test shop deletion and cleanup operations."""
    client = make_refactored_client("alice")
    shop_id = client.register_shop()
    client.enroll_key_card()
    client.login()
    client.handle_all()

    client.create_shop_manifest()
    client.create_listing("Test Item", 1000)

    # Save shop
    client.state_manager.save_shop()

    # Verify shop exists
    assert client.persistence.shop_exists(shop_id)
    assert client.persistence.get_shop_metadata(shop_id) is not None

    # Delete shop
    deleted = client.persistence.delete_shop(shop_id)
    assert deleted

    # Verify shop no longer exists
    assert not client.persistence.shop_exists(shop_id)
    assert client.persistence.get_shop_metadata(shop_id) is None
    assert client.persistence.load_shop(shop_id) is None

    client.close()


def test_concurrent_client_operations_with_persistence(make_refactored_client):
    """Test that concurrent operations from multiple clients maintain consistency."""
    # Create initial client
    alice = make_refactored_client("alice")
    shop_id = alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.handle_all()
    alice.create_shop_manifest()

    # Create second client
    bob = make_refactored_client("bob", shop_id=shop_id, private_key=alice.account.key)
    bob.enroll_key_card()
    bob.login()
    bob.handle_all()

    # Both clients perform operations
    alice.create_listing("Alice's Item", 1000)
    bob.create_listing("Bob's Item", 2000)

    alice.create_tag("alice-tag")
    bob.create_tag("bob-tag")

    # Let both sync
    for _ in range(5):
        alice.handle_all()
        bob.handle_all()
        time.sleep(0.1)

    assert alice.errors == 0
    assert bob.errors == 0

    # Both should see both listings and tags
    assert alice.shop.listings.size == 2
    assert bob.shop.listings.size == 2
    assert alice.shop.tags.size == 2
    assert bob.shop.tags.size == 2

    # Save state from both clients
    alice.state_manager.save_shop()
    bob.state_manager.save_shop()

    # Close and reconnect both
    alice_data_dir = alice.persistence.data_dir
    alice_log_dir = alice.patch_logger.log_dir
    bob_data_dir = bob.persistence.data_dir
    bob_log_dir = bob.patch_logger.log_dir

    alice.close()
    bob.close()

    # Reconnect and verify consistency
    alice_new = make_refactored_client(
        "alice_new",
        shop_id=shop_id,
        data_dir=alice_data_dir,
        log_dir=alice_log_dir,
        private_key=alice.account.key,
    )
    alice_new.enroll_key_card()
    alice_new.login()
    alice_new.handle_all()

    bob_new = make_refactored_client(
        "bob_new",
        shop_id=shop_id,
        data_dir=bob_data_dir,
        log_dir=bob_log_dir,
        private_key=alice.account.key,
    )  # Same account
    bob_new.enroll_key_card()
    bob_new.login()
    bob_new.handle_all()

    # Wait for sync
    for _ in range(10):
        alice_new.handle_all()
        bob_new.handle_all()
        time.sleep(0.1)

    assert alice_new.errors == 0
    assert bob_new.errors == 0
    assert alice_new.shop.listings.size == 2
    assert bob_new.shop.listings.size == 2
    assert alice_new.shop.tags.size == 2
    assert bob_new.shop.tags.size == 2

    alice_new.close()
    bob_new.close()
