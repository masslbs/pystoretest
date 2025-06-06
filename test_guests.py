# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import cbor2
from pathlib import Path
import os
from pprint import pprint
import pytest
from typing import Callable, Tuple
from eth_keys.datatypes import PrivateKey, PublicKey

from massmarket import (
    subscription_pb2,
    error_pb2,
)

import massmarket.cbor.base_types as mbase
import massmarket.cbor.order as morder
import massmarket.cbor.manifest as mmanifest
import massmarket.cbor.patch as mpatch

from client import RelayClient, new_object_id

from test_orders import wait_for_finalization

def check_seed_data_path(seed_data_path: str | None) -> None:
    if seed_data_path is None:
        pytest.skip("TEST_MAKE_HYDRATION_DATA is not set")
        return
    if not Path(seed_data_path).exists():
        pytest.skip(f"TEST_MAKE_HYDRATION_DATA data file {seed_data_path} does not exist")
        return

def test_make_hydration_data(make_client: Callable[[str], RelayClient]):
    """
    Creates a shop with listings, inventory, and orders, then returns the shop owner client
    and a dictionary containing all the relevant IDs and keys for testing.

    This function can be used for hydration tests that assume test data is already present.
    """

    seed_data_path = os.getenv("TEST_MAKE_HYDRATION_DATA")
    check_seed_data_path(seed_data_path)

    # Create the shop owner
    owner: RelayClient = make_client("shop_owner")
    shop_id = owner.register_shop(token_id=1234)
    owner.enroll_key_card()
    owner.login()
    owner.create_shop_manifest()
    assert owner.errors == 0

    # Create some listings and inventory
    listing_ids = []
    for i, (name, price) in enumerate(
        [("Book", 1999), ("T-Shirt", 2499), ("Coffee Mug", 1499), ("Sticker Pack", 599)]
    ):
        listing_id = owner.create_listing(name, price)
        assert owner.errors == 0
        owner.change_inventory(listing_id, 100 - i * 10)  # Different inventory levels
        assert owner.errors == 0
        listing_ids.append(listing_id)

    # Create a customer one and place some orders
    cust1: RelayClient = make_client(
        "customer1", shop=shop_id, guest=True, private_key=os.urandom(32)
    )
    cust1.enroll_key_card()
    cust1.login(subscribe=False)
    cust1.subscribe(filters=[])
    assert cust1.errors == 0

    # Create first order with multiple items
    order_id1 = cust1.create_order()
    cust1.add_to_order(order_id1, listing_ids[0], 2)
    cust1.add_to_order(order_id1, listing_ids[1], 1)
    cust1.commit_items(order_id1)
    assert cust1.errors == 0

    # Create second order with a single item
    order_id2 = cust1.create_order()
    cust1.add_to_order(order_id2, listing_ids[2], 3)
    cust1.commit_items(order_id2)
    assert cust1.errors == 0

    # Create a second customer and have them place an order
    cust2: RelayClient = make_client(
        "customer2", shop=shop_id, guest=True, private_key=os.urandom(32)
    )
    cust2.enroll_key_card()
    cust2.login(subscribe=False)
    cust2.subscribe(filters=[])
    assert cust2.errors == 0

    order_id3 = cust2.create_order()
    cust2.add_to_order(order_id3, listing_ids[3], 5)
    cust2.commit_items(order_id3)
    assert cust2.errors == 0

    owner.handle_all()
    assert owner.errors == 0

    # Collect all the relevant data
    test_data = {
        "shop_id": shop_id,
        "shop_root": owner.shop.hash(),
        "owner_address": owner.account.address,
        "owner_wallet_private_key": owner.account.key,
        "owner_keycard_private_key": owner.own_key_card.key,
        "customer1_address": cust1.account.address,
        "customer1_wallet_private_key": cust1.account.key,
        "customer1_keycard_private_key": cust1.own_key_card.key,
        "customer2_address": cust2.account.address,
        "customer2_wallet_private_key": cust2.account.key,
        "customer2_keycard_private_key": cust2.own_key_card.key,
        "listing_ids": listing_ids,
        "order_ids": {
            "customer1_orders": [order_id1, order_id2],
            "customer2_order": order_id3,
        },
    }

    with open(seed_data_path, "wb") as f:
        import cbor2
        cbor2.dump(test_data, f)

    # Close customer and guest connections
    cust1.close()
    cust2.close()
    owner.close()


def skip_test_shop_hydration_from_cbor(make_client):
    """Test that we can hydrate a shop from CBOR data and access the expected data."""

    # Check if the CBOR file exists
    seed_data_path = os.getenv("TEST_MAKE_HYDRATION_DATA")
    check_seed_data_path(seed_data_path)

    # Load the test data from CBOR
    with open(seed_data_path, "rb") as f:
        test_data = cbor2.load(f)

    # Extract the data we need
    shop_id = test_data["shop_id"]
    shop_root = test_data["shop_root"]
    owner_address = test_data["owner_address"]
    owner_wallet_private_key = test_data["owner_wallet_private_key"]
    owner_keycard_private_key = test_data["owner_keycard_private_key"]
    customer_wallet_private_key = test_data["customer_wallet_private_key"]
    customer_keycard_private_key = test_data["customer_keycard_private_key"]
    guest_address = test_data["guest_address"]
    guest_wallet_private_key = test_data["guest_wallet_private_key"]
    guest_keycard_private_key = test_data["guest_keycard_private_key"]
    listing_ids = test_data["listing_ids"]
    order_ids = test_data["order_ids"]

    # Connect as the owner to verify shop data
    owner = RelayClient(
        name="owner",
        wallet_private_key=owner_wallet_private_key,
        key_card_private_key=owner_keycard_private_key,
    )
    owner.shop_token_id = shop_id
    owner.login()
    assert owner.errors == 0

    # Connect as the customer to verify their orders
    customer = RelayClient(
        name="customer",
        wallet_private_key=customer_wallet_private_key,
        key_card_private_key=customer_keycard_private_key,
    )
    customer.shop_token_id = shop_id
    customer.login(subscribe=False)
    customer.subscribe(filters=[])
    assert customer.errors == 0
    customer.handle_all()
    assert customer.errors == 0

    # Verify customer orders
    for order_id in order_ids["customer_orders"]:
        assert owner.shop.orders.has(
            order_id
        ), f"Customer order {order_id} not found in shop"

    assert customer.shop.orders.has(
        order_ids["customer_orders"][0]
    ), f"Customer order {order_ids['customer_orders'][0]} not found in customer shop"

    # Connect as the guest to verify their order
    guest = RelayClient(
        name="guest",
        guest=True,
        wallet_private_key=guest_wallet_private_key,
        key_card_private_key=guest_keycard_private_key,
    )
    guest.shop_token_id = shop_id
    guest.login(subscribe=False)
    guest.subscribe(filters=[])
    assert guest.errors == 0

    # Verify guest order
    guest_order_id = order_ids["guest_order"]
    assert owner.shop.orders.has(
        guest_order_id
    ), f"Guest order {guest_order_id} not found in shop"
    assert guest.shop.orders.has(
        guest_order_id
    ), f"Guest order {guest_order_id} not found in guest shop"

    # Verify the guest account exists
    import binascii

    guest_address = binascii.unhexlify(guest_address[2:])
    assert owner.shop.accounts.has(
        guest_address
    ), f"Guest account {guest_address} not found in shop"

    # Verify shop has the expected listings
    for listing_id in listing_ids:
        assert owner.shop.listings.has(
            listing_id
        ), f"Listing {listing_id} not found in shop"
        assert customer.shop.listings.has(
            listing_id
        ), f"Listing {listing_id} not found in customer shop"
        assert guest.shop.listings.has(
            listing_id
        ), f"Listing {listing_id} not found in guest shop"

    assert owner.shop.hash() == shop_root

    # Clean up connections
    owner.close()
    customer.close()
    guest.close()


def test_guest_subscribe_to_inventory_fails(make_client):
    # create the owner/clerk
    charlie = make_client("charlie")
    shop_id = charlie.register_shop()
    charlie.enroll_key_card()
    charlie.login()
    charlie.create_shop_manifest()
    assert charlie.errors == 0

    # create a guest without a keycard
    guest = make_client("guest1", shop=shop_id, guest=True, private_key=os.urandom(32))
    guest.connect()
    guest.expect_error = True
    guest.subscribe(
        [
            subscription_pb2.SubscriptionRequest.Filter(
                object_type="OBJECT_TYPE_INVENTORY"
            )
        ]
    )
    assert guest.errors == 1


def test_guest_subscribe_before_auth(make_client):
    # create the owner/clerk
    charlie = make_client("charlie")
    shop_id = charlie.register_shop()
    charlie.enroll_key_card()
    charlie.login()
    charlie.create_shop_manifest()
    assert charlie.errors == 0

    # create a guest without a keycard
    guest = make_client("guest", shop=shop_id, guest=True, private_key=os.urandom(32))
    guest.connect()
    guest.subscribe_visitor()
    guest.handle_all()
    assert guest.errors == 0

    # create a listing
    id = charlie.create_listing("book", 1)
    charlie.change_inventory(id, 10)
    assert charlie.errors == 0

    # fetch the listing
    guest.handle_all()
    assert guest.shop.listings.has(id)


def test_guest_subscribe_to_accounts(make_client):
    # create the owner/clerk
    clerk = make_client("clerk")
    shop_id = clerk.register_shop()
    clerk.enroll_key_card()
    clerk.login()
    clerk.create_shop_manifest()
    assert clerk.errors == 0

    # create a guest without a keycard
    guest = make_client("guest", shop=shop_id, guest=True, private_key=os.urandom(32))
    guest.connect()
    guest.handle_all()
    assert guest.errors == 0

    guest.subscribe(
        [subscription_pb2.SubscriptionRequest.Filter(object_type="OBJECT_TYPE_ACCOUNT")]
    )
    assert guest.errors == 0

    # check both received the keycard from clerk
    guest.handle_all()
    assert len(guest.all_key_cards) == 1
    clerk.handle_all()
    assert len(clerk.all_key_cards) == 1

    # once guest enrolls, clerk should receive the keycard too
    guest.enroll_key_card()
    guest.handle_all()
    clerk.handle_all()
    assert len(guest.all_key_cards) == 2
    assert len(clerk.all_key_cards) == 2
    guest_account = clerk.shop.accounts.get(bytes(20))
    assert guest_account is not None
    guests_keycard_public_key = PrivateKey(guest.own_key_card.key).public_key.to_compressed_bytes().hex()
    hexKeys = [k.key.hex() for k in guest_account.keycards]
    assert guests_keycard_public_key in hexKeys


def test_guest_subscribe_orders_needs_auth(make_client):
    # create the owner/clerk
    charlie = make_client("charlie")
    assert isinstance(charlie, RelayClient)
    shop_id = charlie.register_shop()
    charlie.enroll_key_card()
    charlie.login()
    charlie.create_shop_manifest()
    assert charlie.errors == 0

    # create a guest without a keycard
    guest = make_client("guest", shop=shop_id, guest=True, private_key=os.urandom(32))
    guest.connect()
    assert isinstance(guest, RelayClient)
    assert guest.errors == 0

    # make sure we cant subscribe to orders yet
    guest.expect_error = True
    guest.subscribe_order()
    assert guest.errors == 1

    # reset error state
    guest.expect_error = False
    guest.errors = 0

    # make a guest keycard
    guest.enroll_key_card()
    guest.authenticate()

    # now we should
    guest.subscribe_order()
    assert guest.errors == 0


def test_guest_user_create_order(
    make_two_guests: Tuple[RelayClient, RelayClient, RelayClient],
):
    clerk, guest1, guest2 = make_two_guests
    assert guest1.shop is not None
    assert guest2.shop is not None
    assert clerk.shop is not None

    id = clerk.create_listing("book", 1)
    clerk.change_inventory(id, 10)
    assert clerk.errors == 0

    # guest1 adds an item to their order
    order_id = guest1.create_order()
    assert guest1.errors == 0
    order = guest1.shop.orders.get(order_id)
    assert order is not None
    assert len(order.items) == 0
    guest1.add_to_order(order_id, id, 1)
    assert guest1.errors == 0
    assert len(order.items) == 1

    # guest2 tries to view guest1's order
    guest2.handle_all()
    assert not guest2.shop.orders.has(order_id)


def test_guest_commit_other_users_order(
    make_two_guests: Tuple[RelayClient, RelayClient, RelayClient],
):
    clerk, guest1, guest2 = make_two_guests

    id = clerk.create_listing("book", 1)
    clerk.change_inventory(id, 10)
    assert clerk.errors == 0

    order1 = guest1.create_order()
    assert guest1.errors == 0
    guest1.add_to_order(order1, id, 2)
    assert guest1.errors == 0

    # guest2 tries to commit guest1's order
    guest2.expect_error = True
    guest2.commit_items(order1)
    assert guest2.errors == 1
    assert guest2.last_error is not None
    assert guest2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND
    # reset error state
    guest2.errors = 0
    guest2.last_error = None

    # now guest1 commits it for the next test step
    guest1.commit_items(order1)
    assert guest1.errors == 0
    addr = morder.AddressDetails(
        name="Max Mustermann",
        address1="Somestreet 1",
        city="City",
        postal_code="12345",
        country="Isla de Muerta",
        phone_number="+0155512345",
        email_address="some1@no.where",
    )
    guest1.update_address_for_order(order1, invoice=addr)
    guest1.choose_payment(order1, payee=clerk.default_payee)
    assert guest1.errors == 0

    order = wait_for_finalization(guest1, order1)
    int_total = int(order.payment_details.total)
    assert int_total == 2
    # order has payment details
    pr = {
        "ttl": int(order.payment_details.ttl),
        "order": bytes(32),
        "currency": clerk.default_currency.address.to_bytes(),
        "amount": int_total,
        "payeeAddress": clerk.default_payee.address.address.to_bytes(),
        "chainId": clerk.chain_id,
        "isPaymentEndpoint": False,
        "shopId": int(clerk.shop_token_id),
        "shopSignature": "0x" + "00" * 64,
    }
    pprint(pr)

    gotPaymentId = guest1.payments.functions.getPaymentId(pr).call()
    assert gotPaymentId.to_bytes(32, "big") == order.payment_details.payment_id

    # guest2 tries to abandon guest1's order
    guest2.abandon_order(order1)
    assert guest2.errors > 0
    assert guest2.last_error is not None
    assert guest2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_guest_cannot_create_listing(make_two_guests):
    _, guest1, _ = make_two_guests
    assert isinstance(guest1, RelayClient)
    assert guest1.shop is not None

    guest1.expect_error = True
    guest1.create_listing("unauthorized_item", 1000)
    assert guest1.errors == 1
    assert guest1.last_error is not None
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_guest_cannot_update_listing(make_two_guests):
    clerk, guest1, _ = make_two_guests

    id = clerk.create_listing("book", 1)
    clerk.change_inventory(id, 10)
    assert clerk.errors == 0

    guest1.expect_error = True
    new_price = mbase.Uint256(value=1)
    guest1.update_listing(id, price=new_price)
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_guest_cannot_create_or_update_tag(make_two_guests):
    clerk, guest1, _ = make_two_guests

    guest1.expect_error = True
    tag_id = guest1.create_tag("unauthorized_tag")
    assert guest1.errors == 1
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset errors
    guest1.errors = 0
    guest1.last_error = None

    # Assume clerk creates a tag
    clerk.create_tag("actual tag")
    assert clerk.errors == 0

    guest1.expect_error = True
    guest1.add_to_tag("actual tag", new_object_id())
    assert guest1.errors == 1
    assert guest1.last_error is not None
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_guest_cannot_create_or_update_shop_manifest(make_two_guests):
    _, guest1, _ = make_two_guests
    assert isinstance(guest1, RelayClient)
    assert guest1.shop is not None

    guest1.expect_error = True
    sm = mmanifest.Manifest(
        shop_id=mbase.Uint256(value=guest1.shop_token_id),
        pricing_currency=guest1.default_currency,
        accepted_currencies={
            guest1.chain_id: {guest1.default_currency.address},
        },
        payees={
            guest1.chain_id: {
                guest1.default_payee.address.address: mbase.PayeeMetadata(
                    call_as_contract=False
                )
            },
        },
    )
    guest1._write_patch(
        type=mpatch.ObjectType.MANIFEST,
        obj=sm,
        op=mpatch.OpString.REPLACE,
    )
    assert guest1.errors == 1
    assert guest1.last_error is not None
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset errors
    guest1.errors = 0
    guest1.last_error = None

    p = mbase.Payee(
        address=mbase.ChainAddress(
            address=mbase.EthereumAddress(value=guest1.default_payee.address.address),
            chain_id=guest1.chain_id,
        ),
        call_as_contract=False,
    )
    guest1.update_shop_manifest(add_payee=p)
    assert guest1.errors == 1
    assert guest1.last_error is not None
    assert guest1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_guest_subscribe_empty_filter_no_private_data(make_client):
    # create the owner/clerk
    charlie = make_client("charlie")
    assert isinstance(charlie, RelayClient)
    shop_id = charlie.register_shop()
    charlie.enroll_key_card()
    charlie.login()
    charlie.create_shop_manifest()
    assert charlie.errors == 0

    # Add some inventory items
    id = charlie.create_listing("Test Item", 10)
    assert charlie.errors == 0
    charlie.change_inventory(id, 500)
    assert charlie.errors == 0
    charlie.close()

    # Create another customer and place an order
    customer: RelayClient = make_client(
        "customer", shop=shop_id, guest=True, private_key=os.urandom(32)
    )
    customer.enroll_key_card()
    customer.login(subscribe=False)
    customer.subscribe_customer()
    customer.handle_all()
    assert customer.errors == 0
    customer.start_batch()
    customer.expect_error = True
    order_id = customer.create_order(wait=False)
    customer.add_to_order(order_id, id, 123)
    customer.commit_items(order_id)
    customer.expect_error = False
    customer.flush_batch()
    assert customer.errors == 0
    customer.close()

    # create a guest without a keycard
    guest: RelayClient = make_client(
        "guest", shop=shop_id, guest=True, private_key=os.urandom(32)
    )
    guest.debug = True
    guest.connect()
    assert isinstance(guest, RelayClient)

    # Subscribe with empty filter
    guest.subscribe(filters=[])
    assert guest.errors == 0
    guest.handle_all()
    assert guest.errors == 0

    # Verify the guest can't see private inventory details
    assert guest.shop.listings.has(id)

    assert not guest.shop.inventory.has(id)

    # Verify the guest can't see other people's orders
    assert not guest.shop.orders.has(order_id)
