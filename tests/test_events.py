# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import os
import pytest
import time
import datetime
from typing import Tuple

from massmarket import (
    get_root_hash_of_patches,
    base_types_pb2 as old_pb_types,
    error_pb2,
    subscription_pb2,
)
import massmarket.cbor.patch as mpatch
import massmarket.cbor.base_types as mbase
import massmarket.cbor.listing as mlisting
import massmarket.cbor.order as morder
from massmarket_client.legacy_client import RelayClient
from massmarket_client.utils import RelayException
from massmarket_client.utils import new_object_id, vid
from massmarket_client import RelayClientProtocol
from tests.conftest import MakeClientCallable


def test_helper_vid():
    assert vid(23) == "23:"
    assert vid(23, None) == "23:"
    assert vid(1, ["2"]) == "1:2:"
    assert vid(1, ["2", "3"]) == "1:2:3:"
    assert vid(1, ["3", "2"]) == "1:2:3:"


def test_event_nonce_collision(wc_auth: RelayClientProtocol):
    wc_auth.create_shop_manifest()
    assert wc_auth.errors == 0

    patch = mpatch.Patch(
        path=mpatch.PatchPath(
            type=mpatch.ObjectType.MANIFEST,
            fields=["Payees", "foo"],
        ),
        op=mpatch.OpString.ADD,
        value=mbase.Payee(
            address=mbase.ChainAddress(
                address=os.urandom(20),
                chain_id=wc_auth.chain_id,
            ),
            call_as_contract=True,
        ),
    )

    # need to copy a bit of code from _create_event
    header = mpatch.PatchSetHeader(
        key_card_nonce=1,  # already used
        shop_id=mbase.Uint256(wc_auth.shop_token_id),
        timestamp=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0),
        root_hash=get_root_hash_of_patches([patch]),
    )

    signature = wc_auth._sign_header(header)

    sig_pset = mpatch.SignedPatchSet(
        header=header,
        signature=signature,
        patches=[patch],
    )
    with pytest.raises(RelayException):
        wc_auth._send_signed_patch(sig_pset)
    wc_auth.close()


def test_clerk_update_shop_manifest(wc_auth: RelayClientProtocol):
    wc_auth.create_shop_manifest()
    wc_auth.debug = True
    assert wc_auth.errors == 0
    wc_auth.handle_all()
    curr = mbase.ChainAddress(
        address=wc_auth.erc20Token.address, chain_id=wc_auth.chain_id
    )
    wc_auth.update_shop_manifest(add_currency=curr)
    assert wc_auth.errors == 0
    wc_auth.update_shop_manifest(remove_currency=curr)
    assert wc_auth.errors == 0
    p = mbase.Payee(
        address=mbase.ChainAddress(address=os.urandom(20), chain_id=wc_auth.chain_id),
        call_as_contract=True,
    )
    wc_auth.update_shop_manifest(add_payee=p)
    assert wc_auth.errors == 0
    wc_auth.update_shop_manifest(remove_payee=p)
    # TODO: re-enable once relay checks for existence of ERC20s
    # wc_auth.expect_error = True
    # rand_curr = mcbor.ChainAddress(
    #     address=os.urandom(20),
    #     chain_id=wc_auth.chain_id,
    # )
    # wc_auth.update_shop_manifest(add_currency=rand_curr)
    # assert wc_auth.errors == 1
    # wc_auth.expect_error = False
    wc_auth.close()


def test_clerk_sync_shop_manifest(
    make_two_clients: Tuple[RelayClientProtocol, RelayClientProtocol],
):
    a1, a2 = make_two_clients
    assert a1.shop is not None
    assert a2.shop is not None
    assert a1.shop.manifest.payees == a2.shop.manifest.payees
    assert len(a1.shop.manifest.payees) == 1
    assert len(a2.shop.manifest.payees) == 1

    # a1 writes events
    new_payee = mbase.Payee(
        address=mbase.ChainAddress(address=os.urandom(20), chain_id=a1.chain_id),
        call_as_contract=True,
    )
    a1.update_shop_manifest(add_payee=new_payee)
    a1.handle_all()
    assert a1.errors == 0
    assert len(a1.shop.manifest.payees[a1.chain_id]) == 2
    # a2 syncs the event
    a2.handle_all()
    assert a2.errors == 0
    assert a2.shop is not None
    assert len(a2.shop.manifest.payees[a1.chain_id]) == 2


def test_clerk_write_and_sync_later(make_client: MakeClientCallable):
    # both alices share the same private wallet but have different keycards
    a1 = make_client("alice.1")
    shop_id = a1.register_shop()
    a1.enroll_key_card()
    a1.login()
    a1.handle_all()
    assert a1.errors == 0

    # a1 writes an a few events
    a1.create_shop_manifest()
    a1.create_listing("shoes", 1000)
    assert a1.errors == 0

    print("connecting alice.2")

    # a2 connects after a1 has written events
    a2 = make_client("alice.2")
    # a2.debug = True
    a2.account = a1.account
    a2.shop_token_id = shop_id
    a2.enroll_key_card()
    a2.login()
    assert a2.errors == 0
    assert a2.shop is not None
    retries = 10
    while a2.shop.listings.size < 1 and retries > 0:
        time.sleep(1)
        a2.handle_all()
        retries -= 1
    assert a2.shop.listings.size == 1


# TODO: rethink this. Now the manifest creates the initial manifest.
def skip_test_clerk_manifest_first(make_client: MakeClientCallable):
    a1 = make_client("alice.1")
    a1.register_shop()
    a1.enroll_key_card()
    a1.login()
    a1.handle_all()
    assert a1.errors == 0

    def reset():
        assert a1.errors == 1
        assert a1.last_error is not None
        assert a1.last_error.code == error_pb2.ERROR_CODES_INVALID
        a1.errors = 0
        a1.last_error = None

    a1.expect_error = True

    rand_curr = mbase.ChainAddress(
        address=mbase.EthereumAddress(os.urandom(20)),
        chain_id=a1.chain_id,
    )
    a1.update_shop_manifest(add_currency=rand_curr)
    reset()
    print("tried to update manifest")

    a1.create_listing("foo", 22)
    reset()
    print("tried to create listing")

    a1.create_tag("tag")
    reset()
    print("tried to create tag")

    a1.create_order()
    reset()
    print("created order")

    # should be able to write manifest, though
    a1.expect_error = False
    a1.create_shop_manifest()
    assert a1.errors == 0


def test_accounts_mirror(make_client: MakeClientCallable):
    a = make_client("alice")
    a.register_shop()
    a.enroll_key_card()
    a.login()
    a.handle_all()
    a.create_shop_manifest()
    assert a.errors == 0

    time.sleep(1)
    a.handle_all()

    tx = a.shopReg.functions.registerUser(
        a.shop_token_id,
        "0x" + "42" * 20,
        0x1FF,  # admin
    ).transact()
    a.check_tx(tx)

    # TODO: waitUntil
    for _ in range(5):
        time.sleep(1)
        a.handle_all()
        if len(a.accounts) == 2:
            break
    assert len(a.accounts) == 2
    print(f"registered {tx}")

    tx = a.shopReg.functions.removeUser(
        a.shop_token_id,
        "0x" + "42" * 20,
    ).transact()
    a.check_tx(tx)
    print(f"removed: {tx}")

    # TODO: waitUntil
    for _ in range(5):
        time.sleep(1)
        a.handle_all()
        if len(a.accounts) == 1:
            break
    assert len(a.accounts) == 1


def test_subscription_management(
    make_two_clients: Tuple[RelayClientProtocol, RelayClientProtocol],
):
    a, b = make_two_clients

    # b only cares about one specific listing
    b.cancel_subscription(b.subscription)
    b.handle_all()
    assert b.errors == 0
    assert b.subscription is None

    l1 = a.create_listing("small box", 23)
    l2 = a.create_listing("big box", 123)

    b.handle_all()
    assert b.errors == 0
    assert b.shop is not None
    assert b.shop.listings.size == 0

    b.subscribe(
        [
            subscription_pb2.SubscriptionRequest.Filter(
                object_type="OBJECT_TYPE_LISTING",
                object_id=old_pb_types.ObjectId(raw=l2.to_bytes(8, "big")),
            ),
        ]
    )

    b.handle_all()
    assert b.shop.listings.size == 1
    assert not b.shop.listings.has(l1)
    assert b.shop.listings.has(l2)

    new_title = "cute box"
    a.update_listing(l2, title=new_title)
    a.handle_all()
    assert a.errors == 0

    b.handle_all()
    updated = b.shop.listings.get(l2)
    assert updated is not None
    assert updated.metadata.title == new_title
    assert b.shop.listings.size == 1


def test_clerk_create_and_update_listing(make_client: MakeClientCallable):
    a1 = make_client("alice.1")
    shop_id = a1.register_shop()
    a1.enroll_key_card()
    a1.login()
    a1.handle_all()
    assert a1.errors == 0
    assert a1.shop is not None

    # a1 writes a few events
    a1.create_shop_manifest()
    listing_id = a1.create_listing("shoes", 1000)
    new_price = 2000
    write_req_id = a1.update_listing(listing_id, price=new_price)
    _ = write_req_id
    assert a1.errors == 0
    # TODO: we need logic to wait until the event was processed locally
    # might need to add the seq_no response to the relay
    # a1_hash = a1._assert_shop_against_response(write_req_id)

    # a2 connects after a1 has written events
    a2 = make_client("alice.2")
    a2.account = a1.account
    a2.shop_token_id = shop_id
    a2.enroll_key_card()
    a2.login()
    a2.handle_all()
    assert a2.errors == 0
    assert a2.shop is not None
    a2_l = a2.shop.listings.get(listing_id)
    assert a2_l is not None
    assert a2_l.price == new_price
    a1_l = a1.shop.listings.get(listing_id)
    assert a1_l is not None
    assert a1_l.price == new_price
    # TODO: add logic to wait until the event was processed locally
    # assert a2.shop.hash() == a1_hash

    newImage = "https://http.cat/status/102"
    a2.update_listing(listing_id, add_image=newImage)
    a2.handle_all()
    assert a2.errors == 0
    a2_l = a2.shop.listings.get(listing_id)
    assert a2_l is not None
    assert a2_l.metadata.images is not None
    assert len(a2_l.metadata.images) == 2
    a1_l = a1.shop.listings.get(listing_id)
    assert a1_l is not None
    assert a1_l.metadata.images is not None
    assert len(a1_l.metadata.images) == 1
    a1.handle_all()
    assert a1.errors == 0
    a1_l = a1.shop.listings.get(listing_id)
    assert a1_l is not None
    assert a1_l.metadata.images is not None
    assert len(a1_l.metadata.images) == 2
    # TODO: add logic to wait until the event was processed locally
    # before = a2._assert_shop_against_response(req_id2)

    # try to update non-existent listing
    a2.expect_error = True
    a2.update_listing(new_object_id(), title="nope")
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND
    # assert a2.shop.hash() == before

    # TODO: add tests with too large metadata strings


def test_batch_update_listing(make_client: MakeClientCallable):
    # Create a client and set up shop
    a = make_client("alice")
    a.register_shop()
    a.enroll_key_card()
    a.login()
    a.handle_all()
    a.create_shop_manifest()
    assert a.errors == 0
    assert a.shop is not None

    # Create a listing
    listing_id = a.create_listing("T-shirt", 2000)
    assert a.errors == 0

    # Start a batch update
    a.start_batch()

    # Make multiple changes to the listing
    a.update_listing(listing_id, price=2500)
    a.update_listing(listing_id, title="Premium T-shirt")
    a.update_listing(listing_id, descr="Premium cotton t-shirt, very comfortable")
    a.update_listing(listing_id, remove_image=0)
    a.update_listing(listing_id, add_image="https://example.com/tshirt-front.jpg")
    a.update_listing(listing_id, add_image="https://example.com/tshirt-back.jpg")

    # Flush the batch to send all changes at once
    a.flush_batch()
    a.handle_all()

    # Verify all changes were applied
    assert a.errors == 0
    listing = a.shop.listings.get(listing_id)
    assert listing is not None
    assert listing.price == 2500
    assert listing.metadata.title == "Premium T-shirt"
    assert listing.metadata.description == "Premium cotton t-shirt, very comfortable"
    assert len(listing.metadata.images) == 2
    assert "https://example.com/tshirt-back.jpg" in listing.metadata.images

    # Test that batching can be used for adding and removing tags
    a.create_tag("sale")
    assert a.errors == 0

    a.start_batch()
    a.update_listing(listing_id, state=mlisting.ListingViewState.PUBLISHED)
    a.update_listing(listing_id, add_image="https://example.com/tshirt-sale.jpg")
    a.flush_batch()
    a.handle_all()

    # Verify tag was added
    listing = a.shop.listings.get(listing_id)
    assert listing is not None
    assert listing.view_state == mlisting.ListingViewState.PUBLISHED
    assert len(listing.metadata.images) == 3

    # Test removing tag in a batch
    a.start_batch()
    a.update_listing(listing_id, price=2200)  # Sale price
    a.flush_batch()
    a.handle_all()

    # Verify tag was removed
    listing = a.shop.listings.get(listing_id)
    assert listing is not None
    assert listing.price == 2200


def test_clerk_update_listing_from_other_shop(make_client: MakeClientCallable):
    alice = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.handle_all()
    alice.create_shop_manifest()
    assert alice.errors == 0

    bob = make_client("bob")
    bob.register_shop()
    bob.enroll_key_card()
    bob.login()
    bob.handle_all()
    bob.create_shop_manifest()
    assert bob.errors == 0

    alicesListing = alice.create_listing("shoes", "1000")
    assert alice.errors == 0

    bob.expect_error = True
    bob.update_listing(alicesListing, price=666)
    assert bob.errors == 1
    assert bob.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_clerk_same_ids_with_other_shop(make_client: MakeClientCallable):
    alice = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.handle_all()
    alice.create_shop_manifest()
    assert alice.errors == 0

    bob = make_client("bob")
    bob.register_shop()
    bob.enroll_key_card()
    bob.login()
    bob.handle_all()
    bob.create_shop_manifest()
    assert bob.errors == 0

    iid = new_object_id(23)

    alice.create_listing("sneakers", "1000", iid=iid)
    assert alice.errors == 0
    bob.create_listing("birkenstock", "1000", iid=iid)
    assert bob.errors == 0


def test_clerk_create_and_edit_tag(
    make_two_clients: Tuple[RelayClientProtocol, RelayClientProtocol],
):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    iid1 = a1.create_listing("sneakers", "1000")
    iid2 = a1.create_listing("birkenstock", "1000")
    tag_name = "shoes"
    a1.create_tag(tag_name)
    a1.add_to_tag(tag_name, iid1)
    a1.add_to_tag(tag_name, iid2)
    assert a1.errors == 0
    assert a1.shop is not None

    # a2 syncs
    a2.handle_all()
    assert a2.errors == 0
    assert a2.shop is not None
    assert a2.shop.listings.size == 2
    assert a2.shop.tags.size == 1
    tag = a2.shop.tags.get(tag_name)
    assert tag is not None
    assert len(tag.listings) == 2
    assert iid1 in tag.listings
    assert iid2 in tag.listings

    a2.remove_from_tag(tag_name, iid1)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    tag = a1.shop.tags.get(tag_name)
    assert tag is not None
    assert iid1 not in tag.listings
    tag = a2.shop.tags.get(tag_name)
    assert tag is not None
    assert iid1 not in tag.listings


def test_clerk_invalid_tag_interactions(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    iid1 = a1.create_listing("sneakers", "1000")
    tag_name = "shoes"
    a1.create_tag(tag_name)
    a1.add_to_tag(tag_name, iid1)
    assert a1.errors == 0

    noSuchTagId = "semi-random-tag-name"
    a2.expect_error = True
    a2.add_to_tag(noSuchTagId, iid1)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset error state
    a2.errors = 0
    a2.last_error = None

    noSuchListingId = new_object_id()
    a2.add_to_tag(tag_name, noSuchListingId)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # add listing to tag that is already in tag
    a2.errors = 0
    a2.add_to_tag(tag_name, iid1)
    # multiple adds are an error
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_INVALID

    # TODO: figure out rename semantics
    # rename tag that does not exist
    # a2.errors = 0
    # a2.rename_tag(noSuchTagId, "shoes")
    # assert a2.errors == 1
    # assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # delete tag that does not exist
    a2.errors = 0
    a2.delete_tag(noSuchTagId)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


# TODO: figure out rename semantics
def skip_test_clerk_rename_and_remove_tag(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    tag_name = "toys"
    a1.create_tag(tag_name)
    assert a1.errors == 0

    # a2 syncs
    a2.handle_all()
    assert a2.errors == 0
    assert a2.shop is not None
    assert a2.shop.tags.size == 1
    t = a2.shop.tags.get(tag_name)
    assert t is not None
    assert t.name == tag_name

    a2.rename_tag(tag_name, "games")
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    t = a1.shop.tags.get(tag_name)
    assert t is not None
    assert t.name == "games"
    t = a2.shop.tags.get(tag_name)
    assert t is not None
    assert t.name == "games"

    a2.delete_tag(tag_name)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    t = a1.shop.tags.get(tag_name)
    assert t is None
    t = a2.shop.tags.get(tag_name)
    assert t is None


def test_clerk_publish_listing(make_two_clients: Tuple[RelayClient, RelayClient]):
    a1, a2 = make_two_clients
    assert a1.shop is not None
    assert a2.shop is not None

    # a1 writes a new listing
    iid1 = a1.create_listing("sneakers", 1000)
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0

    # a2 publishes it
    new_state = mlisting.ListingViewState.PUBLISHED
    a2.update_listing(iid1, state=new_state)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    a1_l = a1.shop.listings.get(iid1)
    assert a1_l is not None
    assert a1_l.view_state == new_state


def test_clerk_change_inventory(make_two_clients: Tuple[RelayClient, RelayClient]):
    a1, a2 = make_two_clients
    assert a1.shop is not None
    assert a2.shop is not None

    # a1 writes an a few events
    iid1 = a1.create_listing("sneakers", 1000)
    iid2 = a1.create_listing("birkenstock", 1000)
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0

    # a2 adds some inventory
    a2.change_inventory(iid1, 3)
    a2.change_inventory(iid2, 5)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert a1.check_inventory(iid1) == 3
    assert a1.check_inventory(iid2) == 5

    # Test setting inventory to 0
    a1.change_inventory(iid1, 0)
    assert a1.errors == 0
    assert a1.check_inventory(iid1) == 0
    a2.handle_all()
    assert a2.errors == 0
    assert a2.check_inventory(iid1) == 0

    # Verify we can set it back to a positive number
    a2.change_inventory(iid1, 10)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert a1.check_inventory(iid1) == 10

    # Test setting inventory to 0 again with the other client
    a2.change_inventory(iid1, 0)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert a1.check_inventory(iid1) == 0


def test_clerk_invalid_inventory_interactions(make_two_clients, make_client):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    iid1 = a1.create_listing("sneakers", "1000")
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0

    # a2 adds some inventory
    a2.change_inventory(iid1, 3)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert a1.check_inventory(iid1) == 3

    # a2 tries to add negative inventory
    a2.expect_error = True
    a2.change_inventory(iid1, -4)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_OUT_OF_STOCK

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # a2 tries to add inventory for non-existent listing
    a2.expect_error = True
    a2.change_inventory(new_object_id(), 1)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # bob makes a 2nd shop
    bob = make_client("bob")
    bob.register_shop()
    bob.enroll_key_card()
    bob.login()
    bob.handle_all()
    bob.create_shop_manifest()
    foreignListingId = bob.create_listing("flute", "1000")
    assert bob.errors == 0

    # a2 tries to add inventory for listing in other shopy
    a2.expect_error = True
    a2.change_inventory(foreignListingId, 1)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_listing_with_variation(make_two_clients: Tuple[RelayClient, RelayClient]):
    a1, a2 = make_two_clients
    assert a1.shop is not None
    assert a2.shop is not None

    lid = a1.create_listing("sneaker", 95)

    # add a new option
    size_s = mlisting.ListingVariation(
        variation_info=mlisting.ListingMetadata(
            title="S",
            description="small",
        ),
    )
    size_m = mlisting.ListingVariation(
        variation_info=mlisting.ListingMetadata(
            title="M",
            description="medium",
        ),
    )
    size_l = mlisting.ListingVariation(
        variation_info=mlisting.ListingMetadata(
            title="L",
            description="large",
        ),
    )
    opt_name = "size"
    opt_size = mlisting.ListingOption(
        title=opt_name,
        variations={
            "s": size_s,
            "m": size_m,
            "l": size_l,
        },
    )
    a1.update_listing(lid, add_option=(opt_name, opt_size))
    assert a1.errors == 0

    # wait for all events to be applied
    listing = None
    for _ in range(10):
        a1.handle_all()
        assert a1.errors == 0
        listing = a1.shop.listings.get(lid)
        if (
            listing is not None
            and listing.options is not None
            and len(listing.options) == 1
        ):
            break
    assert listing is not None
    assert listing.options is not None
    assert len(listing.options) == 1
    assert len(listing.options[opt_name].variations) == 3
    a2.handle_all()

    # add variation to existing option
    size_xl = mlisting.ListingVariation(
        variation_info=mlisting.ListingMetadata(
            title="XL",
            description="extra-large",
        ),
    )
    a1.update_listing(lid, add_variation=(opt_name, ("xl", size_xl)))
    assert a1.errors == 0

    # wait for all events to be applied
    for _ in range(10):
        a1.handle_all()
        assert a1.errors == 0
    listing = a1.shop.listings.get(lid)
    assert listing is not None
    assert len(listing.options) == 1
    assert len(listing.options[opt_name].variations) == 4
    a2.handle_all()

    # remove variation
    a1.update_listing(lid, remove_variation=(opt_name, "m"))
    assert a1.errors == 0
    listing = a1.shop.listings.get(lid)
    assert listing is not None
    assert len(listing.options[opt_name].variations) == 3

    # remove option
    opt_silly = mlisting.ListingOption(
        title="nope",
        variations={
            "nope": mlisting.ListingVariation(
                variation_info=mlisting.ListingMetadata(
                    title="nope", description="nope"
                ),
            ),
        },
    )
    a1.update_listing(lid, add_option=("nope", opt_silly))
    assert a1.errors == 0
    listing = a1.shop.listings.get(lid)
    assert listing is not None
    assert len(listing.options) == 2
    a1.update_listing(lid, remove_option="nope")
    listing = a1.shop.listings.get(lid)
    assert listing is not None
    assert len(listing.options) == 1

    # a2.handle_all()

    # TODO: enable inventory
    # stock tests
    # a1.change_inventory(lid, 1, [size_s.id])
    # a1.change_inventory(lid, 2, [size_l.id])
    # a1.change_inventory(lid, 3, [size_xl.id])
    # assert a1.errors == 0
    # assert a1.check_inventory(lid, [size_s.id]) == 1
    # assert a1.check_inventory(lid, [size_m.id]) == 0
    # assert a1.check_inventory(lid, [size_l.id]) == 2
    # assert a1.check_inventory(lid, [size_xl.id]) == 3

    # # sync 2nd client to test event push handling
    # a2.handle_all()
    # assert a2.errors == 0
    # assert a2.check_inventory(lid, [size_s.id]) == 1
    # assert a2.check_inventory(lid, [size_m.id]) == 0
    # assert a2.check_inventory(lid, [size_l.id]) == 2
    # assert a2.check_inventory(lid, [size_xl.id]) == 3


def test_invalid_add_variation_to_nonexistent_option(make_two_clients):
    a1, _ = make_two_clients

    lid = a1.create_listing("t-shirt", "50")

    # Trying to add a variation to a non-existing option
    size_xxl = mlisting.ListingVariation(
        variation_info=mlisting.ListingMetadata(
            title="XXL",
            description="extra-extra-large",
        ),
    )
    a1.expect_error = True
    a1.update_listing(lid, add_variation=("mega", ("xxl", size_xxl)))

    assert a1.errors != 0, "Expecting an error since the option doesn't exist"


def test_invalid_variation_remove_nonexistents(make_two_clients):
    a1, _ = make_two_clients

    a1.expect_error = True

    lid = a1.create_listing("t-shirt", "50")

    a1.update_listing(lid, remove_variation=("size", "xxxxl"))
    assert a1.errors != 0

    a1.errors = 0
    a1.update_listing(lid, remove_option="stuff")
    assert a1.errors != 0


def test_invalid_add_option_with_taken_id(make_two_clients):
    a1, _ = make_two_clients

    lid = a1.create_listing("hat", "25")

    # Add an option
    color_option = mlisting.ListingOption(
        title="stuff",
        variations={
            "steel": mlisting.ListingVariation(
                variation_info=mlisting.ListingMetadata(
                    title="steel", description="steel material"
                ),
            ),
        },
    )
    a1.update_listing(lid, add_option=("material", color_option))
    assert a1.errors == 0

    # Try adding another option with the same ID
    duplicate_id_option = mlisting.ListingOption(
        title="material",
        variations={
            "cotton": mlisting.ListingVariation(
                variation_info=mlisting.ListingMetadata(
                    title="cotton", description="cotton material"
                ),
            ),
        },
    )
    a1.expect_error = True
    a1.update_listing(lid, add_option=("material", duplicate_id_option))
    assert a1.errors != 0, "Expecting an error due to duplicate ID"


def test_invalid_add_variation_with_taken_id(make_two_clients):
    a1, _ = make_two_clients

    lid = a1.create_listing("watch", "150")

    var_small = mlisting.ListingVariation(
        variation_info=mlisting.ListingMetadata(
            title="small", description="small size"
        ),
    )

    # Add an option
    length_option = mlisting.ListingOption(
        title="length",
        variations={
            "small": var_small,
        },
    )
    a1.update_listing(lid, add_option=("length", length_option))
    assert a1.errors == 0

    a1.expect_error = True
    a1.errors = 0

    # variation names are unique per listing
    width_option = mlisting.ListingOption(
        title="width",
        variations={
            "small": mlisting.ListingVariation(
                variation_info=mlisting.ListingMetadata(
                    title="small", description="primary width 1"
                ),
            ),
        },
    )
    a1.update_listing(lid, add_option=("width", width_option))
    assert a1.errors == 1


def test_invalid_change_stock_of_non_existent_variation(make_two_clients):
    a1, _ = make_two_clients
    lid = a1.create_listing("watch", "150")

    a1.expect_error = True
    a1.change_inventory(lid, 23, ["foo", "bar"])
    assert a1.errors != 0, "variation shouldn't exist"


def test_cannot_add_unpublished_item_to_order(
    make_client: MakeClientCallable,
):
    # Create client and setup
    client = make_client("alice")
    client.register_shop()
    client.enroll_key_card()
    client.login()
    client.handle_all()
    client.create_shop_manifest()
    assert client.errors == 0
    assert client.shop is not None

    # Create an unpublished listing
    listing_id = client.create_listing(
        "test product", 1000, state=mlisting.ListingViewState.UNSPECIFIED
    )
    client.handle_all()
    assert client.errors == 0
    client.change_inventory(listing_id, 10)

    # Verify the listing is created but unpublished (draft state)
    listing = client.shop.listings.get(listing_id)
    assert listing is not None
    assert listing.view_state == mlisting.ListingViewState.UNSPECIFIED

    # Try to create an order and add the unpublished item
    order_id = client.create_order()
    assert client.errors == 0

    # Expect an error when trying to add the unpublished item
    client.add_to_order(order_id, listing_id, 1)
    assert client.errors == 0

    # Expect an error when trying to commit the order
    client.expect_error = True
    client.commit_items(order_id)
    assert client.errors == 1
    assert client.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND
    assert client.last_error.additional_info.object_id == listing_id

    # reset error state
    client.expect_error = False
    client.last_error = None
    client.errors = 0

    # Now publish the listing
    client.update_listing(listing_id, state=mlisting.ListingViewState.PUBLISHED)
    client.handle_all()
    assert client.errors == 0

    # Verify it's now published
    listing = client.shop.listings.get(listing_id)
    assert listing is not None
    assert listing.view_state == mlisting.ListingViewState.PUBLISHED

    # Try again to add the now-published item to the order
    client.commit_items(order_id)
    assert client.errors == 0

    # Verify the item was added to the order
    client.handle_all()
    assert client.errors == 0
    order = client.shop.orders.get(order_id)
    assert order is not None
    assert len(order.items) == 1
    assert order.payment_state == morder.OrderPaymentState.COMMITTED
    assert order.items[0].listing_id == listing_id
    assert order.items[0].quantity == 1
