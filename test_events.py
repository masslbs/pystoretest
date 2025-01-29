import os
import pytest
import time
from typing import Tuple

import google.protobuf.any_pb2 as anypb

from massmarket_hash_event import (
    base_types_pb2 as mtypes,
    shop_events_pb2 as mevents,
    error_pb2,
    subscription_pb2,
    transport_pb2,
    envelope_pb2,
)
from client import RelayClient, RelayException, new_object_id, vid, now_pbts


def test_helper_vid():
    assert vid(23) == "23:"
    assert vid(23, None) == "23:"
    assert vid(1, [2]) == "1:2:"
    assert vid(1, [2, 3]) == "1:2:3:"
    assert vid(1, [3, 2]) == "1:2:3:"


def test_event_nonce_collision(wc_auth: RelayClient):
    wc_auth.create_shop_manifest()
    assert wc_auth.errors == 0

    t = mevents.Tag(id=new_object_id(), name="nonce fail")

    shop_evt = mevents.ShopEvent(
        nonce=0,  # used by manifest already
        shop_id=mtypes.Uint256(raw=wc_auth.shop_token_id.to_bytes(32, "big")),
        timestamp=now_pbts(),
        tag=t,
    )

    # need to copy a bit of code from _create_event
    msg = wc_auth._sign_event(shop_evt)
    wrapped = anypb.Any()
    wrapped.Pack(shop_evt)
    sig_evt = transport_pb2.SignedEvent(
        event=wrapped,
        signature=mtypes.Signature(raw=msg.signature),
    )
    with pytest.raises(RelayException):
        wc_auth._send_event(sig_evt)
    wc_auth.close()


def test_clerk_update_shop_manifest(wc_auth: RelayClient):
    wc_auth.create_shop_manifest()
    assert wc_auth.errors == 0
    erc20_addr = wc_auth.w3.to_bytes(hexstr=wc_auth.erc20Token.address[2:])
    erc20_addr_pb = mtypes.EthereumAddress(raw=erc20_addr)
    curr = [mtypes.ShopCurrency(address=erc20_addr_pb, chain_id=wc_auth.chain_id)]
    wc_auth.update_shop_manifest(add_currencies=curr)
    assert wc_auth.errors == 0
    wc_auth.update_shop_manifest(remove_currencies=curr)
    assert wc_auth.errors == 0
    p = mtypes.Payee(
        name="rando",
        address=mtypes.EthereumAddress(raw=os.urandom(20)),
        chain_id=wc_auth.chain_id,
        call_as_contract=True,
    )
    wc_auth.update_shop_manifest(add_payee=p)
    assert wc_auth.errors == 0
    wc_auth.expect_error = True
    rand_curr = mtypes.ShopCurrency(
        address=mtypes.EthereumAddress(raw=os.urandom(20)),
        chain_id=wc_auth.chain_id,
    )
    wc_auth.update_shop_manifest(add_currencies=[rand_curr])
    assert wc_auth.errors == 1
    wc_auth.expect_error = False
    wc_auth.close()


def test_clerk_sync_shop_manifest(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes events
    new_payee = mtypes.Payee(
        name="extras",
        address=mtypes.EthereumAddress(raw=os.urandom(20)),
        chain_id=a1.chain_id,
        call_as_contract=True,
    )
    a1.update_shop_manifest(add_payee=new_payee)
    a1.handle_all()
    assert a1.errors == 0

    # a2 syncs the event
    a2.handle_all()
    assert a2.errors == 0
    assert len(a2.payees) == 2


def test_clerk_write_and_sync_later(make_client):
    # both alices share the same private wallet but have different keycards
    a1 = make_client("alice.1")
    shop_id = a1.register_shop()
    a1.enroll_key_card()
    a1.login()
    a1.handle_all()
    assert a1.errors == 0

    # a1 writes an a few events
    a1.create_shop_manifest()
    a1.create_listing("shoes", "1000")
    assert a1.errors == 0

    print("connecting alice.2")

    # a2 connects after a1 has written events
    a2 = make_client("alice.2")
    a2.account = a1.account
    a2.shop_token_id = shop_id
    a2.enroll_key_card()
    a2.login()
    assert a2.errors == 0
    retries = 10
    while len(a2.listings) < 1 and retries > 0:
        time.sleep(1)
        a2.handle_all()
        retries -= 1
    assert len(a2.listings) == 1


def test_clerk_manifest_first(make_client):
    a1 = make_client("alice.1")
    shop_id = a1.register_shop()
    a1.enroll_key_card()
    a1.login()
    a1.handle_all()
    assert a1.errors == 0

    def reset():
        assert a1.errors == 1
        assert a1.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND
        a1.errors = 0
        a1.last_error = None

    a1.expect_error = True

    rand_curr = mtypes.ShopCurrency(
        address=mtypes.EthereumAddress(raw=os.urandom(20)),
        chain_id=a1.chain_id,
    )
    a1.update_shop_manifest(add_currencies=[rand_curr])
    reset()

    a1.create_listing("foo", "22")
    reset()

    a1.create_tag("tag")
    reset()

    a1.create_order()
    reset()


def test_account_message_mirror(make_client):
    a1 = make_client("alice.1")
    shop_id = a1.register_shop()
    a1.enroll_key_card()
    a1.login()
    a1.handle_all()
    assert a1.errors == 0

    time.sleep(1)
    a1.handle_all()

    tx = a1.shopReg.functions.registerUser(
        a1.shop_token_id,
        "0x" + "42" * 20,
        0x1FF,  # admin
    ).transact()
    a1.check_tx(tx)

    # TODO: waitUntil
    for _ in range(5):
        time.sleep(1)
        a1.handle_all()
        if len(a1.accounts) == 1:
            break
    assert len(a1.accounts) == 1
    print(f"registerd {tx}")

    tx = a1.shopReg.functions.removeUser(
        a1.shop_token_id,
        "0x" + "42" * 20,
    ).transact()
    a1.check_tx(tx)
    print(f"removed: {tx}")

    # TODO: waitUntil
    for _ in range(5):
        time.sleep(1)
        a1.handle_all()
        if len(a1.accounts) == 0:
            break
    assert len(a1.accounts) == 0


def test_subscription_management(make_two_clients: Tuple[RelayClient, RelayClient]):
    a, b = make_two_clients

    # b only cares about one specific listing
    b.cancel_subscription(b.subscription)
    b.handle_all()
    assert b.errors == 0
    assert b.subscription == None

    l1 = a.create_listing("small box", 23)
    l2 = a.create_listing("big box", 123)

    b.handle_all()
    assert b.errors == 0
    assert len(b.listings) == 0

    b.subscribe(
        [
            subscription_pb2.SubscriptionRequest.Filter(
                object_type="OBJECT_TYPE_LISTING", object_id=l2
            ),
        ]
    )

    b.handle_all()
    assert len(b.listings) == 1
    assert l1.raw not in b.listings
    assert l2.raw in b.listings

    new_title = "cute box"
    a.update_listing(l2, title=new_title)
    a.handle_all()
    assert a.errors == 0

    b.handle_all()
    updated = b.listings[l2.raw]
    assert updated.metadata.title == new_title
    assert len(b.listings) == 1


def test_clerk_create_and_update_listing(make_client):
    a1 = make_client("alice.1")
    shop_id = a1.register_shop()
    a1.enroll_key_card()
    a1.login()
    a1.handle_all()
    assert a1.errors == 0

    # a1 writes an a few events
    a1.create_shop_manifest()
    listing_id = a1.create_listing("shoes", "1000")
    pb = mtypes.Uint256(raw=int(2000).to_bytes(32, "big"))
    write_req_id = a1.update_listing(listing_id, price=pb)
    assert a1.errors == 0
    a1_hash = a1._assert_shop_against_response(write_req_id)

    # a2 connects after a1 has written events
    a2 = make_client("alice.2")
    a2.account = a1.account
    a2.shop_token_id = shop_id
    a2.enroll_key_card()
    a2.login()
    a2.handle_all()
    assert a2.errors == 0
    assert len(a2.listings) == 1
    assert a2.listings[listing_id.raw].price == pb
    assert a1.listings[listing_id.raw].price == pb
    assert a2._hash_shop() == a1_hash

    newImage = "https://http.cat/status/102"
    req_id2 = a2.update_listing(listing_id, add_image=newImage)
    a2.handle_all()
    assert a2.errors == 0
    assert len(a1.listings[listing_id.raw].metadata.images) == 1
    a1.handle_all()
    assert a1.errors == 0
    assert len(a1.listings[listing_id.raw].metadata.images) == 2
    before = a2._assert_shop_against_response(req_id2)

    # try to update non-existant listing
    a2.expect_error = True
    a2.update_listing(new_object_id(), title="nope")
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND
    assert a2._hash_shop() == before

    # TODO: add tests with too large metadata strings


def test_clerk_update_listing_from_other_shop(make_client):
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
    new_price = mtypes.Uint256(raw=int(666).to_bytes(32, "big"))
    bob.update_listing(alicesListing, price=new_price)
    assert bob.errors == 1
    assert bob.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_clerk_same_ids_with_other_shop(make_client):
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


def test_clerk_create_and_edit_tag(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    iid1 = a1.create_listing("sneakers", "1000")
    iid2 = a1.create_listing("birkenstock", "1000")
    tid = a1.create_tag("shoes")
    a1.add_to_tag(tid, iid1)
    a1.add_to_tag(tid, iid2)
    assert a1.errors == 0

    # a2 syncs
    a2.handle_all()
    assert a2.errors == 0
    assert len(a2.listings) == 2
    assert len(a2.tags) == 1
    tag = a2.tags[tid.raw]
    assert len(tag.listings) == 2
    assert iid1.raw in tag.listings
    assert iid2.raw in tag.listings

    a2.remove_from_tag(tid, iid1)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert iid1.raw not in a1.tags[tid.raw].listings
    assert iid1.raw not in a2.tags[tid.raw].listings


def test_clerk_invalid_tag_interactions(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    iid1 = a1.create_listing("sneakers", "1000")
    tid = a1.create_tag("shoes")
    a1.add_to_tag(tid, iid1)
    assert a1.errors == 0

    noSuchTagId = new_object_id()
    a2.expect_error = True
    a2.add_to_tag(noSuchTagId, iid1)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # reset error state
    a2.errors = 0
    a2.last_error = None

    noSuchListingId = new_object_id()
    a2.add_to_tag(tid, noSuchListingId)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # remove listing from tag that is not in tag
    a2.errors = 0
    a2.remove_from_tag(noSuchListingId, iid1)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # add listing to tag that is already in tag
    a2.errors = 0
    a2.add_to_tag(tid, iid1)
    # multiple adds are not an error
    assert a2.errors == 0

    # remove listing from tag that is not in shop
    a2.errors = 0
    a2.remove_from_tag(tid, noSuchListingId)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # rename tag that does not exist
    a2.errors = 0
    a2.rename_tag(noSuchTagId, "shoes")
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND

    # delete tag that does not exist
    a2.errors = 0
    a2.delete_tag(noSuchTagId)
    assert a2.errors == 1
    assert a2.last_error.code == error_pb2.ERROR_CODES_NOT_FOUND


def test_clerk_rename_and_remove_tag(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    tid = a1.create_tag("toys")
    assert a1.errors == 0

    # a2 syncs
    a2.handle_all()
    assert a2.errors == 0
    assert len(a2.tags) == 1
    assert tid.raw in a2.tags
    assert a2.tags[tid.raw].name == "toys"

    a2.rename_tag(tid, "games")
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert a1.tags[tid.raw].name == "games"
    assert a2.tags[tid.raw].name == "games"

    a2.delete_tag(tid)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert tid.raw not in a1.tags
    assert tid.raw not in a2.tags


def test_clerk_publish_listing(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes a new listing
    iid1 = a1.create_listing("sneakers", "1000")
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0

    # a2 publishes it
    new_state = mtypes.LISTING_VIEW_STATE_PUBLISHED
    a2.update_listing(iid1, state=new_state)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert a1.listings[iid1.raw].view_state == new_state


def test_clerk_change_inventory(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    iid1 = a1.create_listing("sneakers", "1000")
    iid2 = a1.create_listing("birkenstock", "1000")
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

    # a2 tries to add inventory for non-existant listing
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


def skip_test_against_zero_ids(make_two_clients):
    a1, a2 = make_two_clients

    checks = 0

    def assert_clients():
        nonlocal checks
        assert a1.errors == 1
        a2.handle_all()
        assert a2.errors == 0

        a1.last_error = None
        a1.errors = 0
        checks += 1

    a1.expect_error = True
    zero = mtypes.ObjectId(raw=bytes(8))
    a1.create_listing("zero", 0, iid=zero)
    assert_clients()
    assert len(a2.listings) == 0

    a1.create_tag("zero", tag_id=zero)
    assert_clients()
    assert len(a2.tags) == 0

    a1.create_order(oid=zero)
    assert_clients()
    assert len(a2.orders) == 0

    a1.update_listing(zero, title="zero")
    assert_clients()

    a1.rename_tag(zero, "zero")
    assert_clients()

    a1.add_to_tag(zero, zero)
    assert_clients()

    a1.remove_from_tag(zero, zero)
    assert_clients()

    a1.delete_tag(zero)
    assert_clients()

    a1.add_to_order(zero, zero, 1)
    assert_clients()

    a1.change_inventory(zero, 1)
    assert_clients()

    assert checks == 10


def test_listing_with_variation(make_two_clients):
    a1, a2 = make_two_clients

    lid = a1.create_listing("sneaker", "95")

    # add a new option
    size_s = mtypes.ListingVariation(
        id=new_object_id(),
        variation_info=mtypes.ListingMetadata(
            title="S",
            description="small",
        ),
    )
    size_m = mtypes.ListingVariation(
        id=new_object_id(),
        variation_info=mtypes.ListingMetadata(
            title="M",
            description="medium",
        ),
    )
    size_l = mtypes.ListingVariation(
        id=new_object_id(),
        variation_info=mtypes.ListingMetadata(
            title="L",
            description="large",
        ),
    )
    opt_size = mtypes.ListingOption(
        id=new_object_id(),
        title="size",
        variations=[size_s, size_m, size_l],
    )
    a1.update_listing(lid, add_option=opt_size)
    assert a1.errors == 0

    # wait for all events to be applied
    for _ in range(10):
        a1.handle_all()
        assert a1.errors == 0
        if len(a1.listings[lid.raw].options) == 1:
            break
    listing = a1.listings[lid.raw]
    assert len(listing.options) == 1, f"option not added: {listing}"
    assert len(listing.options[0].variations) == 3
    a2.handle_all()

    # add variation to existing option
    size_xl = mtypes.ListingVariation(
        id=new_object_id(),
        variation_info=mtypes.ListingMetadata(
            title="XL",
            description="extra-large",
        ),
    )
    add_size_var = mevents.UpdateListing.AddVariation(
        option_id=opt_size.id, variation=size_xl
    )
    a1.update_listing(lid, add_variation=add_size_var)
    assert a1.errors == 0

    # wait for all events to be applied
    for _ in range(10):
        a1.handle_all()
        assert a1.errors == 0
    listing = a1.listings[lid.raw]
    assert listing is not None
    assert len(listing.options) == 1
    assert len(listing.options[0].variations) == 4
    a2.handle_all()

    # remove tests
    a1.update_listing(lid, remove_variation=size_m.id)
    assert a1.errors == 0
    assert len(listing.options[0].variations) == 3

    opt_silly = mtypes.ListingOption(
        id=new_object_id(),
        title="nope",
        variations=[
            mtypes.ListingVariation(
                id=new_object_id(),
                variation_info=mtypes.ListingMetadata(title="nope", description="nope"),
            ),
        ],
    )
    a1.update_listing(lid, add_option=opt_silly)
    assert a1.errors == 0
    assert len(listing.options) == 2
    a1.update_listing(lid, remove_option=opt_silly.id)
    assert a1.errors == 0
    assert len(listing.options) == 1
    
    a2.handle_all()

    # stock tests
    a1.change_inventory(lid, 1, [size_s.id])
    a1.change_inventory(lid, 2, [size_l.id])
    a1.change_inventory(lid, 3, [size_xl.id])
    assert a1.errors == 0
    assert a1.check_inventory(lid, [size_s.id]) == 1
    assert a1.check_inventory(lid, [size_m.id]) == 0
    assert a1.check_inventory(lid, [size_l.id]) == 2
    assert a1.check_inventory(lid, [size_xl.id]) == 3

    # sync 2nd client to test event push handling
    a2.handle_all()
    assert a2.errors == 0
    assert a2.check_inventory(lid, [size_s.id]) == 1
    assert a2.check_inventory(lid, [size_m.id]) == 0
    assert a2.check_inventory(lid, [size_l.id]) == 2
    assert a2.check_inventory(lid, [size_xl.id]) == 3


def test_invalid_add_variation_to_nonexistent_option(make_two_clients):
    a1, _ = make_two_clients

    lid = a1.create_listing("t-shirt", "50")

    # Trying to add a variation to a non-existing option
    size_xxl = mtypes.ListingVariation(
        id=new_object_id(),
        variation_info=mtypes.ListingMetadata(
            title="XXL",
            description="extra-extra-large",
        ),
    )
    nonexistent_option_id = new_object_id()
    add_var_nonexistent = mevents.UpdateListing.AddVariation(
        option_id=nonexistent_option_id, variation=size_xxl
    )
    a1.expect_error = True
    a1.update_listing(lid, add_variation=add_var_nonexistent)

    assert a1.errors != 0, "Expecting an error since the option doesn't exist"


sixsixsix = mtypes.ObjectId(raw=b"66666666")


def test_invalid_variation_remove_nonexistents(make_two_clients):
    a1, _ = make_two_clients

    a1.expect_error = True

    lid = a1.create_listing("t-shirt", "50")

    a1.update_listing(lid, remove_variation=sixsixsix)
    assert a1.errors != 0

    a1.errors = 0
    a1.update_listing(lid, remove_option=sixsixsix)
    assert a1.errors != 0


def test_invalid_add_option_with_taken_id(make_two_clients):
    a1, _ = make_two_clients

    lid = a1.create_listing("hat", "25")

    # Add an option
    color_option = mtypes.ListingOption(
        id=new_object_id(),
        title="color",
        variations=[
            mtypes.ListingVariation(
                id=new_object_id(),
                variation_info=mtypes.ListingMetadata(
                    title="red", description="red color"
                ),
            ),
        ],
    )
    a1.update_listing(lid, add_option=color_option)
    assert a1.errors == 0

    # Try adding another option with the same ID
    duplicate_id_option = mtypes.ListingOption(
        id=color_option.id,  # same ID as the existing color option
        title="material",
        variations=[
            mtypes.ListingVariation(
                id=new_object_id(),
                variation_info=mtypes.ListingMetadata(
                    title="cotton", description="cotton material"
                ),
            ),
        ],
    )
    a1.expect_error = True
    a1.update_listing(lid, add_option=duplicate_id_option)
    assert a1.errors != 0, "Expecting an error due to duplicate ID"


def test_invalid_add_variation_with_taken_id(make_two_clients):
    a1, _ = make_two_clients

    lid = a1.create_listing("watch", "150")

    # Add an option
    size_option = mtypes.ListingOption(
        id=new_object_id(),
        title="size",
        variations=[
            mtypes.ListingVariation(
                id=new_object_id(),
                variation_info=mtypes.ListingMetadata(
                    title="small", description="small size"
                ),
            ),
        ],
    )
    a1.update_listing(lid, add_option=size_option)
    assert a1.errors == 0

    # Add another variation with the same ID
    duplicate_id_variation = mtypes.ListingVariation(
        id=size_option.variations[0].id,  # same ID as the existing small variation
        variation_info=mtypes.ListingMetadata(
            title="medium", description="medium size"
        ),
    )
    add_duplicate_variation = mevents.UpdateListing.AddVariation(
        option_id=size_option.id, variation=duplicate_id_variation
    )
    a1.expect_error = True
    a1.update_listing(lid, add_variation=add_duplicate_variation)

    assert a1.errors != 0, "Expecting an error due to duplicate ID"

    a1.errors = 0

    # variation ids are unique per listing
    color_option = mtypes.ListingOption(
        id=new_object_id(),
        title="color",
        variations=[
            mtypes.ListingVariation(
                id=size_option.variations[0].id,  # taken id
                variation_info=mtypes.ListingMetadata(
                    title="red", description="primary color 1"
                ),
            ),
        ],
    )
    a1.update_listing(lid, add_option=color_option)
    assert a1.errors == 0


def test_invalid_change_stock_of_non_existent_variation(make_two_clients):
    a1, _ = make_two_clients
    lid = a1.create_listing("watch", "150")

    a1.expect_error = True
    a1.change_inventory(lid, 23, [sixsixsix, new_object_id()])
    assert a1.errors != 0, "variation shouldn't exist"
