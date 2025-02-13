# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

from typing import Tuple
import os
import random

from client import RelayClient
from massmarket import error_pb2
import massmarket.cbor.base_types as mbase


def setup_shop_with_listing(make_client) -> Tuple[RelayClient, int]:
    alice = make_client("alice")
    assert isinstance(alice, RelayClient)
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    use_batching = random.choice([True, False])

    if use_batching:
        alice.start_batch()

    # remove default setup
    alice.update_shop_manifest(remove_payee=alice.default_payee)
    alice.update_shop_manifest(remove_currency=alice.default_currency)

    # create a listing
    iid = alice.create_listing("sneakers", 10, wait=False)

    if use_batching:
        alice.flush_batch()
    alice.handle_all()
    assert alice.errors == 0

    # TODO: move up into batch
    alice.change_inventory(iid, 20)
    assert alice.errors == 0

    return alice, iid


def test_no_accepted_currency(make_client):
    alice, iid = setup_shop_with_listing(make_client)

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    alice.expect_error = True
    alice.commit_items(oid)
    assert alice.errors == 0
    alice.update_address_for_order(oid, shipping=alice.default_shipping_address)
    assert alice.errors == 0
    alice.choose_payment(oid)
    assert alice.errors != 0


def test_no_pricing_currency(make_client):
    alice, iid = setup_shop_with_listing(make_client)
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    curr = mbase.ChainAddress(
        address=mbase.EthereumAddress(value=erc20_addr),
        chain_id=2,
    )

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    alice.expect_error = True
    alice.commit_items(oid)
    alice.choose_payment(oid, currency=curr)
    assert alice.errors != 0
    assert alice.last_error is not None
    assert alice.last_error.code == error_pb2.ERROR_CODES_INVALID


def test_no_payee(make_client):
    alice, iid = setup_shop_with_listing(make_client)
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    curr = mbase.ChainAddress(
        address=mbase.EthereumAddress(value=erc20_addr),
        chain_id=alice.chain_id,
    )
    alice.update_shop_manifest(add_currency=curr)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    alice.expect_error = True
    alice.commit_items(oid)
    alice.choose_payment(oid, currency=curr)
    assert alice.errors != 0
    assert alice.last_error is not None
    assert alice.last_error.code == error_pb2.ERROR_CODES_INVALID


def test_mismatching_chain_id_in_order_and_currency(make_client):
    alice, iid = setup_shop_with_listing(make_client)

    # Register ERC20 token with chain_id 31337
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    curr = mbase.ChainAddress(
        address=mbase.EthereumAddress(value=erc20_addr),
        chain_id=alice.chain_id,
    )
    alice.update_shop_manifest(add_currency=curr)
    assert alice.errors == 0

    # Add payee with chain_id 1
    payee = mbase.Payee(
        address=mbase.ChainAddress(
            address=mbase.EthereumAddress(value=os.urandom(20)),
            chain_id=alice.chain_id,
        ),
        call_as_contract=True,
    )
    alice.update_shop_manifest(add_payee=payee)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    # Attempt to commit order with chain_id 2
    alice.expect_error = True
    curr_invalid = mbase.ChainAddress(
        address=curr.address,
        chain_id=2,
    )
    alice.commit_items(oid)
    alice.choose_payment(oid, currency=curr_invalid)
    assert alice.errors != 0
    print(f"Failed to finalize order {oid} due to chain_id mismatch")


def test_mismatching_chain_id_in_currency_and_order(make_client):
    alice, iid = setup_shop_with_listing(make_client)

    # Set base currency with chain_id 1
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    currency = mbase.ChainAddress(
        address=mbase.EthereumAddress(value=erc20_addr),
        chain_id=alice.chain_id,
    )

    alice.update_shop_manifest(set_pricing_currency=currency)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)
    assert alice.errors == 0

    # Attempt to commit order with chain_id 2
    curr_invalid = mbase.ChainAddress(
        address=currency.address,
        chain_id=2,
    )
    alice.expect_error = True
    alice.commit_items(oid)
    alice.choose_payment(oid, currency=curr_invalid)
    assert alice.errors != 0
    print(f"Failed to finalize order {oid} due to chain_id mismatch with base currency")


# TODO: for this we need to simulate the relay with multiple chains configured
def skip_test_inconsistent_payee(make_client):
    alice, iid = setup_shop_with_listing(make_client)

    # Add payee with chain_id 2 and set base currency with chain_id 1
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    assert alice.account is not None
    payee_addr = alice.w3.to_bytes(hexstr=alice.account.address)
    escrow_payee = mbase.Payee(
        address=mbase.ChainAddress(
            address=mbase.EthereumAddress(value=os.urandom(20)),
            chain_id=1,
        ),
        call_as_contract=True,
    )
    currency = mbase.ChainAddress(
        address=mbase.EthereumAddress(value=erc20_addr),
        chain_id=2,
    )
    alice.update_shop_manifest(add_payee=escrow_payee)
    assert alice.errors == 0
    alice.update_shop_manifest(add_currency=currency)
    assert alice.errors == 0
    alice.update_shop_manifest(set_pricing_currency=currency)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    # Attempt to commit order with chain_id 1 matching payee but not base currency
    curr_invalid = mbase.ChainAddress(
        address=mbase.EthereumAddress(value=erc20_addr),
        chain_id=2,
    )
    alice.expect_error = True
    alice.commit_items(oid)
    alice.choose_payment(oid, curr_invalid, "escrow")
    assert alice.errors != 0
    print(f"Failed to finalize order {oid} due to chain_id mismatch with base currency")
