from typing import Tuple
import os

from client import RelayClient
from massmarket_hash_event import base_types_pb2 as mtypes, error_pb2


def setup_shop_with_listing(make_client) -> Tuple[RelayClient, bytes]:
    alice = make_client("alice")
    alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    # remove default setup
    alice.update_shop_manifest(
        remove_currencies=[alice.default_currency],
        remove_payee=alice.default_payee,
    )
    assert alice.errors == 0

    iid = alice.create_listing("sneakers", 10)
    i = 10
    while iid.raw not in alice.listings:
        alice.handle_all()
        i -= 1
        assert i > 0, "timeout"
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
    alice.choose_payment(oid)
    assert alice.errors != 0


def test_no_pricing_currency(make_client):
    alice, iid = setup_shop_with_listing(make_client)
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    curr = mtypes.ShopCurrency(
        address=mtypes.EthereumAddress(raw=erc20_addr),
        chain_id=2,
    )

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    alice.expect_error = True
    alice.commit_items(oid)
    alice.choose_payment(oid, curr)
    assert alice.errors != 0
    assert alice.last_error.code == error_pb2.ERROR_CODES_INVALID


def test_no_payee(make_client):
    alice, iid = setup_shop_with_listing(make_client)
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    curr = mtypes.ShopCurrency(
        address=mtypes.EthereumAddress(raw=erc20_addr), chain_id=alice.chain_id
    )
    alice.update_shop_manifest(add_currencies=[curr])
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    alice.expect_error = True
    alice.commit_items(oid)
    alice.choose_payment(oid, curr)
    assert alice.errors != 0
    assert alice.last_error.code == error_pb2.ERROR_CODES_INVALID


def test_mismatching_chain_id_in_order_and_currency(make_client):
    alice, iid = setup_shop_with_listing(make_client)

    # Register ERC20 token with chain_id 31337
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    curr = mtypes.ShopCurrency(
        address=mtypes.EthereumAddress(raw=erc20_addr), chain_id=alice.chain_id
    )
    alice.update_shop_manifest(add_currencies=[curr])
    assert alice.errors == 0

    # Add payee with chain_id 1
    payee = mtypes.Payee(
        name="escrow",
        address=mtypes.EthereumAddress(raw=os.urandom(20)),
        chain_id=alice.chain_id,
        call_as_contract=True,
    )
    alice.update_shop_manifest(add_payee=payee)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    # Attempt to commit order with chain_id 2
    alice.expect_error = True
    curr_invalid = mtypes.ShopCurrency(
        address=curr.address,
        chain_id=2,
    )
    alice.commit_items(oid)
    alice.choose_payment(oid, curr_invalid)
    assert alice.errors != 0
    print(f"Failed to finalize order {oid} due to chain_id mismatch")


def test_mismatching_chain_id_in_currency_and_order(make_client):
    alice, iid = setup_shop_with_listing(make_client)

    # Set base currency with chain_id 1
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    currency = mtypes.ShopCurrency(
        address=mtypes.EthereumAddress(raw=erc20_addr), chain_id=alice.chain_id
    )

    alice.update_shop_manifest(set_pricing_currency=currency)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    # Attempt to commit order with chain_id 2
    curr_invalid = mtypes.ShopCurrency(
        address=currency.address,
        chain_id=2,
    )
    alice.expect_error = True
    alice.commit_items(oid)
    alice.choose_payment(oid, curr_invalid)
    assert alice.errors != 0
    print(f"Failed to finalize order {oid} due to chain_id mismatch with base currency")


# TODO: for this we need to simulate the relay with multiple chains configured
def skip_test_inconsistent_payee(make_client):
    alice, iid = setup_shop_with_listing(make_client)

    # Add payee with chain_id 2 and set base currency with chain_id 1
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    payee = mtypes.Payee(
        name="escrow",
        address=mtypes.EthereumAddress(
            raw=alice.w3.to_bytes(hexstr=alice.account.address),
        ),
        chain_id=1,
        call_as_contract=True,
    )
    currency = mtypes.ShopCurrency(
        address=mtypes.EthereumAddress(raw=erc20_addr),
        chain_id=2,
    )
    alice.update_shop_manifest(
        add_payee=payee, add_currencies=[currency], set_pricing_currency=currency
    )
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    # Attempt to commit order with chain_id 1 matching payee but not base currency
    curr_invalid = mtypes.ShopCurrency(
        address=mtypes.EthereumAddress(raw=erc20_addr),
        chain_id=2,
    )
    alice.expect_error = True
    alice.commit_items(oid)
    alice.choose_payment(oid, curr_invalid, "escrow")
    assert alice.errors != 0
    print(f"Failed to finalize order {oid} due to chain_id mismatch with base currency")
