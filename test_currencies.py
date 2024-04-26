from typing import Tuple
from client import RelayClient
from massmarket_hash_event import shop_pb2, shop_events_pb2, error_pb2

def setup_shop_with_item(make_client) -> Tuple[RelayClient, bytes]:
    alice = make_client("alice")
    shop_id = alice.register_shop()
    alice.enroll_key_card()
    alice.login()
    alice.create_shop_manifest()
    assert alice.errors == 0

    iid = alice.create_item('sneakers', 10)
    alice.change_stock([(iid, 20)])
    assert alice.errors == 0

    # remove default currencies
    alice.update_shop_manifest(
        remove_currencies=[alice.default_currency],
        remove_payee=alice.default_payee)
    assert alice.errors == 0

    return alice, iid

def test_no_base_currency(make_client):
    alice, iid = setup_shop_with_item(make_client)
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    curr = shop_pb2.ShopCurrency(token_addr=erc20_addr, chain_id=2)

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    alice.expect_error = True
    alice.commit_order(oid, curr)
    assert alice.errors != 0
    assert alice.last_error.code == error_pb2.ERROR_CODES_INVALID

def test_no_payee(make_client):
    alice, iid = setup_shop_with_item(make_client)
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    curr = shop_pb2.ShopCurrency(token_addr=erc20_addr, chain_id=alice.chain_id)

    alice.update_shop_manifest(add_currencies=[curr])
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    alice.expect_error = True
    alice.commit_order(oid, curr)
    assert alice.errors != 0
    assert alice.last_error.code == error_pb2.ERROR_CODES_INVALID


def test_mismatching_chain_id_in_order_and_currency(make_client):
    alice, iid = setup_shop_with_item(make_client)

    # Register ERC20 token with chain_id 31337
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    curr = shop_pb2.ShopCurrency(token_addr=erc20_addr, chain_id=alice.chain_id)
    alice.update_shop_manifest(add_currencies=[curr])
    assert alice.errors == 0

    # Add payee with chain_id 1
    payee = shop_events_pb2.UpdateShopManifest.Payee(name="escrow", addr=erc20_addr, chain_id=alice.chain_id, call_as_contract=True)
    alice.update_shop_manifest(add_payee=payee)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    # Attempt to commit order with chain_id 2
    alice.expect_error = True
    curr_invalid = shop_pb2.ShopCurrency(token_addr=erc20_addr, chain_id=2)
    alice.commit_order(oid, curr_invalid)
    assert alice.errors != 0
    print(f'Failed to finalize order {oid} due to chain_id mismatch')


def test_mismatching_chain_id_in_currency_and_order(make_client):
    alice, iid = setup_shop_with_item(make_client)

    # Set base currency with chain_id 1
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    base_currency = shop_pb2.ShopCurrency(token_addr=erc20_addr, chain_id=alice.chain_id)
    alice.update_shop_manifest(set_base_currency=base_currency)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    # Attempt to commit order with chain_id 2
    curr_invalid = shop_pb2.ShopCurrency(token_addr=erc20_addr, chain_id=2)
    alice.expect_error = True
    alice.commit_order(oid, curr_invalid)
    assert alice.errors != 0
    print(f'Failed to finalize order {oid} due to chain_id mismatch with base currency')

def test_removed_accepted_currency(make_client):
    alice, iid = setup_shop_with_item(make_client)

    alice.update_shop_manifest(remove_currencies=[alice.default_currency])
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    alice.expect_error = True
    alice.commit_order(oid)
    assert alice.errors != 0
    print(f'Failed to finalize order {oid} due to using removed chain_id')

def skip_test_inconsistent_payee(make_client):
    alice, iid = setup_shop_with_item(make_client)

    # Add payee with chain_id 2 and set base currency with chain_id 1
    erc20_addr = alice.w3.to_bytes(hexstr=alice.erc20Token.address[2:])
    payee = shop_events_pb2.UpdateShopManifest.Payee(
        name="escrow",
        addr=alice.w3.to_bytes(hexstr=alice.account.address),
        chain_id=1,
        call_as_contract=True)
    base_currency = shop_pb2.ShopCurrency(token_addr=erc20_addr, chain_id=2)
    alice.update_shop_manifest(
        add_payee=payee,
        add_currencies=[base_currency],
        set_base_currency=base_currency)
    assert alice.errors == 0

    oid = alice.create_order()
    alice.add_to_order(oid, iid, 1)

    # Attempt to commit order with chain_id 1 matching payee but not base currency
    curr_invalid = shop_pb2.ShopCurrency(token_addr=erc20_addr, chain_id=2)
    alice.expect_error = True
    alice.commit_order(oid, curr_invalid, "escrow")
    assert alice.errors != 0
    print(f'Failed to finalize order {oid} due to chain_id mismatch with base currency')
