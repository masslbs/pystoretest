import os

from client import RelayClient

def test_create_shop_manifest(wc_auth: RelayClient):
    wc_auth.create_shop_manifest()
    assert wc_auth.errors == 0
    wc_auth.close()

def test_invite_another_user(wc_auth: RelayClient):
    # owner creates a token for the new clerk
    owner = wc_auth
    reg_secret = owner.create_invite()
    owner.handle_all()
    assert owner.errors == 0
    # new_clerk has it's own private key
    bob_key = bytes.hex(os.urandom(32))
    new_clerk = RelayClient(name="Bob", wallet_private_key=bob_key)
    new_clerk.shop_token_id = owner.shop_token_id

    # give clerk some eth so they can run transactions
    transaction = {
        'to': new_clerk.account.address,
        'value': owner.w3.to_wei(0.5, "ether"),
        'gas': 25000,
        'maxFeePerGas': owner.w3.to_wei(50, 'gwei'),
        'maxPriorityFeePerGas': owner.w3.to_wei(5, 'gwei'),
        'nonce': owner.w3.eth.get_transaction_count(owner.account.address),
        'chainId': owner.chain_id
    }
    signed_txn = owner.account.sign_transaction(transaction)
    tx_hash = owner.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    owner.check_tx(tx_hash)

    # use token
    new_clerk.redeem_invite(reg_secret)
    # check we can log in
    new_clerk.enroll_key_card()
    assert new_clerk.errors == 0
    new_clerk.login()
    new_clerk.handle_all()
    assert new_clerk.errors == 0
    new_clerk.close()
    assert len(new_clerk.all_key_cards) == 2
    owner.handle_all()
    assert len(owner.all_key_cards) == 2
    assert new_clerk.all_key_cards == owner.all_key_cards

    # done
    owner.close()
    new_clerk.close()
