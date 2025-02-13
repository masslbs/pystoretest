# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import time
import binascii
import pprint

from client import RelayClient

# TODO: this is old v3 code
from massmarket import shop_pb2, shop_events_pb2


def main():
    rc = RelayClient(
        # wallet_private_key="",
        # key_card_private_key=binascii.unhexlify(""),
        relay_token_id=0,
        chain_id=11155111,
    )
    rc.shop_token_id = int("42", 16)
    try:
        # rc.add_relay_to_shop(int("0", 16))
        # print("relay added")
        # return

        rc.enroll_key_card()
        assert rc.errors == 0
        # TODO: rc.shop...
        assert len(rc.all_key_cards) == 1
        rc.login()
        assert rc.logged_in == True
        print("logged in!")

        rc.handle_all()
        rc.print_state()

        # first time task
        # rc.create_shop_manifest()
        # assert rc.errors == 0
        # print("manifest written!")

        # add OP
        # TODO: patch
        op_eth = shop_pb2.ShopCurrency(chain_id=11155420, token_addr=bytes(20))
        op_payee = shop_events_pb2.UpdateShopManifest.Payee(
            name="op eth",
            addr=bytes.fromhex(rc.account.address[2:]),
            chain_id=op_eth.chain_id,
        )
        # rc.update_shop_manifest(
        # add_currency = op_eth,
        # add_payee = op_payee,
        # )
        # assert rc.errors == 0

        # iid = rc.create_item('shoes', '1000')
        # assert rc.errors == 0
        # print(f"shoes: {iid}")
        iid = binascii.unhexlify(
            "81d93ac68e95c6487eb49b0bb2612930dacf9aaec8e2221538e4c70e5b552b83"
        )

        # rc.change_stock([ (iid, 10) ])
        # assert rc.errors == 0

        oid = rc.create_order()
        rc.add_to_order(oid, iid, 2)
        assert rc.errors == 0

        rc.commit_order(oid, currency=op_eth, payee_name="op eth")
        assert rc.errors == 0

        while True:
            rc.handle_all()
            time.sleep(10)
    finally:
        rc.close()


if __name__ == "__main__":
    main()
