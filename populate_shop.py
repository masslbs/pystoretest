# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import time
import sys
import os
import cbor2

from massmarket.cbor import Shop
import massmarket.cbor.patch as mass_patch

from client import RelayClient


def main(shop_id: int, shop: Shop):
    rc = RelayClient(
        wallet_private_key=os.getenv("ETH_PRIVATE_KEY"),
        # key_card_private_key=binascii.unhexlify(""),
        # key_card_nonce=23,
        relay_http_address="https://relay-sepolia.mass.market",
        relay_token_id=0x0,
        chain_id=11155111,
    )
    rc.shop_token_id = shop_id
    try:
        rc.enroll_key_card()
        print("KC private key:", rc.own_key_card.key.hex())

        rc.login()
        assert rc.logged_in
        print("logged in!")

        rc.handle_all()
        rc.print_state()

        rc.start_batch()

        # prior test data
        skip_ids = [
            2648648132,
            2635876615,
            2039526369,
            1806408744,
        ]

        def make_patch(id_bytes, count):
            id = int.from_bytes(id_bytes, "big")
            if rc.shop.inventory.get(id) is not None:
                print(f"inventory {id} already exists")
                return True
            if id in skip_ids:
                print(f"skipping listing {id}")
                return True
            rc._write_patch(
                obj=count,
                object_id=id,
                type=mass_patch.ObjectType.INVENTORY,
                op=mass_patch.OpString.ADD,
                wait=False,
            )
            return True

        shop.inventory.all(make_patch)

        rc.flush_batch()

        rc.debug = True
        while True:
            rc.handle_all()
            time.sleep(2)
    finally:
        rc.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python populate_shop.py <shop_id> <filename>")
        sys.exit(1)

    shop_id = sys.argv[1]
    if shop_id[:2] == "0x":
        shop_id = int(shop_id, 16)
        print(f"shop_id: {shop_id}")

    filename = sys.argv[2]
    f = sys.stdin if filename == "-" else open(filename, "rb")

    shop_data = cbor2.load(f)
    shop = Shop.from_cbor_dict(shop_data)

    main(shop_id, shop)
