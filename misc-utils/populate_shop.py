# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import time
import sys
import os
import cbor2
import binascii

from massmarket.cbor import Shop
import massmarket.cbor.patch as mass_patch
from massmarket.cbor import Listing

from massmarket_client.client import RefactoredRelayClient


def main(shop_id: int, shop: Shop):
    rc = RefactoredRelayClient(
        wallet_private_key=os.getenv("ETH_PRIVATE_KEY"),
        key_card_private_key=binascii.unhexlify(
            "e878d4a61e3d3d8665c92d896cb3d02137f0ce86f6cf93347a4a060c36e5f45d"
        ),
        key_card_nonce=1,
        relay_http_address="https://relay-sepolia.mass.market",
        relay_token_id=0x0,
        chain_id=11155111,
    )
    rc.shop_token_id = shop_id
    try:
        # rc.enroll_key_card()
        # print("KC private key:", rc.own_key_card.key.hex())

        rc.login()
        assert rc.logged_in
        print("logged in!")
        assert rc.shop is not None

        rc.handle_all()
        rc.print_state()

        # prior test data
        skip_ids = [
            2531125628,  # pepe and co
            # old
            2648648132,
            2635876615,
            2039526369,
            1806408744,
        ]

        # patchset 1) listing + manifest
        rc.start_batch()
        # replace manifest
        rc._write_patch(
            obj=shop.manifest,
            type=mass_patch.ObjectType.MANIFEST,
            op=mass_patch.OpString.REPLACE,
            wait=False,
        )

        # create patchset for listings
        def mk_listing(id_bytes, listing_data):
            id = int.from_bytes(id_bytes, "big")
            listing = Listing.from_cbor_dict(listing_data)
            assert id == listing.id
            if listing in skip_ids:
                print(f"skipping listing {listing.id}")
                return True
            rc._write_patch(
                obj=listing,
                object_id=listing.id,
                type=mass_patch.ObjectType.LISTING,
                op=mass_patch.OpString.ADD,
                wait=False,
            )
            return True

        shop.listings.all(mk_listing)
        rc.flush_batch()

        # create patchset for inventory
        rc.start_batch()

        def mk_inventory(id_bytes, count):
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

        shop.inventory.all(mk_inventory)
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
    if shop_id[:2] != "0x":
        print("shop_id needs to be a hex string")
        sys.exit(1)

    shop_id = int(shop_id, 16)
    print(f"shop_id: {shop_id}")

    filename = sys.argv[2]
    f = sys.stdin if filename == "-" else open(filename, "rb")

    shop_data = cbor2.load(f)
    # v5 upgrade
    shop_data["Manifest"]["OrderPaymentTimeout"] = 86400000000000  # 24hrs
    shop = Shop.from_cbor_dict(shop_data)

    main(shop_id, shop)
