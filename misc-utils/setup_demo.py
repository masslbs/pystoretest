# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import time
import threading
import binascii

from client import RelayClient
from massmarket import shop_pb2, shop_events_pb2

cid = 11155111


def demo_client():
    rc = RelayClient(relay_token_id=0, chain_id=cid)
    rc.shop_token_id = int(
        "805e83d38d5c946bc1559f7d80ce94bce13a4cc0ec4640426bc81835f5958a57", 16
    )

    rc.enroll_key_card()
    assert rc.errors == 0
    assert len(rc.all_key_cards) == 1
    rc.login()
    assert rc.logged_in
    print("logged in!")
    # first time task
    # rc.create_shop_manifest()
    # assert rc.errors == 0
    # print("manifest written!")

    # tid = rc.create_tag("published2")
    # assert rc.errors == 0
    # rc.update_shop_manifest(published_tag_id=tid)
    # assert rc.errors == 0

    def handle():
        while rc.logged_in:
            rc.handle_all()
            time.sleep(3)

    thread = threading.Thread(target=handle)
    thread.daemon = True  # This makes the thread exit when the main program exits
    thread.start()

    return rc


def currencies():
    tok = binascii.unhexlify("be9fe9b717c888a2b2ca0a6caa639afe369249c5")
    curr = shop_pb2.ShopCurrency(chain_id=cid, token_addr=tok)
    owner = binascii.unhexlify("b6eD252e6813340aadfa602d3Dbc219ec20D4069")
    p = shop_events_pb2.UpdateShopManifest.Payee(
        name="default", chain_id=cid, addr=owner
    )
    return (curr, p)


if __name__ == "__main__":
    demo_client()
