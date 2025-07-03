# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

from client import RelayClient
import time

rc = RelayClient(wallet_private_key=None, key_card_private_key=None)
rc.shop_token_id = int("23", 16)
try:
    # rc.add_relay_to_shop(int("6d0e5a049754cbcd13c81458221d5d313c5e5685ef99862acd5846a66cf1f422", 16))
    # os.exit()
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

    # rc.create_item('shoes', '1000')
    # assert rc.errors == 0

    rc.print_state()

    while True:
        rc.handle_all()
        time.sleep(10)

finally:
    rc.close()
