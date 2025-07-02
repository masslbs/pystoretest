# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

from typing import Generator, Tuple, Any, List, Protocol

import atexit
import threading
import os
import json

import filelock

import pytest
from web3 import Web3, Account, HTTPProvider
from web3.middleware import SignAndSendRawMiddlewareBuilder

from massmarket_client.legacy_client import RelayClient
from massmarket_client.client import RefactoredRelayClient
from massmarket_client import RelayClientProtocol
from massmarket_client.utils import check_transaction


# it can happen that a missing .close() on the client leaves a dangling thread.
# this can't tell you _which_ test it was but if the thread.name contains recv_events it's a websocket connection
def print_running_threads():
    alive = [t for t in threading.enumerate() if t.is_alive()]
    if len(alive) == 0:
        return
    print("\nThreads still running after tests:")
    for t in alive:
        print(f"  - {t.name} (daemon: {t.daemon})")


atexit.register(print_running_threads)

use_refactored = os.getenv("USE_REFACTORED_CLIENT", "false").lower() == "true"


class MakeClientCallable(Protocol):
    def __call__(
        self,
        name: str,
        shop: int | None = None,
        guest: bool = False,
        private_key: bytes | None = None,
        auto_connect: bool = True,
        validate_patches: bool = True,
    ) -> RelayClientProtocol: ...


@pytest.fixture
def wc_conn(account_manager) -> RelayClientProtocol:
    ta = account_manager.get_test_account()

    if use_refactored:
        return RefactoredRelayClient(name="wc_conn", wallet_account=ta)
    else:
        return RelayClient(name="wc_conn", wallet_account=ta)


@pytest.fixture
def wc_shop(wc_conn: RelayClientProtocol) -> RelayClientProtocol:
    wc_conn.register_shop()
    wc_conn.enroll_key_card()
    return wc_conn


@pytest.fixture
def wc_auth(account_manager) -> RelayClientProtocol:
    ta = account_manager.get_test_account()

    if use_refactored:
        conn = RefactoredRelayClient(name="wc_auth", wallet_account=ta)
    else:
        conn = RelayClient(name="wc_auth", wallet_account=ta)

    conn.register_shop()
    conn.enroll_key_card()
    conn.login()
    assert conn.logged_in == True
    return conn


@pytest.fixture
def make_client(
    account_manager,
) -> Generator[MakeClientCallable, Any, Any]:
    created_clients: List[RelayClientProtocol] = []

    def _make_client(
        name: str,
        shop: int | None = None,
        guest: bool = False,
        private_key: bytes | None = None,
        auto_connect: bool = True,
        validate_patches: bool = True,
    ) -> RelayClientProtocol:
        acc = None
        if not private_key:
            acc = account_manager.get_test_account()

        if use_refactored:
            c = RefactoredRelayClient(
                name=name,
                guest=guest,
                wallet_account=acc,
                wallet_private_key=private_key,
                auto_connect=auto_connect,
                validate_patches=validate_patches,
            )
        else:
            c = RelayClient(
                name=name,
                guest=guest,
                wallet_account=acc,
                wallet_private_key=private_key,
                auto_connect=auto_connect,
                validate_patches=validate_patches,
            )

        if shop is not None:
            c.shop_token_id = shop
        created_clients.append(c)
        return c

    yield _make_client
    for c in created_clients:
        c.close()
    print(f"{len(created_clients)} clients closed")


@pytest.fixture
def cleanup():
    to_close = []
    yield to_close
    for c in to_close:
        print(f"closing {c.name}")
        c.close()


@pytest.fixture
def make_two_clients(
    make_client, cleanup
) -> Generator[Tuple[RelayClientProtocol, RelayClientProtocol], Any, Any]:
    # both alices share the same private wallet but have different keycards
    a1: RelayClientProtocol = make_client("alice.1")
    a2: RelayClientProtocol = make_client("alice.2")
    cleanup.append(a1)
    cleanup.append(a2)
    shop_id = a1.register_shop()
    a1.enroll_key_card()
    a2.shop_token_id = shop_id
    a2.account = a1.account
    a2.enroll_key_card()
    a1.login()
    a2.login()
    assert a1.errors == 0
    assert a2.errors == 0
    retry = 10
    while a1.all_key_cards != a2.all_key_cards:
        a1.handle_all()
        a2.handle_all()
        retry -= 1
        assert retry > 0, "failed to get two key cards"
    assert len(a1.all_key_cards) == 2
    assert len(a2.all_key_cards) == 2
    assert a1.all_key_cards == a2.all_key_cards
    a1.create_shop_manifest()
    assert a1.errors == 0
    retry = 10
    while a2.shop is not None and len(a2.shop.manifest.payees) == 0:
        a2.handle_all()
        assert a2.errors == 0
        retry -= 1
        assert retry > 0, "failed to get manifest"
    assert a2.shop is not None
    big_token_id = a2.shop.manifest.shop_id
    owner_addr = a2.shopReg.functions.ownerOf(big_token_id).call()
    assert owner_addr == a1.account.address
    assert a1.shop is not None and len(a1.shop.manifest.payees) == 1
    assert a2.shop is not None and len(a2.shop.manifest.payees) == 1
    assert (
        a1.shop is not None
        and a2.shop is not None
        and a2.shop.manifest.payees == a1.shop.manifest.payees
    )
    yield (a1, a2)


@pytest.fixture
def make_two_guests(
    make_client: MakeClientCallable,
) -> Generator[
    Tuple[RelayClientProtocol, RelayClientProtocol, RelayClientProtocol], None, None
]:
    # create the owner/clerk
    charlie: RelayClientProtocol = make_client("charlie")
    shop_id = charlie.register_shop()
    charlie.enroll_key_card()
    charlie.login()
    charlie.create_shop_manifest()
    assert charlie.errors == 0

    # create two guests
    guest1: RelayClientProtocol = make_client(
        "guest1", shop=shop_id, guest=True, private_key=os.urandom(32)
    )
    guest1.enroll_key_card()
    guest1.login(subscribe=False)
    guest1.handle_all()
    guest1.subscribe_customer()
    assert guest1.errors == 0

    guest2: RelayClientProtocol = make_client(
        "guest2", shop=shop_id, guest=True, private_key=os.urandom(32)
    )
    guest2.enroll_key_card()
    guest2.login(subscribe=False)
    guest2.handle_all()
    guest2.subscribe_customer()
    assert guest2.errors == 0

    yield (charlie, guest1, guest2)

    charlie.close()
    guest1.close()
    guest2.close()


class TestAccountManager:
    def __init__(
        self,
        funded_account: Account,
        initial_balance: int = Web3.to_wei(0.05, "ether"),
    ):
        self.funded_account = funded_account
        self.w3 = Web3(HTTPProvider(os.getenv("ETH_RPC_URL")))
        sign_mw = SignAndSendRawMiddlewareBuilder.build(self.funded_account)
        self.w3.middleware_onion.inject(sign_mw, layer=0)  # type: ignore

        self.initial_balance = initial_balance

        # Create a file-based lock in a temp directory
        temp_dir = os.getcwd() if os.getcwd().startswith('/tmp/pystoretest.') else '/tmp/pystoretest'
        os.makedirs(temp_dir, exist_ok=True)
        self.lock_file = os.path.join(temp_dir, "eth_test_nonce.lock")
        self.nonce_file = os.path.join(temp_dir, "eth_test_nonce.json")
        self.file_lock = filelock.FileLock(self.lock_file)

        # Initialize nonce file properly
        self._initialize_nonce_file()

    def _initialize_nonce_file(self):
        """Initialize the nonce file with the current network nonce if it doesn't exist or is behind"""
        with self.file_lock:
            network_nonce = self.w3.eth.get_transaction_count(
                self.funded_account.address  # type: ignore
            )

            if not os.path.exists(self.nonce_file):
                # File doesn't exist, create it with network nonce
                with open(self.nonce_file, "w") as f:
                    json.dump(network_nonce, f)
            else:
                # File exists, but check if it's behind the network
                with open(self.nonce_file, "r") as f:
                    file_nonce = json.load(f)

                if file_nonce < network_nonce:
                    # Our file is behind, update it to match network
                    with open(self.nonce_file, "w") as f:
                        json.dump(network_nonce, f)

    def get_test_account(self) -> Account:
        new_account = Account.create()

        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Move transaction sending inside the file lock to prevent race conditions
                with self.file_lock:
                    # Get nonce from file
                    with open(self.nonce_file, "r") as f:
                        current_nonce = json.load(f)

                    # Double-check our nonce isn't behind the network
                    network_nonce = self.w3.eth.get_transaction_count(
                        self.funded_account.address  # type: ignore
                    )
                    if current_nonce < network_nonce:
                        # We're behind, sync up
                        current_nonce = network_nonce
                        with open(self.nonce_file, "w") as f:
                            json.dump(current_nonce, f)

                    # Build and send transaction atomically with nonce allocation
                    transaction = {
                        "to": new_account.address,
                        "value": self.initial_balance,
                        "nonce": current_nonce,
                        "gas": 21000,
                        "maxFeePerGas": self.w3.to_wei(50, "gwei"),
                        "maxPriorityFeePerGas": self.w3.to_wei(5, "gwei"),
                        "chainId": 31337,
                    }
                    recpt = self.w3.eth.send_transaction(transaction)  # type: ignore
                    check_transaction(self.w3, recpt)

                    # Only increment nonce after successful transaction send
                    with open(self.nonce_file, "w") as f:
                        json.dump(current_nonce + 1, f)

                    return new_account

            except Exception as e:
                if attempt == max_retries - 1:
                    raise e
                continue

        raise Exception("max_retries exceeded")


@pytest.fixture(scope="session")
def account_manager():
    k = os.getenv("ETH_PRIVATE_KEY")
    assert k is not None, "ETH_PRIVATE_KEY not set"
    funded_private_key = bytes.fromhex(k)
    funded_account = Account.from_key(funded_private_key)
    return TestAccountManager(funded_account)
