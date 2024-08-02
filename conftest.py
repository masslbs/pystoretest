from typing import Generator, Callable, Tuple, Any, List

import atexit
import threading
import os
import tempfile
import json

import filelock

import pytest
from web3 import Web3, Account, HTTPProvider
from web3.middleware import construct_sign_and_send_raw_middleware

from client import RelayClient, check_transaction


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


@pytest.fixture
def wc_conn(account_manager) -> RelayClient:
    ta = account_manager.get_test_account()
    return RelayClient(wallet_account=ta)


@pytest.fixture
def wc_shop(wc_conn: RelayClient) -> RelayClient:
    wc_conn.register_shop()
    wc_conn.enroll_key_card()
    return wc_conn


@pytest.fixture
def wc_auth(account_manager) -> RelayClient:
    ta = account_manager.get_test_account()
    conn = RelayClient(wallet_account=ta)
    conn.register_shop()
    conn.enroll_key_card()
    conn.login()
    assert conn.logged_in == True
    return conn


@pytest.fixture
def make_client(account_manager) -> Generator[Callable[..., RelayClient], Any, Any]:
    created_clients: List[RelayClient] = []

    def _make_client(
        name: str,
        shop=None,
        guest: bool = False,
        private_key: bytes | None = None,
        auto_connect: bool = True,
    ):
        acc = None
        if not private_key:
            acc = account_manager.get_test_account()
        c = RelayClient(
            name=name,
            guest=guest,
            wallet_account=acc,
            wallet_private_key=private_key,
            auto_connect=auto_connect,
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
) -> Generator[Tuple[RelayClient, RelayClient], Any, Any]:
    # both alices share the same private wallet but have different keycards
    a1 = make_client("alice.1")
    a2 = make_client("alice.2")
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
    while a2.manifest is None:
        a2.handle_all()
        assert a2.errors == 0
        retry -= 1
        assert retry > 0, "failed to get manifest"
    big_token_id = int.from_bytes(a2.manifest.token_id.raw, "big")
    owner_addr = a2.shopReg.functions.ownerOf(big_token_id).call()
    assert owner_addr == a1.account.address
    yield (a1, a2)


class TestAccountManager:
    def __init__(
        self,
        funded_account: Account,
        initial_balance: int = Web3.to_wei(0.05, "ether"),
    ):
        self.funded_account = funded_account
        self.w3 = Web3(HTTPProvider(os.getenv("ETH_RPC_URL")))
        sign_mw = construct_sign_and_send_raw_middleware(self.funded_account)
        self.w3.middleware_onion.add(sign_mw)

        self.initial_balance = initial_balance

        # Create a file-based lock in a temp directory
        temp_dir = tempfile.gettempdir()
        self.lock_file = os.path.join(temp_dir, "eth_test_nonce.lock")
        self.nonce_file = os.path.join(temp_dir, "eth_test_nonce.json")
        self.file_lock = filelock.FileLock(self.lock_file)

    def _get_and_increment_nonce(self):
        with self.file_lock:
            try:
                if os.path.exists(self.nonce_file):
                    with open(self.nonce_file, "r") as f:
                        saved_nonce = json.load(f)
                else:
                    saved_nonce = self.w3.eth.get_transaction_count(
                        self.funded_account.address
                    )

                current_nonce = saved_nonce

                # Save incremented nonce
                with open(self.nonce_file, "w") as f:
                    json.dump(saved_nonce + 1, f)

                return current_nonce
            except Exception as e:
                # If anything goes wrong, fall back to network nonce
                return self.w3.eth.get_transaction_count(self.funded_account.address)

    def get_test_account(self) -> Account:
        new_account = Account.create()

        max_retries = 3
        for attempt in range(max_retries):
            try:
                nonce = self._get_and_increment_nonce()

                transaction = {
                    "to": new_account.address,
                    "value": self.initial_balance,
                    "nonce": nonce,
                    "gas": 21000,
                    "maxFeePerGas": self.w3.to_wei(50, "gwei"),
                    "maxPriorityFeePerGas": self.w3.to_wei(5, "gwei"),
                    "chainId": 31337,
                }
                recpt = self.w3.eth.send_transaction(transaction)
                check_transaction(self.w3, recpt)
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
