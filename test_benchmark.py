# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

import datetime as dt
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable

# pip
import pytest
import humanize

# our imports
from massmarket.cbor import patch as mass_patch

from client import RelayClient
import objfactory

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(threadName)s: %(message)s"
)
logger = logging.getLogger(__name__)


def now():
    return dt.datetime.now()


def since(start):
    return now() - start


def human_bytes(i: int):
    return humanize.filesize.naturalsize(i)


def human_durr(dt: dt.timedelta):
    return humanize.naturaldelta(dt)


@pytest.mark.parametrize("batch_size", [1, 10, 50, 100, 250])
def test_bench_upload_listings_no_wait(
    make_client: Callable[..., RelayClient], benchmark, batch_size
):
    sender = make_client("tx")
    sender.register_shop()
    sender.enroll_key_card()
    sender.login()
    sender.handle_all()
    assert sender.errors == 0
    sender.create_shop_manifest()
    assert sender.errors == 0

    count = 250
    rounds = 15
    assert count * rounds > 1000

    def create_listings():
        return ([objfactory.create_test_listings(count)]), {}

    def upload(listings):
        # in this test we don't write for responses
        # but if we dont respond to pings we will get disconnected
        last_handle = now()

        if batch_size > 1:
            # Process in batches
            for i in range(0, len(listings), batch_size):
                if since(last_handle).seconds > 2:
                    sender.handle_all()
                    last_handle = now()

                batch = listings[i : i + batch_size]
                sender.start_batch()
                for l in batch:
                    sender._write_patch(
                        obj=l,
                        object_id=l.id,
                        type=mass_patch.ObjectType.LISTING,
                        op="add",
                        wait=False,
                    )
                sender.flush_batch(wait=False)
        else:
            # Process individually (no batching)
            for l in listings:
                if since(last_handle).seconds > 2:
                    sender.handle_all()
                    last_handle = now()
                sender._write_patch(
                    obj=l,
                    object_id=l.id,
                    type=mass_patch.ObjectType.LISTING,
                    op="add",
                    wait=False,
                )

        sender.handle_all()

    benchmark.pedantic(
        upload,
        setup=create_listings,
        rounds=rounds,
    )
    sender.close()


# mostly educational, showing the shortcoming of not using event-driven network io
# the handle_all() > connection.recv() with timeout handling, introduces a stark penalty
# once we do batched event writing this should equalize out (since we dont need to send one request per listing)
def skip_test_bench_upload_listings_wait_response(
    make_client: Callable[..., RelayClient], benchmark
):
    sender = make_client("tx")
    sender.register_shop()
    sender.enroll_key_card()
    sender.login()
    sender.handle_all()
    assert sender.errors == 0
    sender.create_shop_manifest()
    assert sender.errors == 0

    count = 250
    rounds = 4
    assert count * rounds >= 1000

    def create_listings():
        return ([objfactory.create_test_listings(count)]), {}

    def upload(listings):
        for l in listings:
            sender._write_patch(
                obj=l,
                object_id=l.id,
                type=mass_patch.ObjectType.LISTING,
                op="add",
            )

    benchmark.pedantic(
        upload,
        setup=create_listings,
        rounds=rounds,
    )
    sender.close()


def test_bench_download_listings(make_client: Callable[..., RelayClient], benchmark):
    # create a shop and a bunch of listings
    sender = make_client("tx")
    shop_id = sender.register_shop()
    sender.enroll_key_card()
    sender.login()
    sender.handle_all()
    assert sender.errors == 0
    sender.create_shop_manifest()
    assert sender.errors == 0

    count = 250
    listings = objfactory.create_test_listings(count)
    rounds = 15
    assert count * rounds > 1000

    # upload listings
    last_handle = now()
    for l in listings:
        if since(last_handle).seconds > 2:
            sender.handle_all()
            last_handle = now()
        sender._write_patch(
            obj=l,
            object_id=l.id,
            type=mass_patch.ObjectType.LISTING,
            op="add",
            wait=False,
        )
    sender.handle_all()
    sender.close()

    rxers = []

    def create_new_receiver():
        receiver = make_client("rx")
        receiver.account = sender.account
        receiver.shop_token_id = shop_id
        receiver.enroll_key_card()
        receiver.login(subscribe=False)
        rxers.append(receiver)
        return [receiver], {}

    def download(rx):
        rx.subscribe_all()
        fetch_start = now()
        while rx.shop.listings.size < count:
            assert since(fetch_start).seconds < 10
            rx.handle_all()
        return rx.shop.listings.size

    result = benchmark.pedantic(
        download,
        setup=create_new_receiver,
        rounds=rounds,
    )
    assert result == count
    for r in rxers:
        r.close()


@pytest.mark.parametrize("num_clients", [64, 128])
def test_bench_client_concurrency(
    make_client: Callable[..., RelayClient], benchmark, num_clients
):
    idle_time = 5

    # TODO: we could make one shop and enroll keycards for each client
    # but for some reason then we have timeouts...

    def setup_client(i):
        client = make_client(f"client_{i}", auto_connect=False)
        client.register_shop()
        client.enroll_key_card()
        assert client.connected == False
        return client

    def setup_clients():
        cs = []
        futures = None
        with ThreadPoolExecutor(max_workers=num_clients) as executor:
            futures = {executor.submit(setup_client, i): i for i in range(num_clients)}
        for f in as_completed(futures):
            cs.append(f.result())
        return [cs], {}

    # login and ping<>pong loop
    def client_session(client: RelayClient):
        assert client.connected == False
        logger.info(f"{client.name} started")
        client.relay_ping = 2
        client.login()
        logger.info(f"{client.name} logged in")
        assert client.errors == 0
        client.relay_ping = 0.75
        try:
            start = now()
            while since(start).seconds < idle_time:
                client.handle_all()  # respond to pings
            if client.errors > 0:
                logger.error(f"{client.name} had errors: {client.last_error}")
                return False
            client.close()
            logger.info(f"{client.name} closed")
            return True
        except Exception as e:
            logger.error(f"Client {client.name} failed: {e}")
            return False

    def concurrent_clients(clients):
        successful_connections = 0
        with ThreadPoolExecutor(max_workers=num_clients) as executor:
            session_futures = {executor.submit(client_session, c): c for c in clients}
            for f in as_completed(session_futures):
                if f.result():
                    successful_connections += 1
        return successful_connections

    result = benchmark.pedantic(concurrent_clients, setup=setup_clients, rounds=1)
    assert result == num_clients
