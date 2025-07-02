# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

from typing import List
from massmarket import (
    subscription_pb2,
    base_types_pb2 as pb_base,
)
from massmarket.envelope_pb2 import Envelope
from .utils import RelayException


class SubscriptionManager:
    """Manages relay subscriptions."""

    def __init__(self, connection_manager, debug=False):
        self.connection_manager = connection_manager
        self.debug = debug
        self.subscription = None

    def subscribe_all(self, shop_token_id: int, last_seq_no: int):
        """Subscribe to all object types."""
        all_filters = [
            subscription_pb2.SubscriptionRequest.Filter(object_type=t)
            for t in subscription_pb2.ObjectType.keys()[1:]
        ]
        return self.subscribe(all_filters, shop_token_id, last_seq_no)

    def subscribe_visitor(self, shop_token_id: int, last_seq_no: int):
        """Subscribe as a visitor."""
        types = [
            "OBJECT_TYPE_LISTING",
            "OBJECT_TYPE_TAG",
            "OBJECT_TYPE_ACCOUNT",
            "OBJECT_TYPE_MANIFEST",
            "OBJECT_TYPE_INVENTORY",
        ]
        filters = [
            subscription_pb2.SubscriptionRequest.Filter(object_type=t) for t in types
        ]
        return self.subscribe(filters, shop_token_id, last_seq_no)

    def subscribe_customer(self, shop_token_id: int, last_seq_no: int):
        """Subscribe as a customer."""
        types = [
            "OBJECT_TYPE_LISTING",
            "OBJECT_TYPE_TAG",
            "OBJECT_TYPE_ACCOUNT",
            "OBJECT_TYPE_ORDER",
            "OBJECT_TYPE_MANIFEST",
            "OBJECT_TYPE_INVENTORY",
        ]
        filters = [
            subscription_pb2.SubscriptionRequest.Filter(object_type=t) for t in types
        ]
        return self.subscribe(filters, shop_token_id, last_seq_no)

    def subscribe_order(self, shop_token_id: int, last_seq_no: int, order_id=None):
        """Subscribe to a specific order."""
        filters = [
            subscription_pb2.SubscriptionRequest.Filter(
                object_type="OBJECT_TYPE_ORDER",
                object_id=order_id,
            )
        ]
        return self.subscribe(filters, shop_token_id, last_seq_no)

    def subscribe(self, filters: List, shop_token_id: int, last_seq_no: int):
        """Subscribe to specific filters."""
        req_id = self.connection_manager.next_request_id()
        req = subscription_pb2.SubscriptionRequest(
            start_shop_seq_no=last_seq_no,
            shop_id=pb_base.Uint256(raw=shop_token_id.to_bytes(32, "big")),
            filters=filters,
        )
        msg = Envelope(
            request_id=req_id,
            subscription_request=req,
        )

        self.connection_manager.outgoing_requests[req_id.raw] = {
            "waiting": True,
            "handler": self._handle_subscription_response,
        }

        self.connection_manager.send_message(msg)

        # Wait for response
        timeout = 100
        while "waiting" in self.connection_manager.outgoing_requests[req_id.raw]:
            print("Subscription waiting")
            self.connection_manager.handle_all()
            assert timeout > 0, "timeout"
            timeout -= 1

        resp = self.connection_manager.outgoing_requests[req_id.raw]
        if not self.connection_manager.expect_error:
            subscription_id = resp["subscription_id"]
            print(f"Subscription: {subscription_id} open")
            self.subscription = subscription_id
            return subscription_id
        else:
            return resp

    def cancel_subscription(self, subscription_id: int):
        """Cancel a subscription."""
        req_id = self.connection_manager.next_request_id()
        req = subscription_pb2.SubscriptionCancelRequest(
            subscription_id=subscription_id.to_bytes(2, "big"),
        )
        msg = Envelope(
            request_id=req_id,
            subscription_cancel_request=req,
        )
        self.connection_manager.outgoing_requests[req_id.raw] = {
            "waiting": True,
            "subscription_id": subscription_id,
            "handler": self._handle_subscription_cancel_response,
        }
        self.connection_manager.send_message(msg)

        # Wait for response
        while "waiting" in self.connection_manager.outgoing_requests[req_id.raw]:
            print("Subscription cancel waiting")
            self.connection_manager.handle_all()

    def _handle_subscription_response(self, msg: Envelope):
        """Handle subscription response."""

        resp = msg.response
        if self.debug:
            print(f"SubscriptionResponse: {resp}")

        req_id = msg.request_id
        self.connection_manager._check_expected_request(req_id, clean=True)

        if resp.WhichOneof("response") == "error":
            self.connection_manager.errors += 1
            if self.connection_manager.expect_error:
                print(f"Expected error: {resp.error}")
                self.connection_manager.last_error = resp.error
                self.connection_manager.outgoing_requests[req_id.raw] = {
                    "err": resp.error
                }
            else:
                raise RelayException(resp.error)
        else:
            assert len(resp.payload) == 2
            subscription_id = int.from_bytes(resp.payload, "big")
            self.connection_manager.outgoing_requests[req_id.raw] = {
                "subscription_id": subscription_id,
            }

    def _handle_subscription_cancel_response(self, msg: Envelope):
        """Handle subscription cancel response."""

        resp = msg.response
        if self.debug:
            print(f"SubscriptionCancelResponse: {resp}")
        req_id = msg.request_id
        self.connection_manager._check_expected_request(req_id, clean=False)
        if resp.WhichOneof("response") == "error":
            self.connection_manager.errors += 1
            if self.connection_manager.expect_error:
                print(f"Expected error: {resp.error}")
                self.connection_manager.last_error = resp.error
                self.connection_manager.outgoing_requests[req_id.raw] = {
                    "err": resp.error
                }
            else:
                raise RelayException(resp.error)
        else:
            del self.connection_manager.outgoing_requests[req_id.raw]["waiting"]
            subscription_id = self.connection_manager.outgoing_requests[req_id.raw][
                "subscription_id"
            ]
            self.subscription = None
