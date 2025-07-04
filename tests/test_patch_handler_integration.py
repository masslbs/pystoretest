# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

"""Integration tests for PatchHandler with RefactoredRelayClient."""

import pytest
import os
from unittest.mock import patch
from massmarket_client.client import RefactoredRelayClient
from massmarket_client.patch_handler import PatchHandler, StateChangeObserver
from massmarket.cbor.order import Order
from massmarket.cbor.patch import Patch, ObjectType, OpString, PatchPath


class NotificationHandler(StateChangeObserver):
    """Example notification handler that tracks order state changes."""

    def __init__(self):
        self.order_changes = []
        self.payment_confirmations = []
        self.shipping_updates = []

    def on_state_change(self, object_type, object_id, before_state, after_state):
        if object_type == "orders":
            self.order_changes.append(
                {"id": object_id, "before": before_state, "after": after_state}
            )

            # Track specific transitions
            if before_state and after_state:
                if (
                    before_state.payment_state == "UNPAID"
                    and after_state.payment_state == "PAID"
                ):
                    self.payment_confirmations.append(object_id)

                # Check for shipping address changes (including None -> value)
                before_shipping = getattr(before_state, "shipping_address", None)
                after_shipping = getattr(after_state, "shipping_address", None)
                if before_shipping != after_shipping:
                    self.shipping_updates.append(object_id)


class TestRefactoredRelayClientIntegration:
    """Test RefactoredRelayClient with custom patch handler."""

    @pytest.fixture
    def mock_env(self):
        """Set up mock environment variables."""
        with patch.dict(
            os.environ,
            {
                "RELAY_HTTP_ADDRESS": "http://localhost:4444",
                "RELAY_PING": "30",
                "RELAY_TOKEN_ID": "1",
                "CHAIN_ID": "31337",
            },
        ):
            yield

    @pytest.fixture
    def notification_handler(self):
        """Create a notification handler instance."""
        return NotificationHandler()

    @pytest.fixture
    def custom_patch_handler_factory(self, notification_handler):
        """Create a custom patch handler factory."""

        def factory(shop):
            handler = PatchHandler(shop)
            handler.add_observer(notification_handler)
            return handler

        return factory

    def test_client_with_custom_patch_handler(
        self, mock_env, custom_patch_handler_factory
    ):
        """Test creating client with custom patch handler."""
        # Create client with custom handler
        client = RefactoredRelayClient(
            name="test_merchant",
            wallet_private_key="0x" + "1" * 64,
            custom_patch_handler=custom_patch_handler_factory,
            auto_connect=False,
        )

        assert client.custom_patch_handler is not None
        assert client.custom_patch_handler == custom_patch_handler_factory

    def test_state_manager_uses_custom_handler(
        self, mock_env, custom_patch_handler_factory, notification_handler
    ):
        """Test that StateManager uses the custom patch handler."""
        # Create client with custom handler
        client = RefactoredRelayClient(
            name="test_merchant",
            wallet_private_key="0x" + "1" * 64,
            custom_patch_handler=custom_patch_handler_factory,
            auto_connect=False,
        )

        # Initialize shop (this creates the StateManager)
        client._shop_token_id = 123
        client._initialize_state_manager()

        # Verify StateManager has the custom handler factory
        assert client.state_manager.patch_handler_factory is not None
        assert (
            client.state_manager.patch_handler_factory == custom_patch_handler_factory
        )

        # Create a test order in the shop
        shop = client.state_manager.load_shop()
        order_id = 456
        test_order = Order(
            id=order_id,
            items=[],
            payment_state="UNPAID",
            invoice_address=None,
            shipping_address=None,
            chosen_currency=None,
            chosen_payee=None,
            payment_details=None,
            tx_details=None,
            canceled_at=None,
        )
        shop.orders.insert(order_id, test_order)

        # Apply a patch to change order state
        patch = Patch(
            op=OpString.REPLACE,
            path=PatchPath(
                type=ObjectType.ORDER, object_id=order_id, fields=["PaymentState"]
            ),
            value="PAID",
        )

        # Apply patch through StateManager
        client.state_manager.apply_patch(patch, 1)

        # Verify observer was notified
        assert len(notification_handler.order_changes) == 1
        assert notification_handler.order_changes[0]["id"] == str(order_id)
        assert notification_handler.order_changes[0]["before"].payment_state == "UNPAID"
        assert notification_handler.order_changes[0]["after"].payment_state == "PAID"

        # Verify payment confirmation was tracked
        assert len(notification_handler.payment_confirmations) == 1
        assert notification_handler.payment_confirmations[0] == str(order_id)

    def test_multiple_patch_applications(
        self, mock_env, custom_patch_handler_factory, notification_handler
    ):
        """Test multiple patches are handled correctly."""
        client = RefactoredRelayClient(
            name="test_merchant",
            wallet_private_key="0x" + "1" * 64,
            custom_patch_handler=custom_patch_handler_factory,
            auto_connect=False,
        )

        # Initialize shop
        client._shop_token_id = 123
        client._initialize_state_manager()

        # Create test order
        shop = client.state_manager.load_shop()
        order_id = 789
        test_order = Order(
            id=order_id,
            items=[],
            payment_state="UNPAID",
            invoice_address=None,
            shipping_address=None,
            chosen_currency=None,
            chosen_payee=None,
            payment_details=None,
            tx_details=None,
            canceled_at=None,
        )
        shop.orders.insert(order_id, test_order)

        # Apply multiple patches
        patches = [
            # Add payment details
            Patch(
                op=OpString.ADD,
                path=PatchPath(
                    type=ObjectType.ORDER, object_id=order_id, fields=["PaymentDetails"]
                ),
                value={
                    "PaymentID": bytes(32),  # 32 bytes hash
                    "Total": 2000,
                    "ListingHashes": [bytes(32)],  # List of hashes
                    "TTL": 1234567890,
                    "ShopSignature": bytes(65),  # 65 bytes signature
                },
            ),
            # Update payment state
            Patch(
                op=OpString.REPLACE,
                path=PatchPath(
                    type=ObjectType.ORDER, object_id=order_id, fields=["PaymentState"]
                ),
                value="PAID",
            ),
            # Add shipping address
            Patch(
                op=OpString.ADD,
                path=PatchPath(
                    type=ObjectType.ORDER,
                    object_id=order_id,
                    fields=["ShippingAddress"],
                ),
                value={
                    "Name": "Test User",
                    "Address1": "123 Test St",
                    "City": "Test City",
                    "Country": "US",
                    "PostalCode": "12345",
                    "EmailAddress": "test@example.com",
                },
            ),
        ]

        # Apply all patches
        assert client.state_manager
        for i, p in enumerate(patches):
            client.state_manager.apply_patch(p, i + 1)

        # Verify all changes were captured
        assert len(notification_handler.order_changes) == 3

        # Verify payment confirmation
        assert len(notification_handler.payment_confirmations) == 1
        assert notification_handler.payment_confirmations[0] == str(order_id)

        # Verify shipping update
        assert len(notification_handler.shipping_updates) == 1
        assert notification_handler.shipping_updates[0] == str(order_id)


class TestCaduceusUsageExample:
    """Test the Caduceus usage example from documentation."""

    class EmailSender:
        """Mock email sender for testing."""

        def __init__(self):
            self.sent_confirmations = []
            self.sent_status_updates = []

        def send_order_confirmation(self, order):
            self.sent_confirmations.append(order)

        def send_status_update(self, order):
            self.sent_status_updates.append(order)

    class CaduceusObserver(StateChangeObserver):
        """Caduceus observer from documentation example."""

        def __init__(self, email_sender):
            self.email_sender = email_sender

        def on_state_change(self, obj_type, obj_id, before, after):
            if obj_type == "orders":
                # Detect transitions
                if before and after:
                    if (
                        before.payment_state == "UNPAID"
                        and after.payment_state == "PAID"
                    ):
                        self.email_sender.send_order_confirmation(after)
                    elif getattr(before, "fulfillment_status", None) != getattr(
                        after, "fulfillment_status", None
                    ):
                        self.email_sender.send_status_update(after)

    @pytest.fixture
    def mock_env(self):
        """Set up mock environment variables."""
        with patch.dict(
            os.environ,
            {
                "RELAY_HTTP_ADDRESS": os.getenv(
                    "RELAY_HTTP_ADDRESS", "http://localhost:4444"
                ),
                "RELAY_PING": "30",
                "RELAY_TOKEN_ID": "1",
                "CHAIN_ID": "11155111",
            },
        ):
            yield

    def test_caduceus_integration(self, mock_env):
        """Test the complete Caduceus integration example."""
        # Create email sender
        email_sender = self.EmailSender()

        # Create custom patch handler factory with Caduceus observer
        def custom_patch_handler_factory(shop):
            handler = PatchHandler(shop)
            handler.add_observer(self.CaduceusObserver(email_sender))
            return handler

        # Create client with observer
        client = RefactoredRelayClient(
            name="caduceus",
            wallet_private_key="0x" + "2" * 64,
            custom_patch_handler=custom_patch_handler_factory,
            auto_connect=False,
        )

        # Initialize shop
        client._shop_token_id = 456
        client._initialize_state_manager()

        # Create test order
        shop = client.state_manager.load_shop()
        order_id = 1001
        test_order = Order(
            id=order_id,
            items=[],
            payment_state="UNPAID",
            invoice_address=None,
            shipping_address=None,
            chosen_currency=None,
            chosen_payee=None,
            payment_details=None,
            tx_details=None,
            canceled_at=None,
        )
        shop.orders.insert(order_id, test_order)

        # Simulate order payment
        payment_patch = Patch(
            op=OpString.REPLACE,
            path=PatchPath(
                type=ObjectType.ORDER, object_id=order_id, fields=["PaymentState"]
            ),
            value="PAID",
        )

        client.state_manager.apply_patch(payment_patch, 1)

        # Verify email was "sent"
        assert len(email_sender.sent_confirmations) == 1
        assert email_sender.sent_confirmations[0].id == order_id
        assert email_sender.sent_confirmations[0].payment_state == "PAID"
