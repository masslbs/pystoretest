# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

"""Unit tests for PatchHandler state capture and observer functionality."""

from massmarket_client.patch_handler import PatchHandler, StateChangeObserver
from massmarket.cbor import Shop
from massmarket.cbor.patch import Patch, ObjectType, OpString, PatchPath
from massmarket.cbor.manifest import Manifest
from massmarket.cbor.order import Order, OrderedItem, AddressDetails
from massmarket.cbor.listing import Listing, ListingMetadata, ListingViewState
from massmarket.cbor.base_types import Uint256
import massmarket.hamt as hamt


class MockObserver(StateChangeObserver):
    """Test observer that captures state changes."""

    def __init__(self):
        self.changes = []

    def on_state_change(self, object_type, object_id, before_state, after_state):
        self.changes.append(
            {
                "type": object_type,
                "id": object_id,
                "before": before_state,
                "after": after_state,
            }
        )


def create_test_shop():
    """Create a test shop with basic structure."""
    shop = Shop(
        schema_version=4,
        manifest=Manifest(
            shop_id=123,
            payees={},
            accepted_currencies={},
            pricing_currency=None,
            order_payment_timeout=100000000000,
        ),
        accounts=hamt.Trie.new(),
        listings=hamt.Trie.new(),
        tags=hamt.Trie.new(),
        inventory=hamt.Trie.new(),
        orders=hamt.Trie.new(),
    )
    return shop


def create_test_order(order_id=1, state=1):
    """Create a test order."""
    # Handle canceled state
    canceled_at = 1234567890 if state == 2 else None  # CANCELED requires canceled_at

    return Order(
        id=order_id,
        items=[OrderedItem(listing_id=100, quantity=2, variation_ids=None)],
        payment_state=state,
        invoice_address=AddressDetails(
            name="Test User",
            address1="123 Test St",
            city="Test City",
            country="US",
            postal_code="12345",
            email_address="test@example.com",
        ),
        shipping_address=None,
        chosen_currency=None,
        chosen_payee=None,
        payment_details=None,
        tx_details=None,
        canceled_at=canceled_at,
    )


def create_test_listing(listing_id=100, price=1000):
    """Create a test listing."""
    return Listing(
        id=listing_id,
        price=Uint256(price),
        metadata=ListingMetadata(
            title="Test Product", description="A test product", images=[]
        ),
        view_state=ListingViewState.PUBLISHED,
        options=None,
    )


class TestPatchHandlerObserver:
    """Test PatchHandler observer functionality."""

    def test_observer_registration(self):
        """Test adding and removing observers."""
        shop = create_test_shop()
        handler = PatchHandler(shop)
        observer = MockObserver()

        # Add observer
        handler.add_observer(observer)
        assert len(handler._observers) == 1

        # Remove observer
        handler.remove_observer(observer)
        assert len(handler._observers) == 0

    def test_order_state_capture_on_replace(self):
        """Test that order states are captured correctly on REPLACE operations."""
        shop = create_test_shop()
        handler = PatchHandler(shop)
        observer = MockObserver()
        handler.add_observer(observer)

        # Add initial order
        order_id = 123
        order = create_test_order(order_id, 1)  # OPEN
        shop.orders.insert(order_id, order)

        # Create patch to change order state
        patch = Patch(
            op=OpString.REPLACE,
            path=PatchPath(
                type=ObjectType.ORDER, object_id=order_id, fields=["PaymentState"]
            ),
            value=2,  # CANCELED
        )

        # Apply patch
        error = handler.apply_patch(patch)
        assert error is None

        # Verify observer was called
        assert len(observer.changes) == 1
        change = observer.changes[0]
        assert change["type"] == "orders"
        assert change["id"] == str(order_id)
        assert change["before"].payment_state == 1  # OPEN
        assert change["after"].payment_state == 2  # CANCELED

    def test_order_capture_on_add(self):
        """Test that order states are captured correctly on ADD operations."""
        shop = create_test_shop()
        handler = PatchHandler(shop)
        observer = MockObserver()
        handler.add_observer(observer)

        # Create patch to add new order
        order_id = 456
        order_data = {
            "ID": order_id,
            "Items": [],
            "PaymentState": 1,  # OPEN
        }

        patch = Patch(
            op=OpString.ADD,
            path=PatchPath(type=ObjectType.ORDER, object_id=order_id, fields=[]),
            value=order_data,
        )

        # Apply patch
        error = handler.apply_patch(patch)
        assert error is None

        # Verify observer was called
        assert len(observer.changes) == 1
        change = observer.changes[0]
        assert change["type"] == "orders"
        assert change["id"] == str(order_id)
        assert change["before"] is None  # No previous state
        assert change["after"] is not None
        assert change["after"].payment_state == 1  # OPEN

    def test_order_capture_on_remove(self):
        """Test that order states are captured correctly on REMOVE operations."""
        shop = create_test_shop()
        handler = PatchHandler(shop)
        observer = MockObserver()
        handler.add_observer(observer)

        # Add initial order
        order_id = 789
        order = create_test_order(order_id, 2)  # CANCELED
        shop.orders.insert(order_id, order)

        # Create patch to remove order
        patch = Patch(
            op=OpString.REMOVE,
            path=PatchPath(type=ObjectType.ORDER, object_id=order_id, fields=[]),
            value=None,
        )

        # Apply patch
        error = handler.apply_patch(patch)
        assert error is None

        # Verify observer was called
        assert len(observer.changes) == 1
        change = observer.changes[0]
        assert change["type"] == "orders"
        assert change["id"] == str(order_id)
        assert change["before"].id == order_id
        assert change["before"].payment_state == 2  # CANCELED
        assert change["after"] is None  # Order was removed

    def test_listing_state_capture(self):
        """Test that listing states are captured correctly."""
        shop = create_test_shop()
        handler = PatchHandler(shop)
        observer = MockObserver()
        handler.add_observer(observer)

        # Add initial listing
        listing_id = 100
        listing = create_test_listing(listing_id, 1000)
        shop.listings.insert(listing_id, listing)

        # Create patch to change listing price
        patch = Patch(
            op=OpString.REPLACE,
            path=PatchPath(
                type=ObjectType.LISTING, object_id=listing_id, fields=["Price"]
            ),
            value=2000,
        )

        # Apply patch
        error = handler.apply_patch(patch)
        assert error is None

        # Verify observer was called
        assert len(observer.changes) == 1
        change = observer.changes[0]
        assert change["type"] == "listings"
        assert change["id"] == str(listing_id)
        assert int(change["before"].price) == 1000
        assert int(change["after"].price) == 2000

    def test_multiple_observers(self):
        """Test that multiple observers are notified."""
        shop = create_test_shop()
        handler = PatchHandler(shop)
        observer1 = MockObserver()
        observer2 = MockObserver()

        handler.add_observer(observer1)
        handler.add_observer(observer2)

        # Add order
        order_id = 321
        order = create_test_order(order_id, 1)  # OPEN
        shop.orders.insert(order_id, order)

        # Apply patch
        patch = Patch(
            op=OpString.REPLACE,
            path=PatchPath(
                type=ObjectType.ORDER, object_id=order_id, fields=["PaymentState"]
            ),
            value=2,  # CANCELED
        )

        error = handler.apply_patch(patch)
        assert error is None

        # Both observers should be notified
        assert len(observer1.changes) == 1
        assert len(observer2.changes) == 1
        assert observer1.changes[0]["before"].payment_state == 1  # OPEN
        assert observer2.changes[0]["after"].payment_state == 2  # CANCELED

    def test_observer_error_handling(self):
        """Test that observer errors don't affect patch application."""
        shop = create_test_shop()
        handler = PatchHandler(shop)

        # Create observer that raises exception
        class ErrorObserver(StateChangeObserver):
            def on_state_change(self, object_type, object_id, before, after):
                raise Exception("Observer error")

        handler.add_observer(ErrorObserver())
        handler.add_observer(MockObserver())  # This one should still work

        # Add order
        order_id = 654
        order = create_test_order(order_id, 1)  # OPEN
        shop.orders.insert(order_id, order)

        # Apply patch - should succeed despite observer error
        patch = Patch(
            op=OpString.REPLACE,
            path=PatchPath(
                type=ObjectType.ORDER, object_id=order_id, fields=["PaymentState"]
            ),
            value=2,  # CANCELED
        )

        error = handler.apply_patch(patch)
        assert error is None

        # Verify patch was applied
        updated_order = shop.orders.get(order_id)
        assert updated_order.payment_state == 2  # CANCELED

    def test_no_notification_without_observers(self):
        """Test that state capture doesn't happen without observers."""
        shop = create_test_shop()
        handler = PatchHandler(shop)

        # Add order
        order_id = 987
        order = create_test_order(order_id, 1)  # OPEN
        shop.orders.insert(order_id, order)

        # Apply patch without observers
        patch = Patch(
            op=OpString.REPLACE,
            path=PatchPath(
                type=ObjectType.ORDER, object_id=order_id, fields=["PaymentState"]
            ),
            value=2,  # CANCELED
        )

        error = handler.apply_patch(patch)
        assert error is None

        # Verify patch was applied
        updated_order = shop.orders.get(order_id)
        assert updated_order.payment_state == 2  # CANCELED

    def test_complex_order_state_changes(self):
        """Test capturing complex order state changes."""
        shop = create_test_shop()
        handler = PatchHandler(shop)
        observer = MockObserver()
        handler.add_observer(observer)

        # Add order
        order_id = 111
        order = create_test_order(order_id, 1)  # OPEN
        shop.orders.insert(order_id, order)

        # Add payment details
        patch1 = Patch(
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
        )

        error = handler.apply_patch(patch1)
        assert error is None

        # Change payment state
        patch2 = Patch(
            op=OpString.REPLACE,
            path=PatchPath(
                type=ObjectType.ORDER, object_id=order_id, fields=["PaymentState"]
            ),
            value=2,  # CANCELED
        )

        error = handler.apply_patch(patch2)
        assert error is None

        # Verify both changes were captured
        assert len(observer.changes) == 2

        # First change added payment details
        change1 = observer.changes[0]
        assert change1["before"].id == order_id
        assert change1["after"] is not None
        assert change1["after"].payment_details is not None

        # Second change updated payment state
        change2 = observer.changes[1]
        assert change2["before"].payment_state == 1  # OPEN
        assert change2["after"].payment_state == 2  # CANCELED


class TestCaduceusIntegration:
    """Test Caduceus-specific use cases."""

    def test_caduceus_order_state_transitions(self):
        """Test detecting specific order state transitions for email notifications."""

        class CaduceusObserver(StateChangeObserver):
            def __init__(self):
                self.order_confirmations = []
                self.status_updates = []

            def on_state_change(self, object_type, object_id, before, after):
                if object_type == "orders" and before and after:
                    # Detect OPEN -> CANCELED transition
                    if (
                        before.payment_state == 1 and after.payment_state == 2
                    ):  # OPEN -> CANCELED
                        self.order_confirmations.append((object_id, after))

                    # Detect fulfillment status changes
                    before_fulfillment = getattr(before, "fulfillment_status", None)
                    after_fulfillment = getattr(after, "fulfillment_status", None)
                    if before_fulfillment != after_fulfillment:
                        self.status_updates.append(
                            (object_id, before_fulfillment, after_fulfillment)
                        )

        shop = create_test_shop()
        handler = PatchHandler(shop)
        caduceus_observer = CaduceusObserver()
        handler.add_observer(caduceus_observer)

        # Create order
        order_id = 999
        order = create_test_order(order_id, 1)  # OPEN
        shop.orders.insert(order_id, order)

        # Simulate payment
        patch = Patch(
            op=OpString.REPLACE,
            path=PatchPath(
                type=ObjectType.ORDER, object_id=order_id, fields=["PaymentState"]
            ),
            value=2,  # CANCELED
        )

        error = handler.apply_patch(patch)
        assert error is None

        # Verify Caduceus observer detected the transition
        assert len(caduceus_observer.order_confirmations) == 1
        assert caduceus_observer.order_confirmations[0][0] == str(order_id)
        assert (
            caduceus_observer.order_confirmations[0][1].payment_state == 2
        )  # CANCELED
