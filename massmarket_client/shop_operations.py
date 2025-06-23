# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

from typing import Optional, List, Tuple
import massmarket.cbor.patch as mass_patch
import massmarket.cbor.base_types as mass_base
import massmarket.cbor.manifest as mass_manifest
import massmarket.cbor.listing as mass_listing
import massmarket.cbor.order as mass_order
from .utils import new_object_id, vid, cbor_now


class ShopOperations:
    """Handles shop-specific operations like creating listings, orders, inventory management."""

    def __init__(
        self,
        patch_manager,
        state_manager,
        default_currency,
        default_payee,
        default_shipping_address,
        client,  # Reference to client to access expect_error
        debug=False,
    ):
        self.patch_manager = patch_manager
        self.state_manager = state_manager
        self.default_currency = default_currency
        self.default_payee = default_payee
        self.default_shipping_address = default_shipping_address
        self.client = client  # Store client reference
        self.debug = debug

    @property
    def expect_error(self) -> bool:
        """Get expect_error flag from client."""
        return self.client.expect_error

    # ============================================================================
    # SHOP MANIFEST OPERATIONS
    # ============================================================================

    def create_shop_manifest(self, shop_token_id):
        """Create a shop manifest."""
        sm = mass_manifest.Manifest(
            shop_id=mass_base.Uint256(shop_token_id),
            accepted_currencies={
                self.default_currency.chain_id: {
                    self.default_currency.address,
                },
            },
            pricing_currency=self.default_currency,
            payees={
                self.default_payee.address.chain_id: {
                    self.default_payee.address.address: mass_base.PayeeMetadata(
                        call_as_contract=False
                    )
                },
            },
            shipping_regions={
                "default": mass_base.ShippingRegion(
                    country="",
                    postal_code="",
                    city="",
                )
            },
        )
        self.patch_manager.write_patch(
            obj=sm,
            type=mass_patch.ObjectType.MANIFEST,
            op="replace",
        )

    def update_shop_manifest(
        self,
        add_currency: Optional[mass_base.ChainAddress] = None,
        remove_currency: Optional[mass_base.ChainAddress] = None,
        set_pricing_currency: Optional[mass_base.ChainAddress] = None,
        add_payee: Optional[mass_base.Payee] = None,
        remove_payee: Optional[mass_base.Payee] = None,
        add_region: Optional[Tuple[str, mass_base.ShippingRegion]] = None,
        remove_region: Optional[str] = None,
        wait: bool = True,
    ):
        """Update shop manifest."""
        obj = None
        fields = None
        op = None
        assert self.state_manager is not None, "shop not initialized"
        if add_currency:
            op = mass_patch.OpString.ADD
            fields = [
                "AcceptedCurrencies",
                add_currency.chain_id,
                add_currency.address.to_bytes(),
            ]
            obj = {}
        elif remove_currency is not None:
            op = mass_patch.OpString.REMOVE
            assert isinstance(remove_currency, mass_base.ChainAddress)
            fields = [
                "AcceptedCurrencies",
                remove_currency.chain_id,
                remove_currency.address.to_bytes(),
            ]
            obj = None
        elif set_pricing_currency:
            op = mass_patch.OpString.REPLACE
            fields = ["PricingCurrency"]
            obj = set_pricing_currency
            assert isinstance(obj, mass_base.ChainAddress)
        elif add_payee:
            op = mass_patch.OpString.ADD
            assert isinstance(add_payee, mass_base.Payee)
            fields = [
                "Payees",
                add_payee.address.chain_id,
                add_payee.address.address.to_bytes(),
            ]
            obj = mass_base.PayeeMetadata(call_as_contract=add_payee.call_as_contract)
        elif remove_payee is not None:
            op = mass_patch.OpString.REMOVE
            assert isinstance(remove_payee, mass_base.Payee)
            fields = [
                "Payees",
                remove_payee.address.chain_id,
                remove_payee.address.address.to_bytes(),
            ]
            obj = None
        elif add_region:
            op = mass_patch.OpString.ADD
            name = add_region[0]
            fields = ["ShippingRegions", name]
            obj = add_region[1]
            assert isinstance(obj, mass_base.ShippingRegion)
        elif remove_region is not None:
            op = mass_patch.OpString.REMOVE
            assert isinstance(remove_region, str)
            fields = ["ShippingRegions", remove_region]
            obj = None
        else:
            raise Exception("no fields to update")
        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.MANIFEST,
            obj=obj,
            op=op,
            fields=fields,
            wait=wait,
        )

    # ============================================================================
    # LISTING OPERATIONS
    # ============================================================================

    def create_listing(
        self,
        name: str,
        price: int,
        iid=None,
        wait=True,
        state=mass_listing.ListingViewState.PUBLISHED,
    ):
        """Create a new listing."""
        if iid is None:
            iid = new_object_id()

        if self.state_manager and self.state_manager.get_shop().listings.has(iid):
            raise Exception(f"Listing already exists: {iid}")

        meta = mass_listing.ListingMetadata(
            title=name,
            description="This is a description of the listing",
            images=["https://example.com/image.png"],
        )
        listing = mass_listing.Listing(
            id=iid,
            metadata=meta,
            price=mass_base.Uint256(price),
            view_state=state,
        )

        self.patch_manager.write_patch(
            obj=listing,
            object_id=iid,
            type=mass_patch.ObjectType.LISTING,
            op=mass_patch.OpString.ADD,
            wait=wait,
        )

        if wait and not self.expect_error and self.state_manager:
            i = 10
            while not self.state_manager.get_shop().listings.has(iid):
                self.patch_manager.connection_manager.handle_all()
                i -= 1
                assert i > 0, f"create listing {iid} timeout"

        return iid

    def update_listing(
        self,
        listing_id: int,
        price: Optional[int | mass_base.Uint256] = None,
        title: Optional[str] = None,
        descr: Optional[str] = None,
        add_image: Optional[str] = None,
        remove_image: Optional[int] = None,
        state: Optional[mass_listing.ListingViewState] = None,
        add_option: Optional[Tuple[str, mass_listing.ListingOption]] = None,
        remove_option: Optional[str] = None,
        add_variation: Optional[
            Tuple[str, Tuple[str, mass_listing.ListingVariation]]
        ] = None,
        remove_variation: Optional[Tuple[str, str]] = None,
    ):
        """Update a listing."""
        op = None
        obj = None
        fields = None

        if self.state_manager and not self.expect_error:
            shop = self.state_manager.get_shop()
            assert shop.listings.has(listing_id), f"unknown listing: {listing_id}"

        if price:
            op = mass_patch.OpString.REPLACE
            fields = ["Price"]
            assert isinstance(price, int) or isinstance(price, mass_base.Uint256)
            obj = price
        elif title:
            op = mass_patch.OpString.REPLACE
            fields = ["Metadata", "Title"]
            assert isinstance(title, str)
            obj = title
        elif descr:
            op = mass_patch.OpString.REPLACE
            fields = ["Metadata", "Description"]
            assert isinstance(descr, str)
            obj = descr
        elif add_image:
            op = mass_patch.OpString.APPEND
            fields = ["Metadata", "Images"]
            assert isinstance(add_image, str)
            obj = add_image
        elif remove_image is not None:
            op = mass_patch.OpString.REMOVE
            fields = ["Metadata", "Images", remove_image]
            assert isinstance(remove_image, int)
            obj = None
        elif state:
            op = mass_patch.OpString.REPLACE
            fields = ["ViewState"]
            assert isinstance(state, mass_listing.ListingViewState)
            obj = state
        elif add_option:
            op = mass_patch.OpString.ADD
            assert isinstance(add_option, tuple) and len(add_option) == 2
            opt_name = add_option[0]
            assert isinstance(opt_name, str)
            obj = add_option[1]
            assert isinstance(obj, mass_listing.ListingOption)
            fields = ["Options", opt_name]
        elif remove_option:
            op = mass_patch.OpString.REMOVE
            fields = ["Options", remove_option]
            assert isinstance(remove_option, str)
            obj = None
        elif add_variation:
            op = mass_patch.OpString.ADD
            assert isinstance(add_variation, tuple) and len(add_variation) == 2
            opt_name = add_variation[0]
            assert isinstance(opt_name, str)
            new_var = add_variation[1]
            assert isinstance(new_var, tuple) and len(new_var) == 2
            var_name = new_var[0]
            assert isinstance(var_name, str)
            obj = new_var[1]
            assert isinstance(obj, mass_listing.ListingVariation)
            fields = ["Options", opt_name, "Variations", var_name]
        elif remove_variation:
            op = mass_patch.OpString.REMOVE
            assert isinstance(remove_variation, tuple) and len(remove_variation) == 2
            opt_name = remove_variation[0]
            assert isinstance(opt_name, str)
            var_name = remove_variation[1]
            assert isinstance(var_name, str)
            fields = ["Options", opt_name, "Variations", var_name]
            obj = None
        else:
            raise Exception("no fields to update")

        assert fields is not None, "no fields to update"
        assert op is not None, "no op to update"

        return self.patch_manager.write_patch(
            type=mass_patch.ObjectType.LISTING,
            object_id=listing_id,
            obj=obj,
            op=op,
            fields=fields,
        )

    # ============================================================================
    # TAG OPERATIONS
    # ============================================================================

    def create_tag(self, name):
        """Create a new tag."""
        if not self.expect_error:
            assert self.state_manager is not None, "shop not initialized"
        if self.state_manager and self.state_manager.get_shop().tags.has(name):
            raise Exception(f"Tag already exists: {name}")
        tag = mass_base.Tag(name=name, listings=[])
        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.TAG,
            tag_name=name,
            obj=tag,
            op=mass_patch.OpString.ADD,
        )

    def add_to_tag(self, tag_name, listing_id):
        """Add a listing to a tag."""
        if self.state_manager:
            shop = self.state_manager.get_shop()
            # Skip tag existence check when batching is enabled since the tag might
            # be created earlier in the same batch but not yet applied to local state
            if (
                not self.expect_error
                and not self.patch_manager.batching_enabled
                and not shop.tags.has(tag_name)
            ):
                raise Exception(f"Unknown tag: {tag_name}")
            if not self.expect_error and not shop.listings.has(listing_id):
                raise Exception(f"Unknown listing: {listing_id}")
        if not isinstance(listing_id, int):
            raise Exception("Listing ID must be an integer")
        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.TAG,
            tag_name=tag_name,
            fields=["ListingIDs"],
            op=mass_patch.OpString.APPEND,
            obj=listing_id,
        )

    def remove_from_tag(self, tag_name, listing_id):
        """Remove a listing from a tag."""
        if self.state_manager:
            shop = self.state_manager.get_shop()
            tag = shop.tags.get(tag_name)
            if not self.expect_error and tag is None:
                raise Exception(f"Unknown tag: {tag_name}")
            if not self.expect_error and not shop.listings.has(listing_id):
                raise Exception(f"Unknown listing: {listing_id}")
            assert tag is not None, f"Unknown tag: {tag_name}"
            # Find the index of the listing ID in the tag's listings array
            try:
                index = tag.listings.index(listing_id)
            except ValueError:
                raise Exception(f"Listing {listing_id} not found in tag {tag_name}")
            except AttributeError:
                if self.expect_error:
                    index = 0
                else:
                    raise Exception(f"Tag {tag_name} has no listings")

            self.patch_manager.write_patch(
                type=mass_patch.ObjectType.TAG,
                tag_name=tag_name,
                fields=["ListingIDs", index],
                op=mass_patch.OpString.REMOVE,
            )

    def delete_tag(self, tag_name):
        """Delete a tag."""
        if self.state_manager:
            shop = self.state_manager.get_shop()
            if not self.expect_error and not shop.tags.has(tag_name):
                raise Exception(f"Unknown tag: {tag_name}")
        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.TAG,
            tag_name=tag_name,
            op=mass_patch.OpString.REMOVE,
        )

    # ============================================================================
    # INVENTORY OPERATIONS
    # ============================================================================

    def change_inventory(
        self, listing_id: int, change: int, variations: Optional[List[str]] = None
    ):
        """Change inventory for a listing."""
        if (
            self.state_manager
            and not self.expect_error
            and not self.state_manager.get_shop().listings.has(listing_id)
        ):
            raise Exception(f"Unknown listing: {listing_id}")

        op = mass_patch.OpString.ADD
        lookup_id = vid(listing_id, variations)

        if self.state_manager:
            current = self.state_manager.get_shop().inventory.get(lookup_id)
            if current is None:
                current = 0
                op = mass_patch.OpString.ADD
            if not self.expect_error and current + change < 0:
                raise Exception(
                    f"Inventory underflow: {lookup_id} {current} + {change} < 0"
                )
            if change == 0:
                op = mass_patch.OpString.REPLACE
            elif change > 0:
                op = mass_patch.OpString.INCREMENT
            else:
                change = -change
                op = mass_patch.OpString.DECREMENT

        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.INVENTORY,
            object_id=listing_id,
            op=op,
            obj=change,
            fields=variations,
        )

    def check_inventory(self, listing_id: int, variations: Optional[List[str]] = None):
        """Check inventory for a listing."""
        if not self.state_manager:
            return 0

        lookup_id = vid(listing_id, variations)
        shop = self.state_manager.get_shop()
        current = shop.inventory.get(lookup_id)
        if current is None:
            return 0
        else:
            return current

    # ============================================================================
    # ORDER OPERATIONS
    # ============================================================================

    def create_order(self, oid=None, wait=True):
        """Create a new order."""
        if oid is None:
            oid = new_object_id()

        if self.state_manager and self.state_manager.get_shop().orders.has(oid):
            raise Exception(f"Order already exists: {oid}")

        order = mass_order.Order(id=oid, items=[], state=mass_order.OrderState.OPEN)
        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=oid,
            obj=order,
            op=mass_patch.OpString.ADD,
            wait=wait,
        )

        if wait and not self.expect_error and self.state_manager:
            i = 10
            while not self.state_manager.get_shop().orders.has(oid):
                self.patch_manager.connection_manager.handle_all()
                i -= 1
                assert i > 0, "create order timeout"

        return oid

    def add_to_order(self, order_id, listing_id, quantity, variations=None):
        """Add an item to an order."""
        if self.state_manager:
            shop = self.state_manager.get_shop()
            if not self.expect_error and not shop.orders.has(order_id):
                raise Exception(f"Unknown order: {order_id}")
            if not self.expect_error and not shop.listings.has(listing_id):
                raise Exception(f"Unknown listing: {listing_id}")
        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.APPEND,
            obj=mass_order.OrderedItem(
                listing_id=listing_id,
                quantity=quantity,
                variation_ids=variations,
            ),
            fields=["Items"],
        )

    def remove_from_order(self, order_id, listing_id, quantity, variations=None):
        """Remove an item from an order."""
        if self.state_manager:
            shop = self.state_manager.get_shop()
            if not self.expect_error and not shop.orders.has(order_id):
                raise Exception(f"Unknown order: {order_id}")
            if not self.expect_error and not shop.listings.has(listing_id):
                raise Exception(f"Unknown listing: {listing_id}")

            order = shop.orders.get(order_id)
            if order is None:
                raise Exception(f"Unknown order: {order_id}")

            index = None
            for i, item in enumerate(order.items):
                if item.listing_id == listing_id and item.variation_ids == variations:
                    index = i
                    break

            if index is None:
                raise Exception(f"Listing {listing_id} not found in order {order_id}")

            self.patch_manager.write_patch(
                type=mass_patch.ObjectType.ORDER,
                object_id=order_id,
                op=mass_patch.OpString.DECREMENT,
                obj=quantity,
                fields=["Items", index, "Quantity"],
            )

    def abandon_order(self, order_id):
        """Abandon an order."""
        if self.state_manager:
            shop = self.state_manager.get_shop()
            if not self.expect_error and not shop.orders.has(order_id):
                raise Exception(f"Unknown order: {order_id}")

        # Start batch to combine these operations
        was_batching = self.patch_manager.batching_enabled
        if not was_batching:
            self.patch_manager.start_batch()

        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.ADD,
            fields=["CanceledAt"],
            obj=cbor_now(),
        )
        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.REPLACE,
            fields=["State"],
            obj=mass_order.OrderState.CANCELED,
        )

        if not was_batching:
            self.patch_manager.flush_batch()

    def update_address_for_order(self, order_id, invoice=None, shipping=None):
        """Update address for an order."""
        if self.state_manager:
            shop = self.state_manager.get_shop()
            if not self.expect_error and not shop.orders.has(order_id):
                raise Exception(f"Unknown order: {order_id}")
        if invoice is None and shipping is None:
            raise Exception("invoice and shipping cannot both be None")
        field_name = "InvoiceAddress" if invoice else "ShippingAddress"
        address_obj = invoice if invoice else shipping

        # check if order already has an address
        if self.state_manager:
            shop = self.state_manager.get_shop()
            order = shop.orders.get(order_id)
            if order is not None:
                if order.invoice_address is not None and field_name == "InvoiceAddress":
                    op = mass_patch.OpString.REPLACE
                elif (
                    order.shipping_address is not None
                    and field_name == "ShippingAddress"
                ):
                    op = mass_patch.OpString.REPLACE
                else:
                    op = mass_patch.OpString.ADD
            else:
                op = mass_patch.OpString.ADD
        else:
            op = mass_patch.OpString.ADD

        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=op,
            fields=[field_name],
            obj=address_obj,
        )

    def commit_items(self, order_id):
        """Commit order items."""
        if self.state_manager:
            shop = self.state_manager.get_shop()
            if not self.expect_error and not shop.orders.has(order_id):
                raise Exception(f"Unknown order: {order_id}")
        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.REPLACE,
            fields=["State"],
            obj=mass_order.OrderState.COMMITTED,
            wait=self.expect_error,
        )

    def choose_payment(self, order_id, currency=None, payee=None):
        """Choose payment for an order."""
        if self.state_manager:
            shop = self.state_manager.get_shop()
            if not self.expect_error and not shop.orders.has(order_id):
                raise Exception(f"Unknown order: {order_id}")

        # Set chosen currency
        if currency is None:
            currency = self.default_currency

        # Set chosen payee
        if payee is None:
            payee = self.default_payee

        was_batching_before = self.patch_manager.batching_enabled
        if not was_batching_before:
            self.patch_manager.start_batch()

        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.REPLACE,
            fields=["ChosenCurrency"],
            obj=currency,
        )

        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.REPLACE,
            fields=["ChosenPayee"],
            obj=payee,
        )

        self.patch_manager.write_patch(
            type=mass_patch.ObjectType.ORDER,
            object_id=order_id,
            op=mass_patch.OpString.REPLACE,
            fields=["State"],
            obj=mass_order.OrderState.PAYMENT_CHOSEN,
        )

        if not was_batching_before:
            self.patch_manager.flush_batch()
