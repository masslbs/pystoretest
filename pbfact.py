import factory
import random
from google.protobuf import timestamp_pb2
from massmarket_hash_event import (
    base_types_pb2,
    shop_events_pb2,
)  # adjust import as needed


class ObjectIdFactory(factory.Factory):
    class Meta:
        model = base_types_pb2.ObjectId

    raw = factory.LazyFunction(lambda: random.randbytes(8))


class Uint256Factory(factory.Factory):
    class Meta:
        model = base_types_pb2.Uint256

    raw = factory.LazyFunction(
        lambda: (100 * random.randint(0, 1000)).to_bytes(32, "big")
    )


class PlusMinusFactory(factory.Factory):
    class Meta:
        model = base_types_pb2.PlusMinus

    plus_sign = factory.LazyFunction(lambda: random.choice([True, False]))

    @factory.post_generation
    def diff(obj, create, extracted, **kwargs):
        if not extracted:
            obj.diff.CopyFrom(Uint256Factory())


# Helper function to generate product-like names
def generate_product_name():
    adjectives = ["Premium", "Deluxe", "Classic", "Modern", "Eco-friendly"]
    categories = ["Shirt", "Pants", "Jacket", "Shoes", "Bag", "Hat"]
    return f"{random.choice(adjectives)} {random.choice(categories)}"


class ListingMetadataFactory(factory.Factory):
    class Meta:
        model = base_types_pb2.ListingMetadata

    title = factory.LazyFunction(generate_product_name)
    description = factory.Faker("text", max_nb_chars=300)

    @factory.post_generation
    def images(obj, create, extracted, **kwargs):
        if not extracted:
            num_images = random.randint(1, 5)
            obj.images.extend([f"image_{i}.jpg" for i in range(num_images)])


class ListingVariationMetadataFactory(factory.Factory):
    class Meta:
        model = base_types_pb2.ListingMetadata

    # TODO: based on option name would be nice but good enough for now
    title = factory.LazyFunction(generate_product_name)
    description = factory.Faker("text", max_nb_chars=100)

    @factory.post_generation
    def images(obj, create, extracted, **kwargs):
        if not extracted:
            num_images = random.randint(0, 1)
            obj.images.extend([f"variation_{i}.jpg" for i in range(num_images)])


class ListingVariationFactory(factory.Factory):
    class Meta:
        model = base_types_pb2.ListingVariation

    @factory.post_generation
    def id(obj, create, extracted, **kwargs):
        if not extracted:
            obj.id.CopyFrom(ObjectIdFactory())

    @factory.post_generation
    def variation_info(obj, create, extracted, **kwargs):
        if not extracted:
            obj.variation_info.CopyFrom(ListingVariationMetadataFactory())

    @factory.post_generation
    def diff(obj, create, extracted, **kwargs):
        if not extracted:
            obj.diff.CopyFrom(PlusMinusFactory())


class ListingOptionFactory(factory.Factory):
    class Meta:
        model = base_types_pb2.ListingOption

    title = factory.Iterator(["Color", "Size", "Material", "Style"])

    @factory.post_generation
    def id(obj, create, extracted, **kwargs):
        if not extracted:
            obj.id.CopyFrom(ObjectIdFactory())

    @factory.post_generation
    def variations(obj, create, extracted, **kwargs):
        if not extracted:
            num_variations = random.randint(2, 5)
            for _ in range(num_variations):
                variation = ListingVariationFactory()
                obj.variations.append(variation)


class ListingStockStatusFactory(factory.Factory):
    class Meta:
        model = base_types_pb2.ListingStockStatus

    @factory.post_generation
    def variation_ids(obj, create, extracted, **kwargs):
        if not extracted:
            num_variations = random.randint(1, 3)
            for _ in range(num_variations):
                obj_id = ObjectIdFactory()
                obj.variation_ids.append(obj_id)

    @factory.post_generation
    def status(obj, create, extracted, **kwargs):
        if random.choice([True, False]):
            obj.in_stock = True
        else:
            timestamp = timestamp_pb2.Timestamp()
            timestamp.GetCurrentTime()
            timestamp.seconds += random.randint(86400, 2592000)  # 1 day to 30 days
            obj.expected_in_stock_by.CopyFrom(timestamp)


class ListingFactory(factory.Factory):
    class Meta:
        model = shop_events_pb2.Listing

    view_state = 1  # shop_events_pb2.LISTING_VIEW_STATE_PUBLISHED

    @factory.post_generation
    def id(obj, create, extracted, **kwargs):
        if not extracted:
            obj.id.CopyFrom(ObjectIdFactory())

    @factory.post_generation
    def price(obj, create, extracted, **kwargs):
        if not extracted:
            obj.price.CopyFrom(Uint256Factory())

    @factory.post_generation
    def metadata(obj, create, extracted, **kwargs):
        if not extracted:
            obj.metadata.CopyFrom(ListingMetadataFactory())

    @factory.post_generation
    def options(obj, create, extracted, **kwargs):
        if not extracted:
            num_options = random.randint(1, 3)
            for _ in range(num_options):
                option = ListingOptionFactory()
                obj.options.append(option)

    @factory.post_generation
    def stock_statuses(obj, create, extracted, **kwargs):
        if not extracted:
            num_statuses = random.randint(1, 3)
            for _ in range(num_statuses):
                status = ListingStockStatusFactory()
                obj.stock_statuses.append(status)


def create_test_listings(count: int = 10):
    return [ListingFactory() for _ in range(count)]


if __name__ == "__main__":
    # Example usage
    listings = create_test_listings(100)
    total = 0
    for listing in listings:
        print(f"Listing: {listing.metadata.title}")
        print(f"  Price: {listing.price.raw.hex()}")
        # opts = [f"{opt.title}: {[var.variation_info.title for var in opt.variations]}" for opt in listing.options]
        opts = [opt.title for opt in listing.options]
        print(f"  Options: {opts}")
        print(f"  Stock Statuses: {len(listing.stock_statuses)}")
        pbstr = listing.SerializeToString()
        sz = len(pbstr)
        total += sz
        print(f" Size: {sz}")
        print()
    avg = total / len(listings)
    print(f"Average Size: {avg}")
