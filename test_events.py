import os
import json

import requests

from client import RelayClient
from massmarket_hash_event import schema_pb2

def test_blob_upload(wc_auth: RelayClient):
    wc_auth.create_store_manifest()
    assert wc_auth.errors == 0
    req_id = wc_auth.get_blob_upload_url()
    wc_auth.handle_all()
    while "waiting" in wc_auth.outgoingRequests[req_id]:
        print("waiting")
        wc_auth.handle_all()
        assert wc_auth.errors == 0
    urlResp = wc_auth.outgoingRequests[req_id]
    files = {'file': ('filename.txt', open('testcat.jpg', 'rb'), 'application/octet-stream')}
    uploadResp = requests.post(urlResp["url"], files=files)
    assert uploadResp.status_code == 201
    uploadJson = uploadResp.json()
    assert uploadJson["ipfs_path"] == "/ipfs/Qma8tx56NLeSi2we2R41C8haSNj9kyRooxrJptyLvncbWf"
    wc_auth.close()

def test_update_store_manifest(wc_auth: RelayClient):
    wc_auth.create_store_manifest()
    assert wc_auth.errors == 0
    wc_auth.update_store_manifest(field=schema_pb2.UpdateManifest.MANIFEST_FIELD_DOMAIN, string_value="merch.mass.market")
    assert wc_auth.errors == 0
    new_pub_tag = os.urandom(32)
    wc_auth.create_tag('published 2', tag_id=new_pub_tag)
    wc_auth.update_store_manifest(field=schema_pb2.UpdateManifest.MANIFEST_FIELD_PUBLISHED_TAG, id_value=new_pub_tag)
    assert wc_auth.errors == 0
    erc20_addr = wc_auth.w3.to_bytes(hexstr=wc_auth.erc20Token.address[2:])
    wc_auth.update_store_manifest(field=schema_pb2.UpdateManifest.MANIFEST_FIELD_ADD_ERC20, addr_value=erc20_addr)
    assert wc_auth.errors == 0
    wc_auth.update_store_manifest(field=schema_pb2.UpdateManifest.MANIFEST_FIELD_REMOVE_ERC20, addr_value=erc20_addr)
    assert wc_auth.errors == 0
    wc_auth.excpect_error = True
    wc_auth.update_store_manifest(field=schema_pb2.UpdateManifest.MANIFEST_FIELD_ADD_ERC20, addr_value=os.urandom(20))
    assert wc_auth.errors == 1
    wc_auth.excpect_error = False
    wc_auth.close()

def test_sync_store_manifest(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes events
    a1.update_store_manifest(field=schema_pb2.UpdateManifest.MANIFEST_FIELD_DOMAIN, string_value="merch.mass.market")
    a1.handle_all()
    assert a1.errors == 0

    # a2 syncs the event
    a2.handle_all()
    assert a2.errors == 0
    assert a2.manifest.domain == "merch.mass.market"
    assert a2.manifest.domain == a1.manifest.domain
    # TODO: only one store manifest

def test_write_and_sync_later(make_client):
    # both alices share the same private wallet but have different keycards
    a1 = make_client("alice.1")
    store_id = a1.register_store()
    a1.enroll_key_card()
    a1.login()
    a1.handle_all()
    assert a1.errors == 0

    # a1 writes an a few events
    a1.create_store_manifest()
    a1.update_store_manifest(field=schema_pb2.UpdateManifest.MANIFEST_FIELD_DOMAIN, string_value="merch.mass.market")
    a1.create_item('shoes', '1000')
    assert a1.errors == 0

    print("connecting alice.2")

    # a2 connects after a1 has written events
    a2 = make_client("alice.2")
    a2.store_token_id = store_id
    a2.enroll_key_card()
    a2.login()
    assert a2.errors == 0
    assert len(a2.items) == 1
    assert a2.manifest.domain == "merch.mass.market"
    assert a2.manifest.domain == a1.manifest.domain

def test_create_and_update_item(make_client):
    # both alices share the same private wallet but have different keycards
    a1 = make_client("alice.1")
    store_id = a1.register_store()
    a1.enroll_key_card()
    a1.login()
    a1.handle_all()
    assert a1.errors == 0

    # a1 writes an a few events
    a1.create_store_manifest()
    item_id = a1.create_item('shoes', '1000')
    write_req_id = a1.update_item(item_id, field=schema_pb2.UpdateItem.ITEM_FIELD_PRICE, value=2000)
    assert a1.errors == 0
    a1_hash = a1._assert_store_against_response(write_req_id)

    # a2 connects after a1 has written events
    a2 = make_client("alice.2")
    a2.store_token_id = store_id
    a2.enroll_key_card()
    a2.login()
    a2.handle_all()
    assert a2.errors == 0
    assert a2.manifest.domain == a1.manifest.domain
    assert len(a2.items) == 1
    assert a2.items[item_id].price == '2000.00'
    assert a2.items[item_id].price == a1.items[item_id].price
    assert a2._hash_store() == a1_hash

    newMetadata = b'{"color": "red"}'
    req_id2 = a2.update_item(item_id, field=schema_pb2.UpdateItem.ITEM_FIELD_METADATA, value=newMetadata)
    a2.handle_all()
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert a1.items[item_id].metadata == newMetadata
    before = a2._assert_store_against_response(req_id2)

    # try to update non-existant item
    a2.excpect_error = True
    a2.update_item(os.urandom(32), field=schema_pb2.UpdateItem.ITEM_FIELD_METADATA, value=newMetadata)
    assert a2.errors == 1
    assert a2.last_error.code == "notFound"
    assert a2._hash_store() == before

    # try gigantic metadata
    a2.errors = 0
    a2.last_error = None
    largeMetadata = json.dumps({"a": "b"*10_000}).encode('utf-8')
    a2.update_item(item_id, field=schema_pb2.UpdateItem.ITEM_FIELD_METADATA, value=largeMetadata)
    assert a2.errors == 1
    assert a2.last_error.code == "invalid"

    # reset error state
    a2.errors = 0
    a2.last_error = None
    
    newLargeMetaItem = os.urandom(32)
    item = schema_pb2.CreateItem(event_id=newLargeMetaItem, metadata=largeMetadata, price=b'01.00')
    evt = schema_pb2.Event(create_item=item)
    a2._write_event(evt)
    assert a2.errors == 1
    assert a2.last_error.code == "invalid"



def test_invalid_prices(make_client):
    c = make_client("alice")
    c.register_store()
    c.enroll_key_card()
    c.login()
    c.create_store_manifest()
    assert c.errors == 0

    # create events by hand to side-step client validation
    iid = os.urandom(32)
    meta = {
        'name': 'bad prices',
        'description': '',
        'image': 'https://example.com/image.png',
    }
    metadata = json.dumps(meta).encode('utf-8')

    test_cases = [
        {"price": "", "expected_error": "invalid"},
        {"price": "hello, world", "expected_error": "invalid"},
        {"price": ".00", "expected_error": "invalid"},
        {"price": "123,00", "expected_error": "invalid"},
        {"price": "1000.0", "expected_error": "invalid"},
        {"price": "1000.000", "expected_error": "invalid"},
        {"price": "-1000.00", "expected_error": "invalid"},
        # a bit arbitrary but we currently only support 10 digites total with 2 of them being cents
        {"price": "123456789.00", "expected_error": "invalid"},
    ]

    c.excpect_error = True

    for test_case in test_cases:
        # reset error state
        c.errors = 0
        c.last_error = None

        item = schema_pb2.CreateItem(event_id=iid, metadata=metadata, price=test_case["price"])
        c._write_event(schema_pb2.Event(create_item=item))
        assert c.errors == 1
        assert c.last_error.code == test_case["expected_error"]

    # now test updating the price
    c.errors = 0
    c.last_error = None
    c.excpect_error = False

    ci = schema_pb2.CreateItem(event_id=iid, metadata=metadata, price="123.00")
    c._write_event(schema_pb2.Event(create_item=ci))
    assert c.errors == 0

    c.excpect_error = True

    for test_case in test_cases:
        # reset error state
        c.errors = 0
        c.last_error = None

        update = schema_pb2.UpdateItem(event_id=iid, field=schema_pb2.UpdateItem.ITEM_FIELD_PRICE, price=test_case["price"])
        c._write_event(schema_pb2.Event(update_item=update))
        assert c.errors == 1
        assert c.last_error.code == test_case["expected_error"]

def test_update_item_from_other_store(make_client):
    alice = make_client("alice")
    alice.register_store()
    alice.enroll_key_card()
    alice.login()
    alice.handle_all()
    alice.create_store_manifest()
    assert alice.errors == 0

    bob = make_client("bob")
    bob.register_store()
    bob.enroll_key_card()
    bob.login()
    bob.handle_all()
    bob.create_store_manifest()
    assert bob.errors == 0

    alicesItem = alice.create_item('shoes', '1000')
    assert alice.errors == 0

    bob.excpect_error = True
    bob.update_item(alicesItem, field=schema_pb2.UpdateItem.ITEM_FIELD_PRICE, value=2000)
    assert bob.errors == 1
    assert bob.last_error.code == "notFound"

def test_create_and_edit_tag(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    iid1 = a1.create_item('sneakers', '1000')
    iid2 = a1.create_item('birkenstock', '1000')
    tid = a1.create_tag('shoes')
    a1.add_item_to_tag(tid, iid1)
    a1.add_item_to_tag(tid, iid2)
    assert a1.errors == 0

    # a2 syncs
    a2.handle_all()
    assert a2.errors == 0
    assert a2.manifest.domain == a1.manifest.domain
    assert len(a2.items) == 2
    # TODO: make published tag more consistent
    assert len(a2.tags) == 2
    tag = a2.tags[tid]
    assert len(tag.items) == 2
    assert iid1 in tag.items
    assert iid2 in tag.items

    a2.remove_from_tag(tid, iid1)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert iid1 not in a1.tags[tid].items
    assert iid1 not in a2.tags[tid].items

def test_invalid_tag_interactions(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    iid1 = a1.create_item('sneakers', '1000')
    tid = a1.create_tag('shoes')
    a1.add_item_to_tag(tid, iid1)
    assert a1.errors == 0

    noSuchTagId = os.urandom(32)
    a2.excpect_error = True
    a2.add_item_to_tag(noSuchTagId, iid1)
    assert a2.errors == 1
    assert a2.last_error.code == "notFound"

    # reset error state
    a2.errors = 0
    a2.last_error = None

    noSuchItemId = os.urandom(32)
    a2.add_item_to_tag(tid, noSuchItemId)
    assert a2.errors == 1
    assert a2.last_error.code == "notFound"

    # remove item from tag that is not in tag
    a2.errors = 0
    a2.remove_from_tag(noSuchItemId, iid1)
    assert a2.errors == 1
    assert a2.last_error.code == "notFound"

    # add item to tag that is already in tag
    a2.errors = 0
    a2.add_item_to_tag(tid, iid1)
    # multiple adds are not an error
    assert a2.errors == 0
    
    # remove item from tag that is not in store
    a2.errors = 0
    a2.remove_from_tag(tid, noSuchItemId)
    assert a2.errors == 1
    assert a2.last_error.code == "notFound"

    # rename tag that does not exist
    a2.errors = 0
    a2.rename_tag(noSuchTagId, 'shoes')
    assert a2.errors == 1
    assert a2.last_error.code == "notFound"

    # delete tag that does not exist
    a2.errors = 0
    a2.delete_tag(noSuchTagId)
    assert a2.errors == 1
    assert a2.last_error.code == "notFound"

def test_rename_and_remove_tag(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    tid = a1.create_tag('toys')
    assert a1.errors == 0

    # a2 syncs
    a2.handle_all()
    assert a2.errors == 0
    assert a2.manifest.domain == a1.manifest.domain
    assert len(a2.tags) == 2 # TODO: system tags
    assert tid in a2.tags
    assert a2.tags[tid].name == 'toys'

    a2.rename_tag(tid, 'games')
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert a1.tags[tid].name == 'games'
    assert a2.tags[tid].name == 'games'

    a2.delete_tag(tid)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert tid not in a1.tags
    assert tid not in a2.tags

def test_publish_item(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes a new item
    iid1 = a1.create_item('sneakers', '1000')
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0

    # a2 publishes it
    a2.add_item_to_tag(a1.manifest.published_tag_id, iid1)
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0

    # a1 updates it
    a1.update_item(iid1, schema_pb2.UpdateItem.ITEM_FIELD_PRICE, 32)
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0

def test_change_stock(make_two_clients):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    iid1 = a1.create_item('sneakers', '1000')
    iid2 = a1.create_item('birkenstock', '1000')
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0

    # a2 adds some stock
    a2.change_stock([(iid1, 3), (iid2, 5)])
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert a1.stock[iid1] == 3
    assert a1.stock[iid2] == 5

def test_invalid_stock_interactions(make_two_clients, make_client):
    a1, a2 = make_two_clients

    # a1 writes an a few events
    iid1 = a1.create_item('sneakers', '1000')
    assert a1.errors == 0
    a2.handle_all()
    assert a2.errors == 0

    # a2 adds some stock
    a2.change_stock([(iid1, 3)])
    assert a2.errors == 0
    a1.handle_all()
    assert a1.errors == 0
    assert a1.stock[iid1] == 3

    # a2 tries to add negative stock
    a2.excpect_error = True
    a2.change_stock([(iid1, -4)])
    assert a2.errors == 1
    assert a2.last_error.code == "outOfStock"

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # a2 tries to add stock for non-existant item
    a2.excpect_error = True
    a2.change_stock([(os.urandom(32), 1)])
    assert a2.errors == 1
    assert a2.last_error.code == "notFound"

    # reset error state
    a2.errors = 0
    a2.last_error = None

    # bob makes a 2nd store
    bob = make_client("bob")
    bob.register_store()
    bob.enroll_key_card()
    bob.login()
    bob.handle_all()
    bob.create_store_manifest()
    foreignItemId = bob.create_item('flute', '1000')
    assert bob.errors == 0

    # a2 tries to add stock for item in other store
    a2.excpect_error = True
    a2.change_stock([(foreignItemId, 1)])
    assert a2.errors == 1
    assert a2.last_error.code == "notFound"
