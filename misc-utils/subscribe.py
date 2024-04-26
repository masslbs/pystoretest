import asyncio
import json
import requests
from pprint import pprint
from websockets import connect

async def get_event():
    async with connect("wss://sepolia.drpc.org") as ws:
        req = json.dumps({
            "jsonrpc":"2.0",
            "id": 1,
            "method": "eth_subscribe",
            "params": [
                "logs",
                {
                    "address":[ "0x3d9DbbD22E4903274171ED3e94F674Bb52bCF015"],
                    "fromBlock": "0x0",
                    "toBlock": "latest",
                    "topics": [  ]
                }
            ]
        })

        # req = b'{"jsonrpc":"2.0","id":2,"method":"eth_subscribe","params":["logs",{"address":["0x3d9dbbd22e4903274171ed3e94f674bb52bcf015"],"fromBlock":"0x1","toBlock":"latest","topics":null}]}'
        pprint(req)
        await ws.send(req)
        subscription_response = await ws.recv()
        print(subscription_response)
        # you are now subscribed to the event
        # you keep trying to listen to new events (similar idea to longPolling)
        while True:
            try:
                message = await asyncio.wait_for(ws.recv(), timeout=60)
                print(json.loads(message))
                pass
            except:
                pass
if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    while True:
        loop.run_until_complete(get_event())
