# pythonTorrentDHT

A Python implementation of the BitTorrent Distributed Hash Table, extending
[nitmir/btdht](https://github.com/nitmir/btdht) with additional BEP support.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Overview

pythonTorrentDHT provides a full Python implementation of the BitTorrent mainline DHT. It
is a natural evolution of [nitmir/btdht](https://github.com/nitmir/btdht),
modernised for Python 3.10+ (pure Python, no Cython) and extended with
additional BitTorrent Enhancement Proposals:

| BEP | Description |
|-----|-------------|
| [BEP 5](https://www.bittorrent.org/beps/bep_0005.html) | BitTorrent DHT Protocol — core routing table, `get_peers`, `announce_peer` |
| [BEP 9](https://www.bittorrent.org/beps/bep_0009.html) | Extension for Peers to Send Metadata Files — fetch `.torrent` info-dicts without a tracker |
| [BEP 10](https://www.bittorrent.org/beps/bep_0010.html) | Extension Protocol — peer capability negotiation (required by BEP 9) |
| [BEP 51](https://www.bittorrent.org/beps/bep_0051.html) | DHT Infohash Indexing — `sample_infohashes` for crawling the DHT |

## Requirements

- Python 3.10+
- [datrie](https://pypi.org/project/datrie/)
- [netaddr](https://pypi.org/project/netaddr/)

No C compiler required.

## Installation

```bash
pip install pythontorrentdht
```

Or from source:

```bash
git clone https://github.com/Sprooty/pythonTorrentDHT
cd pythonTorrentDHT
pip install -e .
```

## Usage

### Find peers for a torrent

```python
import btpydht
import binascii

dht = btpydht.DHT()
dht.start()  # allow ~15s to bootstrap

peers = dht.get_peers(binascii.a2b_hex("0403fb4728bd788fbcb67e87d6feb241ef38c75a"))
print(peers)
# [('81.171.107.75', 17744), ('94.242.250.86', 3813), ...]

dht.stop()
```

### Fetch torrent metadata (BEP 9/10)

Retrieve the info-dict directly from a peer without a `.torrent` file:

```python
from btpydht.metadata import get_metadata

info_hash = binascii.a2b_hex("0403fb4728bd788fbcb67e87d6feb241ef38c75a")
peers = dht.get_peers(info_hash)

metadata = get_metadata(info_hash, peers[0])
print(metadata[b"name"])
```

### Sample infohashes from the DHT (BEP 51)

Walk the DHT and collect infohashes being announced:

```python
class CrawlerDHT(btpydht.DHT_BASE):
    def on_sample_infohashes_response(self, response):
        for ih in response.get(b"samples", []):
            print(ih.hex())

dht = CrawlerDHT()
dht.start()
```

### Announce a torrent

```python
info_hash = binascii.a2b_hex("0403fb4728bd788fbcb67e87d6feb241ef38c75a")
dht.announce_peer(info_hash, port=6881)
```

### Extend with custom message handlers

Subclass `btpydht.DHT_BASE` and override `on_<msg>_query` / `on_<msg>_response`:

```python
class MyDHT(btpydht.DHT_BASE):
    def on_get_peers_query(self, query):
        print(f"Peer request for: {query[b'info_hash'].hex()}")

dht = MyDHT()
dht.register_message(b"get_peers")
dht.start()
```

### Save and restore routing table state

```python
dht.save("routing_table.dat")
# later...
dht.load("routing_table.dat")
```

## Development

```bash
pip install -r requirements-dev.txt
make test
```

Or run pytest directly:

```bash
python -m pytest tests/ -v
```

## License

GPLv3 — see [LICENSE](LICENSE) for details.

## Credits

Originally created by [Valentin Samir](https://github.com/nitmir).
