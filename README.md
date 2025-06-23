<!--
SPDX-FileCopyrightText: 2025 Mass Labs

SPDX-License-Identifier: MIT
-->

# pystoretest - Integration Tests for Relay

This repository contains integration tests for the Mass Labs [Relay](https://github.com/masslbs/relay) service, which is part of a decentralized marketplace system built on Ethereum.

## Overview

pystoretest provides comprehensive testing of the relay service, including:

- Shop management (creation, configuration, and updates)
- Inventory tracking and management
- Listing creation and modification
- Order processing and payment handling
- Authentication with keycards and wallet signatures
- Multi-client synchronization

## Requirements

- [Nix](https://nixos.org/download.html) - Used for dependency management
- Local Ethereum node (e.g., Anvil) for testing blockchain interactions
- Running [relay](https://github.com/masslbs/relay) service instance

## Setup

1. Clone the repository
2. Create your environment configuration:
   ```
   cp .env.example .env
   ```
3. Edit the configuration file:
   ```
   $EDITOR .env
   ```
4. Start the Nix shell:
   ```
   nix-shell
   ```
5. Run the tests:
   ```
   make test
   ```

## Configuration

The `.env` file should contain the following configuration variables:

- `RELAY_HTTP_ADDRESS` - The HTTP address of the relay service (default: http://localhost:4444)
- `RELAY_PING` - Ping interval in seconds (default: 0.250)
- `ETH_PRIVATE_KEY` - Private key for Ethereum testing (use one of the Anvil test accounts)
- `ETH_RPC_URL` - URL for Ethereum RPC node (default: http://localhost:8545)
- `MASS_CONTRACTS` - Path to Mass Labs contract ABIs and addresses

## Test Features

- Account management for testing with automatic nonce handling
- Client fixtures for easy test setup
- Support for multiple simultaneous clients
- Guest account testing
- Shop state inspection and manipulation
- Order creation and processing
- CoinGecko integration for pricing tests

## Running Specific Tests

To run specific test files:
```
pytest test_specific_file.py -v
```

To run a single test:
```
pytest -v -k test_name
```


# Relay Client Refactoring

This document describes the refactoring of the large `RelayClient` class into a more modular, maintainable architecture with added persistence capabilities.

## Problem

The original `client.py` file was over 2400 lines long and contained multiple responsibilities:
- WebSocket connection management
- Authentication handling
- Patch application logic
- Shop state management
- Ethereum contract interactions
- Message handling
- Business logic for shop operations

This made the code difficult to maintain, test, and extend.

## Solution

The refactoring breaks down the monolithic client into focused, single-responsibility modules:

### 1. `persistence.py` - Data Persistence Layer

**Classes:**
- `ShopPersistence`: Handles saving/loading shop data to/from disk
- `PatchLogger`: Logs patch operations for debugging and replay
- `StateManager`: Manages shop state with caching and persistence

**Features:**
- Automatic CBOR serialization of shop data
- Metadata tracking for quick queries
- Session-based patch logging
- Dirty state tracking for efficient saves

### 2. `connection_manager.py` - Connection Management

**Classes:**
- `ConnectionManager`: Handles WebSocket connections and message routing
- `AuthenticationManager`: Manages authentication flow with the relay

**Features:**
- Automatic reconnection with exponential backoff
- Message handler registration system
- Request/response tracking
- Rate limiting handling

### 3. `patch_handler.py` - Patch Application Logic

**Classes:**
- `PatchHandler`: Applies patches to shop state

**Features:**
- Isolated patch application logic
- Error handling for invalid patches
- Support for all patch operations (ADD, REMOVE, REPLACE, etc.)

### 4. `refactored_client.py` - Main Client Interface

**Classes:**
- `RefactoredRelayClient`: Main client that orchestrates all components

**Features:**
- Clean, focused interface
- Automatic state persistence
- Patch batching support
- Simplified error handling

## Benefits

### 1. **Separation of Concerns**
Each module has a single, well-defined responsibility:
- Persistence handles data storage
- Connection manager handles networking
- Patch handler handles state updates
- Main client orchestrates operations



## Usage Examples

### Basic Usage

```python
from refactored_client import RefactoredRelayClient

# Create client with persistence
client = RefactoredRelayClient(
    name="MyShop",
    wallet_private_key="0x...",
    data_dir="shop_data",
    log_dir="patch_logs"
)

# Register shop (creates persistent storage)
shop_id = client.register_shop()

# Login and create content
client.login()
client.create_shop_manifest()
listing_id = client.create_listing("Product", 1000)
client.change_inventory(listing_id, 10)

# State is automatically saved
client.close()
```

### Advanced Usage

```python
# Use batching for performance
client.start_batch()
client.change_inventory(listing1_id, -1)
client.change_inventory(listing2_id, -1)
client.change_inventory(listing3_id, -1)
client.flush_batch()  # Single network request

# Manual state management
client.save_state()
shop = client.load_state()

# Access persistence directly
if client.persistence.shop_exists(shop_id):
    metadata = client.persistence.get_shop_metadata(shop_id)
    print(f"Shop has {metadata['listings_count']} listings")
```


## File Structure

```
pystoretest/
├── client.py                 # Original monolithic client (2483 lines)
├── refactored_client.py      # New main client (400+ lines)
├── persistence.py            # Data persistence layer (200+ lines)
├── connection_manager.py     # Connection management (300+ lines)
├── patch_handler.py          # Patch application logic (400+ lines)
├── example_usage.py          # Usage examples
└── README_REFACTORING.md     # This file
```
