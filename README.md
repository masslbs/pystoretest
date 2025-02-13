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
