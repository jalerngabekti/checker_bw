# checker_bw: Cross-Chain Bridge Event Listener Simulator

This repository contains a Python-based simulation of a critical component in a cross-chain bridge architecture: the event listener, also known as a relayer or oracle. This script connects to a source blockchain (like Ethereum or a compatible testnet), listens for specific events from a bridge contract, validates them, and simulates the process of relaying this information to a destination chain.

This project is designed as an architectural showcase, demonstrating principles of modularity, state management, and resilience required for real-world blockchain infrastructure components.

## Concept

A cross-chain bridge enables the transfer of assets or data from one blockchain to another. A common design pattern is the "lock-and-mint" mechanism:
1.  **Lock:** A user deposits assets into a smart contract on the source chain (e.g., locking 100 ETH).
2.  **Event Emission:** The source chain contract emits an event (`AssetLocked`) containing details of the deposit (user, amount, destination chain).
3.  **Validation & Relay:** A network of off-chain listeners (validators/relayers) detects this event. They wait for a certain number of block confirmations to ensure the transaction is final and not part of a blockchain reorganization (reorg).
4.  **Mint:** After validating the event, the relayers submit a signed message to a contract on the destination chain. Once a sufficient number of signatures are collected, the destination contract mints a corresponding amount of a wrapped asset (e.g., 100 wETH) for the user.

This script simulates the crucial **Step 3**, acting as one of these off-chain listeners.

## Code Architecture

The script is designed with a clear separation of concerns, implemented through several distinct classes:

-   `CrossChainEventListener`: The main orchestrator. It manages the connection to the source chain's RPC node, handles the main polling loop, and determines which blocks to scan.

-   `StateDB`: A simple, file-based persistence layer. It keeps track of the `last_processed_block` and a list of `processed_event_ids`. This ensures that the listener can be stopped and restarted without losing its place or processing the same event twice (preventing replay attacks).

-   `EventParser`: A static utility class responsible for decoding raw log data received from the blockchain into a structured, human-readable format. This isolates the complex and often error-prone parsing logic.

-   `TransactionProcessor`: This class takes a parsed event and applies the core business logic. It checks if the event has already been processed using the `StateDB` and then coordinates with the `SignatureRelaySimulator` to forward the event.

-   `SignatureRelaySimulator`: Simulates the final step of the relayer's duty. It generates a cryptographic signature for the event data (as a real validator would) and sends the event payload and signature to a mock API endpoint, simulating a submission to the destination chain's relayer network.

### Data Flow Diagram

```
[Source Chain RPC] <---(getLogs)-- [CrossChainEventListener]
          |
          v (Raw Log Data)
     [EventParser]
          |
          v (Parsed Event Data)
 [TransactionProcessor] ----(check)----> [StateDB]
          |
          v (Validated Event)
 [SignatureRelaySimulator]
          |
          v (POST Request with Signed Payload)
[Destination Chain API Endpoint (Mock)]
```

## How it Works

1.  **Initialization**: The `CrossChainEventListener` connects to the specified RPC endpoint and initializes all helper classes, including loading the previous state from `listener_state.json` via `StateDB`.
2.  **Polling Loop**: The listener enters an infinite loop, periodically waking up to check for new blocks.
3.  **Block Scanning**: It determines the range of blocks to scan, from the `last_processed_block + 1` up to the `latest_block_number - BLOCK_CONFIRMATIONS`.
4.  **Log Fetching**: It queries the RPC node for all event logs within that block range that match the specified bridge contract address and event topic hash.
5.  **Parsing**: For each log found, the `EventParser` decodes the data into a structured dictionary (e.g., user address, amount).
6.  **Processing**: The `TransactionProcessor` receives the parsed event. It first queries the `StateDB` to ensure the event's unique ID (`tx_hash-log_index`) hasn't been processed before.
7.  **Signing & Relaying**: If the event is new, the `SignatureRelaySimulator` signs a digest of the event data and `POST`s it to a mock API endpoint.
8.  **State Update**: If the relay is successful, the `TransactionProcessor` instructs the `StateDB` to mark the event ID as processed. Finally, the `CrossChainEventListener` updates the `last_processed_block` in the `StateDB` and saves the state to the JSON file.
9.  **Wait**: The listener then sleeps for `POLL_INTERVAL_SECONDS` before starting the cycle again.

## Usage Example

### 1. Prerequisites
- Python 3.8+
- An RPC URL for an Ethereum-compatible network. You can get one for free from services like [Infura](https://infura.io/) or [Alchemy](https://www.alchemy.com/). This script is pre-configured for the Sepolia testnet.

### 2. Setup

First, clone the repository and navigate into the directory:
```bash
git clone https://github.com/your-username/checker_bw.git
cd checker_bw
```

Next, create a virtual environment and install the required dependencies:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
pip install -r requirements.txt
```

### 3. Configuration

The script can be configured via environment variables. While it has default values for demonstration, you can override them.

```bash
# Recommended: Export your RPC URL as an environment variable
export RPC_URL="https://sepolia.infura.io/v3/your-infura-project-id"

# (Optional) You can also change the contract to listen to
export BRIDGE_CONTRACT_ADDRESS="0x...."
```

The script is configured by default to listen for `Deposit` events on the Sepolia WETH contract (`0x7b79995e5f793A07Bc00c21412e50Eaae098E7f9`), which serves as a great real-world example of a high-traffic contract emitting events.

### 4. Running the Script

Simply execute the python script:
```bash
python script.py
```

You will see log output in your terminal as the listener connects, scans for blocks, and processes events if any are found.

**Expected Output:**

```
2023-10-27 15:30:00 - INFO - Successfully connected to Ethereum node. Chain ID: 11155111
2023-10-27 15:30:00 - INFO - SignatureRelaySimulator initialized for validator: 0x...
2023-10-27 15:30:00 - INFO - Starting Cross-Chain Event Listener...
2023-10-27 15:30:02 - INFO - Scanning for events from block 4850101 to 4850120
2023-10-27 15:30:05 - INFO - Found 2 potential event(s). Parsing and processing...
2023-10-27 15:30:05 - INFO - Processing new event: 0x...-34 from block 4850115
2023-10-27 15:30:05 - INFO - Relaying event 0x...-34 to https://httpbin.org/post
2023-10-27 15:30:06 - INFO - Successfully relayed event. Response: { ... }
2023-10-27 15:30:06 - INFO - Successfully processed and marked event 0x...-34 as complete.
...
2023-10-27 15:30:07 - INFO - Finished scan. Last processed block updated to: 4850120
2023-10-27 15:30:07 - INFO - Waiting for 15 seconds before next poll.
```

A `listener_state.json` file will be created in the same directory to store the script's progress.