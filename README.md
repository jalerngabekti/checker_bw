```
---
# checker_bw: Cross-Chain Bridge Event Listener Simulator

This repository provides a Python-based simulation of a critical component in a cross-chain bridge architecture: the event listener, also known as a relayer or oracle. This script connects to a source blockchain (like Ethereum or a compatible testnet), listens for specific events from a bridge contract, validates them, and simulates the process of relaying this information to a destination chain.

This project serves as a blueprint, showcasing the principles of modularity, state management, and resilience required for real-world blockchain infrastructure components.

## Concept

A cross-chain bridge enables the transfer of assets or data from one blockchain to another. A common design pattern is the “lock-and-mint” mechanism:

1. **Lock:** A user deposits assets into a smart contract on the source chain (e.g., locking 100 ETH).
2. **Event Emission:** The source chain contract emits an event (`AssetLocked`) containing details of the deposit (user, amount, destination chain).
3. **Validation & Relay:** A network of off-chain listeners (validators/relayers) detects this event. They wait for a certain number of block confirmations to ensure the transaction is final and not part of a blockchain reorganization (reorg).
4. **Mint:** After validating the event, the relayers submit a signed message to a contract on the destination chain. Once a sufficient number of signatures are collected, the destination contract mints a corresponding amount of a wrapped asset (e.g., 100 wETH) for the user.

This script simulates the crucial **Step 3**, acting as one of these off-chain listeners.

## Code Architecture

The script is designed with a clear separation of concerns, implemented through several distinct classes:

- **`CrossChainEventListener`**: The main orchestrator. It manages the connection to the source chain’s RPC node, handles the main polling loop, and determines which blocks to scan.

- **`StateDB`**: A simple, file-based persistence layer. It keeps track of the `last_processed_block` and a list of `processed_event_ids`. This ensures that the listener can be stopped and restarted without losing its place or reprocessing the same event, helping to prevent replay attacks.

- **`EventParser`**: A static utility class responsible for decoding raw log data received from the blockchain into a structured, human-readable format. This isolates the logic for decoding raw event data, which can be complex and error-prone.

- **`TransactionProcessor`**: This class takes a parsed event and applies the core business logic. It checks if the event has already been processed using the `StateDB` and then coordinates with the `SignatureRelaySimulator` to forward the event.

- **`SignatureRelaySimulator`**: Simulates the final step of a relayer’s duty. It generates a cryptographic signature for the event data (as a real validator would) and sends the event payload and signature to a mock API endpoint, simulating a submission to the destination chain’s relayer network.

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

1. **Initialization**: The `CrossChainEventListener` connects to the specified RPC endpoint and initializes all helper classes, including loading the previous state from `listener_state.json` via `StateDB`.
2. **Polling Loop**: The listener enters an infinite loop, periodically waking up to check for new blocks.
3. **Block Scanning**: It determines the range of blocks to scan, from `last_processed_block + 1` up to `latest_block_number - BLOCK_CONFIRMATIONS`.
4. **Log Fetching**: It queries the RPC node for all event logs within that block range that match the specified bridge contract address and event topic hash.
5. **Parsing**: For each log found, the `EventParser` decodes the data into a structured dictionary. For example:

    ```json
    {
      "event_id": "0xabc...-34",
      "block_number": 4850115,
      "transaction_hash": "0xabc...",
      "log_index": 34,
      "event_name": "Deposit",
      "data": {
        "dst": "0xUserAddress...",
        "wad": 1000000000000000000
      }
    }
    ```

6. **Processing**: The `TransactionProcessor` receives the parsed event. It first queries the `StateDB` to ensure the event’s unique ID (`tx_hash-log_index`) has not been processed before.
7. **Signing & Relaying**: If the event is new, the `SignatureRelaySimulator` signs a digest of the event data and `POST`s it to a mock API endpoint.
8. **State Update**: If the relay is successful, the `TransactionProcessor` instructs the `StateDB` to mark the event ID as processed. Finally, the `CrossChainEventListener` updates the `last_processed_block` in the `StateDB` and saves the state to the JSON file.
9. **Wait**: The listener then sleeps for `POLL_INTERVAL_SECONDS` before starting the cycle again.

## Usage

### 1. Prerequisites

- Python 3.8+
- An RPC URL for an Ethereum-compatible network. You can get one for free from services like Infura or Alchemy.

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

Configuration is managed via environment variables. Create a `.env` file in the project’s root directory with the following content:

**Example `.env` file:**

```dotenv
# Required: Your RPC URL for the source chain (e.g., Sepolia)
RPC_URL="https://sepolia.infura.io/v3/your-infura-project-id"

# Optional: Override the default bridge contract address.
# BRIDGE_CONTRACT_ADDRESS="0x..."
```

By default, the script is pre-configured to listen for `Deposit` events on the Sepolia WETH contract (`0x7b79995e5f793A07Bc00c21412e50Eaae098E7f9`), which serves as a real-world example of a high-traffic contract emitting events.

### 4. Running the Script

With your virtual environment activated and the `.env` file configured, start the listener by running the main Python script:

```bash
python script.py
```

You will see log output in your terminal as the listener connects, scans for blocks, and processes any events it finds.

**Expected Output:**

```
YYYY-MM-DD HH:MM:SS - INFO - Successfully connected to Ethereum node. Chain ID: 11155111
YYYY-MM-DD HH:MM:SS - INFO - SignatureRelaySimulator initialized for validator: 0x...
YYYY-MM-DD HH:MM:SS - INFO - Starting Cross-Chain Event Listener...
YYYY-MM-DD HH:MM:SS - INFO - Scanning for events from block 4850101 to 4850120
YYYY-MM-DD HH:MM:SS - INFO - Found 2 potential event(s). Parsing and processing...
YYYY-MM-DD HH:MM:SS - INFO - Processing new event: 0x...-34 from block 4850115
YYYY-MM-DD HH:MM:SS - INFO - Relaying event 0x...-34 to https://httpbin.org/post
YYYY-MM-DD HH:MM:SS - INFO - Successfully relayed event. Response: { ... }
YYYY-MM-DD HH:MM:SS - INFO - Successfully processed and marked event 0x...-34 as complete.
...
YYYY-MM-DD HH:MM:SS - INFO - Finished scan. Last processed block updated to: 4850120
YYYY-MM-DD HH:MM:SS - INFO - Waiting for 15 seconds before next poll.
```

A `listener_state.json` file will be created in the same directory to store the script’s progress. It tracks the last block scanned and the unique IDs of events that have already been relayed to prevent duplicates.

```json
{
  "last_processed_block": 4850120,
  "processed_event_ids": [
    "0xabc...def-34",
    "0x123...456-51"
  ]
}
```

### 5. Minimal Usage Example

Once the listener is running, you can interact with it programmatically (for example, from a Python REPL) by importing the main class and starting it manually:

```python
from checker_bw.listener import CrossChainEventListener

listener = CrossChainEventListener()
listener.run()  # Starts the polling loop and blocks until interrupted (Ctrl+C)
```

This mirrors the behavior of `python script.py` and can be adapted for integration into larger systems or testing harnesses.
---
```