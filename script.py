import os
import json
import time
import logging
from typing import Dict, Any, List, Optional

import requests
from web3 import Web3
from web3.types import LogReceipt
from web3.exceptions import BlockNotFound
from eth_account import Account
from eth_account.messages import encode_defunct

# --- Configuration ---
# It's recommended to use environment variables for sensitive data like RPC URLs and private keys.
RPC_URL = os.environ.get("RPC_URL", "https://rpc.sepolia.org")
# This is the WETH contract on Sepolia testnet. We'll use its 'Deposit' event as a proxy for a bridge 'Lock' event.
BRIDGE_CONTRACT_ADDRESS = os.environ.get("BRIDGE_CONTRACT_ADDRESS", "0x7b79995e5f793A07Bc00c21412e50Eaae098E7f9")
# Event signature for 'Deposit(address indexed dst, uint wad)'
EVENT_SIGNATURE_HASH = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"

# Simulation parameters
POLL_INTERVAL_SECONDS = 15  # Time to wait between checking for new blocks
BLOCK_CONFIRMATIONS = 6     # Number of blocks to wait for before processing an event to avoid reorgs
STATE_FILE = 'listener_state.json'
RELAY_API_ENDPOINT = "https://httpbin.org/post" # Mock endpoint to simulate posting to a destination chain relayer

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


class StateDB:
    """
    A simple file-based database to maintain the listener's state.
    This ensures that if the script restarts, it can resume from where it left off
    and doesn't re-process events.
    """
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        """Loads the state from the JSON file. If the file doesn't exist, initializes a default state."""
        try:
            with open(self.filepath, 'r') as f:
                state = json.load(f)
                logging.info(f"Loaded state from {self.filepath}")
                return state
        except (FileNotFoundError, json.JSONDecodeError):
            logging.warning(f"State file not found or invalid. Initializing new state.")
            return {"last_processed_block": 0, "processed_event_ids": []}

    def save_state(self):
        """Saves the current state to the JSON file."""
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.data, f, indent=4)
        except IOError as e:
            logging.error(f"Failed to save state to {self.filepath}: {e}")

    def get_last_processed_block(self) -> int:
        """Returns the last block number that was successfully processed."""
        return self.data.get("last_processed_block", 0)

    def set_last_processed_block(self, block_number: int):
        """Updates the last processed block number in the state."""
        self.data["last_processed_block"] = block_number

    def is_event_processed(self, event_id: str) -> bool:
        """Checks if an event has already been processed to prevent replay attacks."""
        return event_id in self.data["processed_event_ids"]

    def mark_event_as_processed(self, event_id: str):
        """Adds an event's unique identifier to the list of processed events."""
        if not self.is_event_processed(event_id):
            self.data["processed_event_ids"].append(event_id)


class EventParser:
    """
    Responsible for decoding raw event logs from the blockchain into a structured format.
    This separation of concerns makes the main listener logic cleaner.
    """
    @staticmethod
    def parse_deposit_event(log: LogReceipt) -> Optional[Dict[str, Any]]:
        """
        Parses a raw log for a 'Deposit' event.
        This simulates parsing a cross-chain 'Lock' event.
        
        Args:
            log: The raw event log from web3.py.
        
        Returns:
            A dictionary with structured event data or None if parsing fails.
        """
        try:
            # The event signature is 'Deposit(address indexed dst, uint wad)'
            # Topic 0: Event signature hash
            # Topic 1: `dst` (the indexed address)
            # Data: `wad` (the non-indexed amount)
            
            # Decode the indexed 'dst' address from topics
            # Topics are 32-byte hex strings. The address is the last 20 bytes.
            dst_address = Web3.to_checksum_address('0x' + log['topics'][1].hex()[-40:])
            
            # Decode the non-indexed 'wad' amount from the data field
            amount = Web3.to_int(hexstr=log['data'].hex())
            
            # Create a unique identifier for the event to prevent replays
            event_id = f"{log['transactionHash'].hex()}-{log['logIndex']}"

            return {
                "event_id": event_id,
                "destination_user": dst_address,
                "amount": amount,
                "source_tx_hash": log['transactionHash'].hex(),
                "block_number": log['blockNumber']
            }
        except (IndexError, ValueError) as e:
            logging.error(f"Failed to parse event log. Log: {log}. Error: {e}")
            return None


class SignatureRelaySimulator:
    """
    Simulates the off-chain component that aggregates signatures from validators/relayers
    and submits the finalized data to the destination chain.
    """
    def __init__(self, relayer_api: str):
        self.relayer_api = relayer_api
        # In a real system, this key would be securely managed (e.g., HSM, Vault)
        self.validator_private_key = Account.create().key.hex()
        self.validator_address = Account.from_key(self.validator_private_key).address
        logging.info(f"SignatureRelaySimulator initialized for validator: {self.validator_address}")

    def sign_and_relay(self, event_data: Dict[str, Any]) -> bool:
        """
        Simulates signing the event data and relaying it to the destination chain's network.
        
        Args:
            event_data: The structured data of the event to be relayed.
        
        Returns:
            True if the relay was successful (simulated), False otherwise.
        """
        message_to_sign = json.dumps(event_data, sort_keys=True)
        message_hash = encode_defunct(text=message_to_sign)
        signed_message = Account.sign_message(message_hash, private_key=self.validator_private_key)

        payload = {
            "event_data": event_data,
            "validator_signature": {
                "validator": self.validator_address,
                "signature": signed_message.signature.hex()
            }
        }

        logging.info(f"Relaying event {event_data['event_id']} to {self.relayer_api}")
        try:
            response = requests.post(self.relayer_api, json=payload, timeout=10)
            response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
            logging.info(f"Successfully relayed event. Response: {response.json()}")
            return True
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to relay event {event_data['event_id']}. Error: {e}")
            return False


class TransactionProcessor:
    """
    Processes validated events. This involves checking for duplicates and coordinating
    with the relay simulator to send the transaction to the destination chain.
    """
    def __init__(self, state_db: StateDB, relay_simulator: SignatureRelaySimulator):
        self.state_db = state_db
        self.relay_simulator = relay_simulator

    def process_event(self, event_data: Dict[str, Any]):
        """
        Handles the logic for processing a single parsed event.
        """
        event_id = event_data['event_id']
        if self.state_db.is_event_processed(event_id):
            logging.warning(f"Skipping already processed event: {event_id}")
            return

        logging.info(f"Processing new event: {event_id} from block {event_data['block_number']}")
        
        # Here you could add more validation logic, e.g., checking the amount against a threshold,
        # cross-referencing with an off-chain oracle, etc.

        # Simulate relaying the event to the destination chain
        if self.relay_simulator.sign_and_relay(event_data):
            # Only mark as processed if relay was successful
            self.state_db.mark_event_as_processed(event_id)
            logging.info(f"Successfully processed and marked event {event_id} as complete.")
        else:
            logging.error(f"Processing failed for event {event_id} due to relay failure. Will retry later.")


class CrossChainEventListener:
    """
    The main component that connects to the source blockchain, scans for blocks and events,
    and orchestrates the parsing and processing workflow.
    """
    def __init__(self, rpc_url: str, contract_address: str, event_topic: str):
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        if not self.web3.is_connected():
            raise ConnectionError(f"Failed to connect to Ethereum node at {rpc_url}")
        
        logging.info(f"Successfully connected to Ethereum node. Chain ID: {self.web3.eth.chain_id}")
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.event_topic = event_topic
        self.state_db = StateDB(STATE_FILE)
        relay_simulator = SignatureRelaySimulator(RELAY_API_ENDPOINT)
        self.processor = TransactionProcessor(self.state_db, relay_simulator)
        

    def run(self):
        """Starts the main event listening loop."""
        logging.info("Starting Cross-Chain Event Listener...")
        while True:
            try:
                self.scan_blocks()
            except Exception as e:
                logging.error(f"An unexpected error occurred in the main loop: {e}", exc_info=True)
            
            logging.info(f"Waiting for {POLL_INTERVAL_SECONDS} seconds before next poll.")
            time.sleep(POLL_INTERVAL_SECONDS)

    def scan_blocks(self):
        """
        Scans a range of blocks from the last processed block to the latest confirmed block.
        """
        latest_block = self.web3.eth.block_number
        # We process up to a certain number of blocks behind the head to handle reorgs.
        target_block = latest_block - BLOCK_CONFIRMATIONS
        
        start_block = self.state_db.get_last_processed_block()
        if start_block == 0:
            # On first run, start from the target block to avoid processing the whole chain history.
            start_block = target_block - 1

        if start_block >= target_block:
            logging.info(f"No new confirmed blocks to process. Current head: {latest_block}, last processed: {start_block}")
            return
        
        # To avoid overwhelming the RPC node, process in chunks if the gap is too large.
        # For this simulation, we'll keep it simple and process the whole range.
        end_block = target_block
        logging.info(f"Scanning for events from block {start_block + 1} to {end_block}")

        # Fetch logs for the block range
        try:
            logs = self.web3.eth.get_logs({
                'fromBlock': start_block + 1,
                'toBlock': end_block,
                'address': self.contract_address,
                'topics': [self.event_topic]
            })
        except (BlockNotFound, ValueError) as e:
            logging.error(f"Error fetching logs: {e}. The RPC node might not have data for this range.")
            return

        if not logs:
            logging.info("No relevant events found in this block range.")
        else:
            logging.info(f"Found {len(logs)} potential event(s). Parsing and processing...")
            for log in sorted(logs, key=lambda x: (x['blockNumber'], x['logIndex'])):
                parsed_event = EventParser.parse_deposit_event(log)
                if parsed_event:
                    self.processor.process_event(parsed_event)

        # After processing all logs in the range, update the state and save it.
        self.state_db.set_last_processed_block(end_block)
        self.state_db.save_state()
        logging.info(f"Finished scan. Last processed block updated to: {end_block}")


def main():
    """Main entry point of the script."""
    try:
        listener = CrossChainEventListener(
            rpc_url=RPC_URL,
            contract_address=BRIDGE_CONTRACT_ADDRESS,
            event_topic=EVENT_SIGNATURE_HASH
        )
        listener.run()
    except ConnectionError as e:
        logging.critical(f"Initialization failed: {e}")
    except KeyboardInterrupt:
        logging.info("Shutting down listener...")
    except Exception as e:
        logging.critical(f"A fatal error occurred during initialization: {e}", exc_info=True)

if __name__ == "__main__":
    main()
