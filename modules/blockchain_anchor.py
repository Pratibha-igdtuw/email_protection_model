"""
Real blockchain anchoring layer, sitting on top of modules/blockchain.py's
local hash-chain.

modules/blockchain.py already implements a genuine blockchain data
structure in this app's own database: linked block hashes, proof-of-work
mining, end-to-end verification. Its threat model is "did anyone silently
edit the evidence after the fact on this one server" -- and it answers
that correctly, without a network of any kind.

This module extends that with a *different* trust model: it publishes
each local block's hash to a public Ethereum-compatible chain (default:
the Sepolia testnet) via the EvidenceAnchor smart contract
(contracts/EvidenceAnchor.sol), so a hash's existence at a given time is
attested to by every node on that network -- not by whoever operates this
server. Anyone, with no access to this app's database at all, can call
verify_onchain() (or read the contract directly on a public block
explorer) and independently confirm a hash was anchored, by whom, and
when.

This is strictly additive. If the env vars below aren't set,
is_configured() returns False, every block's on-chain status is simply
"not_configured", and modules/blockchain.py's local chain keeps working
exactly as it did before -- on-chain anchoring is never required to run
the platform or to trust the local hash-chain on its own.

Setup (see README "Real blockchain anchoring setup" for the full
step-by-step walkthrough -- wallet, faucet, contract deployment via
Remix, RPC provider):
    WEB3_RPC_URL            e.g. a free Sepolia RPC endpoint
    WEB3_PRIVATE_KEY        0x-prefixed hex private key of a TESTNET-ONLY
                             wallet -- never point this at a wallet that
                             holds real funds
    WEB3_CONTRACT_ADDRESS   address EvidenceAnchor.sol was deployed to
    WEB3_NETWORK_NAME       optional, default 'sepolia' (label only)
    WEB3_EXPLORER_BASE_URL  optional, default Sepolia Etherscan's tx URL

Design note on why this doesn't wait for confirmation inline: a public
testnet block takes ~12+ seconds to mine, and this function is called
synchronously from the case-analysis request/response cycle
(modules/blockchain.py -> modules/chain_of_custody.py -> app.py). Making
an analyst wait 12+ seconds on every single email analysis for a
best-effort forensic add-on would be a bad trade. So submit_anchor()
only *broadcasts* the transaction (~1-2 seconds) and returns immediately
with a 'submitted' status and the transaction hash; check_confirmation()
is a separate, cheap, non-blocking receipt check that the /blockchain
page calls on every load to move any still-'submitted' blocks to
'confirmed' or 'failed' once they've actually been mined.
"""
import os

CONTRACT_ABI = [
    {
        "inputs": [{"internalType": "bytes32", "name": "blockHash", "type": "bytes32"}],
        "name": "anchorHash",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "blockHash", "type": "bytes32"}],
        "name": "getAnchor",
        "outputs": [
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "address", "name": "anchoredBy", "type": "address"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "bytes32", "name": "blockHash", "type": "bytes32"},
            {"indexed": True, "internalType": "address", "name": "anchoredBy", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
        ],
        "name": "HashAnchored",
        "type": "event",
    },
]

_w3 = None
_contract = None


def is_configured():
    return bool(
        os.environ.get('WEB3_RPC_URL')
        and os.environ.get('WEB3_PRIVATE_KEY')
        and os.environ.get('WEB3_CONTRACT_ADDRESS')
    )


def network_name():
    return os.environ.get('WEB3_NETWORK_NAME', 'sepolia')


def explorer_tx_url(tx_hash):
    if not tx_hash:
        return None
    base = os.environ.get('WEB3_EXPLORER_BASE_URL', 'https://sepolia.etherscan.io/tx/')
    return f"{base}{tx_hash}" if base.endswith('/') else f"{base}/{tx_hash}"


def _get_w3_and_contract():
    """Lazily connects on first use (not at import time -- importing this
    module must never require web3/network access, since is_configured()
    needs to work even when the package isn't fully set up)."""
    global _w3, _contract
    if _w3 is None:
        from web3 import Web3
        _w3 = Web3(Web3.HTTPProvider(os.environ['WEB3_RPC_URL'], request_kwargs={'timeout': 10}))
        _contract = _w3.eth.contract(
            address=Web3.to_checksum_address(os.environ['WEB3_CONTRACT_ADDRESS']),
            abi=CONTRACT_ABI,
        )
    return _w3, _contract


def _hex_to_bytes32(hex_str):
    return bytes.fromhex(hex_str[2:] if hex_str.startswith('0x') else hex_str)


def _signed_raw_bytes(signed_tx):
    # web3.py v6 renamed SignedTransaction.rawTransaction -> raw_transaction;
    # support either so this doesn't silently break on a version bump.
    return getattr(signed_tx, 'raw_transaction', None) or signed_tx.rawTransaction


def submit_anchor(block_hash_hex):
    """
    Broadcasts an anchorHash(blockHash) transaction. Returns immediately
    once the transaction is accepted into the mempool -- does NOT wait
    for it to be mined (see module docstring for why).

    Returns one of:
      {'status': 'not_configured'}
      {'status': 'submitted', 'tx_hash': '0x...', 'network': 'sepolia'}
      {'status': 'failed', 'error': '<message>'}
    """
    if not is_configured():
        return {'status': 'not_configured'}
    try:
        from web3 import Web3

        w3, contract = _get_w3_and_contract()
        account = w3.eth.account.from_key(os.environ['WEB3_PRIVATE_KEY'])
        nonce = w3.eth.get_transaction_count(account.address, 'pending')
        hash_bytes32 = _hex_to_bytes32(block_hash_hex)

        tx = contract.functions.anchorHash(hash_bytes32).build_transaction({
            'from': account.address,
            'nonce': nonce,
            'chainId': w3.eth.chain_id,
        })
        try:
            tx['gas'] = int(w3.eth.estimate_gas(tx) * 1.2)
        except Exception:
            tx['gas'] = 100_000  # generous flat fallback for this tiny function if estimation fails

        latest = w3.eth.get_block('latest')
        base_fee = latest.get('baseFeePerGas', Web3.to_wei(1, 'gwei'))
        priority_fee = Web3.to_wei(1.5, 'gwei')
        tx['maxPriorityFeePerGas'] = priority_fee
        tx['maxFeePerGas'] = base_fee * 2 + priority_fee

        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(_signed_raw_bytes(signed))
        return {'status': 'submitted', 'tx_hash': tx_hash.hex(), 'network': network_name()}
    except Exception as e:
        return {'status': 'failed', 'error': str(e)}


def check_confirmation(tx_hash):
    """
    Cheap, non-blocking receipt check for a previously-submitted
    transaction. Safe to call repeatedly. Returns 'confirmed', 'failed'
    (the transaction reverted), 'pending' (not mined yet, or the node
    hasn't seen it propagate yet), or 'not_configured'.
    """
    if not is_configured():
        return 'not_configured'
    try:
        w3, _ = _get_w3_and_contract()
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        if receipt is None:
            return 'pending'
        return 'confirmed' if receipt.status == 1 else 'failed'
    except Exception:
        return 'pending'


def verify_onchain(block_hash_hex):
    """
    Read-only call, no wallet or gas needed: independently confirms
    whether a hash is really anchored on-chain right now, straight from
    the contract -- not from this app's own ChainBlock row. This is the
    function that actually delivers "trust the chain, not this server".

    Returns {'status': 'not_configured'} | {'status': 'not_found'} |
            {'status': 'found', 'timestamp': int, 'anchored_by': '0x...'} |
            {'status': 'error', 'message': str}
    """
    if not is_configured():
        return {'status': 'not_configured'}
    try:
        _, contract = _get_w3_and_contract()
        hash_bytes32 = _hex_to_bytes32(block_hash_hex)
        timestamp, anchored_by = contract.functions.getAnchor(hash_bytes32).call()
        if timestamp == 0:
            return {'status': 'not_found'}
        return {'status': 'found', 'timestamp': timestamp, 'anchored_by': anchored_by}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
