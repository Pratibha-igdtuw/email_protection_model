"""
USP 4 (blockchain piece): a minimal, append-only hash-chain used as the
tamper-evident ledger for forensic chain-of-custody records.

This is a genuine blockchain data structure -- each block commits to the
PREVIOUS block's hash via SHA-256 (see _hash_block), so editing any past
block, or the case evidence it attests to, changes that block's hash and
breaks every link after it in verify_chain(). A small proof-of-work step
(_mine) mirrors the difficulty-target idea from real blockchains: a block
is only accepted once its hash has DIFFICULTY leading hex zeros, found by
incrementing a nonce.

Scope note (say this out loud in the viva if asked "which blockchain
network does this run on?"): this is a single-writer, single-server
ledger, not a distributed one -- there is no P2P network, no consensus
protocol, and no multiple untrusted nodes voting on one history, because
this project's threat model is "did anyone silently edit the evidence
after the fact on this one server", not "can mutually distrusting
parties agree on shared state". A real multi-node deployment (e.g.
Hyperledger Fabric, or anchoring block_hash values on a public chain)
would extend this without changing the block structure below.
"""
import hashlib
from datetime import datetime, timezone

from models import db, ChainBlock

GENESIS_HASH = '0' * 64
DIFFICULTY = 2  # required leading hex zeros in a mined block hash


def _hash_block(index, case_ref, evidence_sha256, previous_hash, timestamp_str, nonce):
    payload = f"{index}|{case_ref}|{evidence_sha256}|{previous_hash}|{timestamp_str}|{nonce}"
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _mine(index, case_ref, evidence_sha256, previous_hash, timestamp_str):
    """Increment nonce until the block hash has DIFFICULTY leading hex
    zeros. DIFFICULTY=2 keeps this near-instant (~hundreds of tries on
    average) so evidence ingestion isn't slowed down, while still
    demonstrating real proof-of-work mining."""
    nonce = 0
    target = '0' * DIFFICULTY
    while True:
        candidate = _hash_block(index, case_ref, evidence_sha256, previous_hash, timestamp_str, nonce)
        if candidate.startswith(target):
            return nonce, candidate
        nonce += 1


def add_block(case_ref, evidence_sha256):
    """Mine and append a new block committing to this case's evidence
    hash and the previous block's hash. Returns the persisted ChainBlock.

    Also best-effort anchors this block's hash on a public testnet via
    modules/blockchain_anchor.py, if configured. This never blocks or
    fails case ingestion -- the local hash-chain above is already a
    complete, self-contained tamper-evident ledger on its own; on-chain
    anchoring is an additional, independent trust layer stacked on top
    of it, not a dependency of it."""
    last = ChainBlock.query.order_by(ChainBlock.block_index.desc()).first()
    index = (last.block_index + 1) if last else 0
    previous_hash = last.block_hash if last else GENESIS_HASH
    timestamp = datetime.now(timezone.utc)
    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')

    nonce, block_hash = _mine(index, case_ref, evidence_sha256, previous_hash, timestamp_str)

    block = ChainBlock(
        block_index=index,
        case_ref=case_ref,
        evidence_sha256=evidence_sha256,
        previous_hash=previous_hash,
        block_hash=block_hash,
        nonce=nonce,
        timestamp=timestamp,
    )
    db.session.add(block)
    db.session.commit()

    try:
        from modules import blockchain_anchor
        result = blockchain_anchor.submit_anchor(block.block_hash)
        block.onchain_status = result.get('status', 'not_configured')
        block.onchain_tx_hash = result.get('tx_hash')
        block.onchain_network = result.get('network')
        block.onchain_error = result.get('error')
        db.session.commit()
    except Exception as e:
        block.onchain_status = 'failed'
        block.onchain_error = str(e)
        db.session.commit()

    return block


def refresh_pending_onchain_status():
    """Checks every block still marked 'submitted' and, if its
    transaction has since been mined, updates it to 'confirmed' or
    'failed'. Cheap (one non-blocking receipt lookup per pending block,
    no waiting) -- safe to call on every /blockchain page load."""
    from modules import blockchain_anchor

    pending = ChainBlock.query.filter_by(onchain_status='submitted').all()
    changed = False
    for block in pending:
        if not block.onchain_tx_hash:
            continue
        new_status = blockchain_anchor.check_confirmation(block.onchain_tx_hash)
        if new_status in ('confirmed', 'failed') and new_status != block.onchain_status:
            block.onchain_status = new_status
            if new_status == 'confirmed':
                block.onchain_confirmed_at = datetime.now(timezone.utc)
            changed = True
    if changed:
        db.session.commit()


def verify_chain():
    """Walk the entire chain from genesis and recompute every block's
    hash. Returns (is_valid, first_broken_index_or_None, total_blocks).

    A break means either a block's stored fields were altered after the
    fact, or its previous_hash link to the prior block no longer
    matches -- both are caught here without trusting any single row."""
    blocks = ChainBlock.query.order_by(ChainBlock.block_index.asc()).all()
    expected_previous = GENESIS_HASH
    for block in blocks:
        if block.previous_hash != expected_previous:
            return False, block.block_index, len(blocks)
        recomputed = _hash_block(
            block.block_index, block.case_ref, block.evidence_sha256,
            block.previous_hash,
            block.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
            block.nonce,
        )
        if recomputed != block.block_hash:
            return False, block.block_index, len(blocks)
        expected_previous = block.block_hash
    return True, None, len(blocks)


def get_block_for_case(case_ref):
    return ChainBlock.query.filter_by(case_ref=case_ref).order_by(ChainBlock.block_index.desc()).first()


def get_all_blocks():
    return ChainBlock.query.order_by(ChainBlock.block_index.asc()).all()
