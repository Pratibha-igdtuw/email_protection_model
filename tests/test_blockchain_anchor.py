"""
Tests for modules/blockchain_anchor.py (real on-chain evidence anchoring).

Two layers, matching the module's own design:

1. Graceful-degradation tests -- WEB3_* env vars unset (the default in the
   test environment, see conftest.py), so every function must short-circuit
   to a 'not_configured' status without importing web3 or touching the
   network at all.

2. Real-EVM tests -- deploys the *actual compiled* EvidenceAnchor contract
   (contracts/build/, see contracts/README.md) to eth-tester's in-memory
   Ethereum implementation and exercises modules/blockchain_anchor.py's
   real functions against it: genuine EVM execution (including the
   contract's require() revert path), no live network needed, so this
   runs the same in CI as it does locally.
"""
import json
import os

import pytest

from modules import blockchain_anchor as ba

CONTRACTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'contracts', 'build')


# --------------------------------------------------------------------------
# Layer 1: not configured (default state)
# --------------------------------------------------------------------------

def test_is_configured_false_by_default(monkeypatch):
    monkeypatch.delenv('WEB3_RPC_URL', raising=False)
    monkeypatch.delenv('WEB3_PRIVATE_KEY', raising=False)
    monkeypatch.delenv('WEB3_CONTRACT_ADDRESS', raising=False)
    assert ba.is_configured() is False


def test_is_configured_true_when_all_three_set(monkeypatch):
    monkeypatch.setenv('WEB3_RPC_URL', 'https://example-rpc.test')
    monkeypatch.setenv('WEB3_PRIVATE_KEY', '0xabc')
    monkeypatch.setenv('WEB3_CONTRACT_ADDRESS', '0xdef')
    assert ba.is_configured() is True


def test_is_configured_false_when_one_missing(monkeypatch):
    monkeypatch.setenv('WEB3_RPC_URL', 'https://example-rpc.test')
    monkeypatch.setenv('WEB3_PRIVATE_KEY', '0xabc')
    monkeypatch.delenv('WEB3_CONTRACT_ADDRESS', raising=False)
    assert ba.is_configured() is False


def test_submit_anchor_not_configured(monkeypatch):
    monkeypatch.delenv('WEB3_RPC_URL', raising=False)
    assert ba.submit_anchor('aa' * 32) == {'status': 'not_configured'}


def test_check_confirmation_not_configured(monkeypatch):
    monkeypatch.delenv('WEB3_RPC_URL', raising=False)
    assert ba.check_confirmation('0xdeadbeef') == 'not_configured'


def test_verify_onchain_not_configured(monkeypatch):
    monkeypatch.delenv('WEB3_RPC_URL', raising=False)
    assert ba.verify_onchain('aa' * 32) == {'status': 'not_configured'}


def test_explorer_tx_url_default_network(monkeypatch):
    monkeypatch.delenv('WEB3_EXPLORER_BASE_URL', raising=False)
    url = ba.explorer_tx_url('0x1234')
    assert url == 'https://sepolia.etherscan.io/tx/0x1234'


def test_explorer_tx_url_none_when_no_hash():
    assert ba.explorer_tx_url(None) is None


def test_explorer_tx_url_custom_base(monkeypatch):
    monkeypatch.setenv('WEB3_EXPLORER_BASE_URL', 'https://amoy.polygonscan.com/tx')
    assert ba.explorer_tx_url('0xabcd') == 'https://amoy.polygonscan.com/tx/0xabcd'


# --------------------------------------------------------------------------
# Layer 2: real EVM execution via eth-tester (skipped if the optional dev
# deps aren't installed -- these are not required to run the app itself,
# only to run this specific real-contract-execution test)
# --------------------------------------------------------------------------

eth_tester_stack = pytest.importorskip(
    "eth_tester", reason="eth-tester/py-evm not installed -- optional, see requirements-dev.txt"
)
web3_mod = pytest.importorskip("web3", reason="web3 not installed -- see requirements.txt")


@pytest.fixture()
def deployed_contract(monkeypatch):
    """Deploys the real compiled EvidenceAnchor bytecode to an in-memory
    EVM and points modules/blockchain_anchor.py at it, so the module's own
    functions run against genuine contract execution."""
    from web3 import Web3
    from eth_tester import EthereumTester

    abi_path = os.path.join(CONTRACTS_DIR, 'EvidenceAnchor.abi.json')
    bin_path = os.path.join(CONTRACTS_DIR, 'EvidenceAnchor.bin')
    if not (os.path.exists(abi_path) and os.path.exists(bin_path)):
        pytest.skip("contracts/build/ artifacts missing -- see contracts/README.md to regenerate")

    with open(abi_path) as f:
        abi = json.load(f)
    with open(bin_path) as f:
        bytecode = f.read().strip()

    tester = EthereumTester()
    w3 = Web3(Web3.EthereumTesterProvider(tester))
    deployer = w3.eth.accounts[0]

    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Contract.constructor().transact({'from': deployer})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = receipt.contractAddress
    contract = w3.eth.contract(address=contract_address, abi=ba.CONTRACT_ABI)

    # Point the module at this in-memory chain instead of a real RPC.
    monkeypatch.setattr(ba, '_w3', w3)
    monkeypatch.setattr(ba, '_contract', contract)

    private_key_hex = tester.backend.account_keys[0].to_hex()
    monkeypatch.setenv('WEB3_RPC_URL', 'unused-monkeypatched-w3')
    monkeypatch.setenv('WEB3_PRIVATE_KEY', private_key_hex)
    monkeypatch.setenv('WEB3_CONTRACT_ADDRESS', contract_address)
    monkeypatch.setenv('WEB3_NETWORK_NAME', 'eth-tester (test)')

    return {'w3': w3, 'contract': contract, 'deployer': deployer}


def test_submit_and_confirm_real_anchor(deployed_contract):
    w3 = deployed_contract['w3']
    test_hash = w3.keccak(text="test-block-hash-1").hex()

    result = ba.submit_anchor(test_hash)
    assert result['status'] == 'submitted'
    assert result['tx_hash']

    status = ba.check_confirmation(result['tx_hash'])
    assert status == 'confirmed'


def test_verify_onchain_finds_anchored_hash(deployed_contract):
    w3 = deployed_contract['w3']
    test_hash = w3.keccak(text="test-block-hash-2").hex()

    result = ba.submit_anchor(test_hash)
    ba.check_confirmation(result['tx_hash'])  # mines it (eth-tester auto-mines)

    verify = ba.verify_onchain(test_hash)
    assert verify['status'] == 'found'
    assert verify['anchored_by'].lower() == deployed_contract['deployer'].lower()
    assert verify['timestamp'] > 0


def test_verify_onchain_not_found_for_unseen_hash(deployed_contract):
    w3 = deployed_contract['w3']
    unseen_hash = w3.keccak(text="never anchored").hex()
    assert ba.verify_onchain(unseen_hash) == {'status': 'not_found'}


def test_duplicate_anchor_fails_gracefully(deployed_contract):
    """The contract's require() blocks re-anchoring the same hash --
    submit_anchor must report this as a normal 'failed' result, not raise."""
    w3 = deployed_contract['w3']
    test_hash = w3.keccak(text="test-block-hash-3").hex()

    first = ba.submit_anchor(test_hash)
    assert first['status'] == 'submitted'
    ba.check_confirmation(first['tx_hash'])

    second = ba.submit_anchor(test_hash)
    assert second['status'] == 'failed'
    assert 'already anchored' in second['error']
