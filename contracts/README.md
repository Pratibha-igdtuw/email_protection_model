# contracts/

`EvidenceAnchor.sol` is the on-chain half of the evidence ledger (see
`modules/blockchain_anchor.py` for the Python side, and README.md's
"Real blockchain anchoring setup" for how to deploy this to a public
testnet).

## build/

`build/EvidenceAnchor.abi.json` and `build/EvidenceAnchor.bin` are the
compiled ABI and bytecode, checked in so:

  - `tests/test_blockchain_anchor.py` can deploy the *real* compiled
    contract to an in-memory EVM (`eth-tester`) and test against actual
    contract execution, without needing a Solidity compiler installed in
    CI.
  - Anyone who wants to deploy via a script (instead of Remix) has ready-
    to-use bytecode without installing solc locally.

Compiled with solc 0.8.19 (optimizer on) via `solcjs` (the npm-distributed
build of the Solidity compiler -- no local solc install needed):

```bash
npm install solc@0.8.19
npx solcjs --optimize --abi --bin contracts/EvidenceAnchor.sol -o /tmp/build
cp /tmp/build/*EvidenceAnchor_sol_EvidenceAnchor.abi contracts/build/EvidenceAnchor.abi.json
cp /tmp/build/*EvidenceAnchor_sol_EvidenceAnchor.bin  contracts/build/EvidenceAnchor.bin
```

Re-run this any time `EvidenceAnchor.sol` changes, and redeploy (a new
deployment gets a new contract address -- update `WEB3_CONTRACT_ADDRESS`).
