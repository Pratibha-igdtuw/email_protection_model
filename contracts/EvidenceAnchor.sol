// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title EvidenceAnchor
/// @notice Anchors forensic evidence block hashes on a public Ethereum-
/// compatible chain for independent, tamper-evident timestamping.
///
/// This is the "real blockchain" layer for ThreatForensicAI's evidence
/// ledger: modules/blockchain.py already keeps a local, append-only
/// hash-chain in this app's own database (a genuine blockchain data
/// structure -- linked block hashes, proof-of-work mining). That local
/// chain proves nobody edited old evidence *without leaving a trace in
/// this database*. It cannot prove nobody controlling this server quietly
/// rewrote the whole database and regenerated a self-consistent chain.
///
/// Anchoring each local block's hash here closes that gap: once a hash is
/// anchored, its existence at that timestamp is attested to by every node
/// on the network this contract is deployed to -- not by this app's
/// operator. Anyone, including someone who has never seen this app's
/// database, can call getAnchor() (or read the contract on a public block
/// explorer) and independently confirm a given hash was anchored, by whom,
/// and when.
///
/// Design is intentionally minimal: one mapping, one write function, one
/// read function, one event. There is nothing here to upgrade, pause, or
/// own -- once deployed, anchoring is permissionless (anyone can call
/// anchorHash) and permanent (no delete/overwrite function exists).
contract EvidenceAnchor {
    struct Anchor {
        uint256 timestamp;   // block.timestamp when anchored; 0 = not anchored
        address anchoredBy;  // wallet that submitted the anchoring transaction
    }

    mapping(bytes32 => Anchor) private anchors;

    event HashAnchored(bytes32 indexed blockHash, address indexed anchoredBy, uint256 timestamp);

    /// @notice Anchor a 32-byte hash on-chain. Reverts if this exact hash
    /// has already been anchored (each hash can only be anchored once --
    /// re-anchoring would let someone quietly move its timestamp later).
    function anchorHash(bytes32 blockHash) external {
        require(anchors[blockHash].timestamp == 0, "EvidenceAnchor: hash already anchored");
        anchors[blockHash] = Anchor({timestamp: block.timestamp, anchoredBy: msg.sender});
        emit HashAnchored(blockHash, msg.sender, block.timestamp);
    }

    /// @notice Look up when/by whom a hash was anchored.
    /// @return timestamp 0 if never anchored, otherwise the block.timestamp of anchoring
    /// @return anchoredBy the zero address if never anchored
    function getAnchor(bytes32 blockHash) external view returns (uint256 timestamp, address anchoredBy) {
        Anchor memory a = anchors[blockHash];
        return (a.timestamp, a.anchoredBy);
    }
}
