import hashlib

from modules import chain_of_custody


def test_compute_sha256_matches_hashlib():
    data = b"hello world"
    assert chain_of_custody.compute_sha256(data) == hashlib.sha256(data).hexdigest()


def test_verify_integrity_true_when_unmodified(tmp_path):
    data = b"evidence bytes"
    path = tmp_path / "evidence.eml"
    path.write_bytes(data)
    expected_hash = chain_of_custody.compute_sha256(data)

    verified, current_hash = chain_of_custody.verify_integrity(str(path), expected_hash)
    assert verified is True
    assert current_hash == expected_hash


def test_verify_integrity_false_when_tampered(tmp_path):
    path = tmp_path / "evidence.eml"
    path.write_bytes(b"original bytes")
    expected_hash = chain_of_custody.compute_sha256(b"original bytes")

    path.write_bytes(b"tampered bytes")
    verified, current_hash = chain_of_custody.verify_integrity(str(path), expected_hash)
    assert verified is False
    assert current_hash != expected_hash


def test_verify_integrity_missing_file():
    verified, current_hash = chain_of_custody.verify_integrity('/nonexistent/path.eml', 'deadbeef')
    assert verified is False
    assert current_hash is None


def test_build_custody_record_contains_expected_fields(tmp_path):
    path = tmp_path / "evidence.eml"
    path.write_bytes(b"data")
    evidence_hash = chain_of_custody.compute_sha256(b"data")

    record = chain_of_custody.build_custody_record('CASE-1', str(path), evidence_hash)
    assert record['case_ref'] == 'CASE-1'
    assert record['integrity_verified'] is True
    assert record['hash_algorithm'] == 'SHA-256'
    assert 'compliance_note' in record
