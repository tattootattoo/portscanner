"""
transports/_x509_lite.py
The standard ssl library returns an **empty** getpeercert() when
verify_mode=CERT_NONE (a deliberate CPython security decision, so
unverified certificate data isn't treated as trusted). Since what we're
doing here is discovery/fingerprinting rather than trust verification,
we need to extract the fields (Subject, Issuer, validity) manually from
the raw DER bytes (getpeercert(binary_form=True) always returns them
regardless of verify_mode).

This is a very minimal ASN.1/DER decoder — just for the fields we
need, not a full X.509 implementation. No external dependency (neither
cryptography nor pyOpenSSL) to keep the project lightweight.
"""

from __future__ import annotations

_SEQUENCE = 0x30
_SET = 0x31
_OID = 0x06
_EXPLICIT_VERSION = 0xA0

# the most common OIDs in Name fields (RFC 4514) — 2.5.4.x, DER-encoded
_OID_LABELS: dict[bytes, str] = {
    bytes.fromhex("550403"): "CN",
    bytes.fromhex("55040A"): "O",
    bytes.fromhex("55040B"): "OU",
    bytes.fromhex("550406"): "C",
    bytes.fromhex("550408"): "ST",
    bytes.fromhex("550407"): "L",
}


class _DERError(Exception):
    pass


def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise _DERError("ran past the end of the data while reading the length")
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    num_bytes = first & 0x7F
    if num_bytes == 0 or pos + 1 + num_bytes > len(data):
        raise _DERError("invalid DER length format")
    length = int.from_bytes(data[pos + 1:pos + 1 + num_bytes], "big")
    return length, pos + 1 + num_bytes


def _read_tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Returns (tag, content_start, content_end). Doesn't support
    multi-byte tags (not needed for the fields we extract here)."""
    if pos >= len(data):
        raise _DERError("ran past the end of the data while reading the tag")
    tag = data[pos]
    length, content_start = _read_length(data, pos + 1)
    content_end = content_start + length
    if content_end > len(data):
        raise _DERError("TLV length exceeds the actual data size")
    return tag, content_start, content_end


def _format_name(name_der: bytes) -> str:
    """RDNSequence: a sequence of SETs, each containing SEQUENCE{OID, value}."""
    parts: list[str] = []
    pos = 0
    n = len(name_der)
    while pos < n:
        _set_tag, set_start, set_end = _read_tlv(name_der, pos)
        inner_tag, inner_start, _inner_end = _read_tlv(name_der, set_start)
        if inner_tag != _SEQUENCE:
            pos = set_end
            continue
        oid_tag, oid_start, oid_end = _read_tlv(name_der, inner_start)
        if oid_tag != _OID:
            pos = set_end
            continue
        oid_bytes = name_der[oid_start:oid_end]
        _val_tag, val_start, val_end = _read_tlv(name_der, oid_end)
        raw_value = name_der[val_start:val_end]
        try:
            value = raw_value.decode("utf-8")
        except UnicodeDecodeError:
            value = raw_value.hex()
        label = _OID_LABELS.get(oid_bytes, "OID." + oid_bytes.hex())
        parts.append(f"{label}={value}")
        pos = set_end
    return ", ".join(parts)


def parse_certificate_fields(der: bytes) -> dict[str, str] | None:
    """
    Parses an X.509 (DER) certificate and returns only
    Subject/Issuer/validity. Returns None silently if the certificate
    can't be parsed (instead of failing the whole scan — this is
    optional supplementary discovery, definitely not a critical step).
    """
    try:
        _cert_tag, cert_start, _cert_end = _read_tlv(der, 0)
        _tbs_tag, tbs_start, _tbs_end = _read_tlv(der, cert_start)

        pos = tbs_start
        tag, content_start, content_end = _read_tlv(der, pos)
        if tag == _EXPLICIT_VERSION:  # optional version field [0] EXPLICIT
            pos = content_end
            tag, content_start, content_end = _read_tlv(der, pos)
        pos = content_end  # skip serialNumber (INTEGER)

        _sig_tag, _sig_start, sig_end = _read_tlv(der, pos)  # signature AlgId
        pos = sig_end

        _issuer_tag, issuer_start, issuer_end = _read_tlv(der, pos)
        issuer_bytes = der[issuer_start:issuer_end]
        pos = issuer_end

        _validity_tag, validity_start, validity_end = _read_tlv(der, pos)
        pos = validity_end

        _subject_tag, subject_start, subject_end = _read_tlv(der, pos)
        subject_bytes = der[subject_start:subject_end]

        _nb_tag, nb_start, nb_end = _read_tlv(der, validity_start)
        not_before = der[nb_start:nb_end].decode("ascii", errors="ignore")
        _na_tag, na_start, na_end = _read_tlv(der, nb_end)
        not_after = der[na_start:na_end].decode("ascii", errors="ignore")

        return {
            "subject": _format_name(subject_bytes),
            "issuer": _format_name(issuer_bytes),
            "not_before": not_before,
            "not_after": not_after,
        }
    except (_DERError, IndexError, ValueError):
        return None
