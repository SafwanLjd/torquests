"""Parsers for the microdescriptor consensus and for microdescriptors.

These implement the netdoc meta-format line discipline (dir-spec/netdoc.md): a
document is a sequence of keyword lines, each optionally followed by one
PEM-style object. Reading is relaxed where the spec demands it:
unknown keywords are ignored and extra arguments are tolerated, while every
field this client relies on is validated strictly, raising
:class:`ConsensusError` on malformed input.

Two document kinds are handled:

* the microdescriptor-flavor consensus (dir-spec/computing-consensus.md,
  "Microdescriptor consensus"): the ``r`` line has *no* descriptor-digest field,
  the ``m`` line carries the base64 SHA-256 microdescriptor digest, and the
  preamble/footer/signature items follow dir-spec/consensus-formats.md;
* microdescriptors (dir-spec/computing-microdescriptors.md): each entry starts
  at its ``onion-key`` line and is identified by the SHA-256 of its raw text.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import itertools
import re
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import NamedTuple

from ..exceptions import ConsensusError
from .models import (
    Consensus,
    ConsensusSignature,
    ExitPolicySummary,
    Microdescriptor,
    RouterStatus,
)

_KEYWORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*\Z")
_IPV4_RE = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z")


class _Item(NamedTuple):
    """One netdoc item: a keyword line plus its optional object."""

    keyword: str
    args: list[str]
    object_label: str | None
    object_data: str  # concatenated base64 lines; "" when there is no object


def _items(lines: list[str]) -> Iterator[_Item]:
    """Iterate netdoc items over ``lines`` (dir-spec/netdoc.md grammar)."""
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line:
            continue  # Document ::= (Item | NL)+, bare newlines are allowed
        if line.startswith("-----"):
            raise ConsensusError(f"object delimiter without a keyword line: {line!r}")
        parts = line.split()
        if parts and parts[0] == "opt":  # historical prefix; SHOULD be accepted
            parts = parts[1:]
        if not parts or not _KEYWORD_RE.match(parts[0]):
            raise ConsensusError(f"malformed keyword line: {line!r}")
        label: str | None = None
        data = ""
        if i < len(lines) and lines[i].startswith("-----BEGIN "):
            begin = lines[i]
            if not begin.endswith("-----"):
                raise ConsensusError(f"malformed object begin line: {begin!r}")
            label = begin[len("-----BEGIN ") : -len("-----")]
            end = f"-----END {label}-----"
            i += 1
            body: list[str] = []
            while i < len(lines) and lines[i] != end:
                if lines[i].startswith("-----"):
                    raise ConsensusError(f"mismatched object end line: {lines[i]!r}")
                body.append(lines[i])
                i += 1
            if i >= len(lines):
                raise ConsensusError(f"unterminated {label} object")
            i += 1
            data = "".join(body)
        yield _Item(parts[0], parts[1:], label, data)


def _b64(value: str, *, length: int | None, what: str) -> bytes:
    """Decode base64 that may or may not carry trailing ``=`` padding."""
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except binascii.Error as exc:
        raise ConsensusError(f"malformed base64 in {what}: {value!r}") from exc
    if length is not None and len(raw) != length:
        raise ConsensusError(f"{what} must be {length} bytes, got {len(raw)}")
    return raw


def _hex(value: str, *, length: int, what: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ConsensusError(f"malformed hex in {what}: {value!r}") from exc
    if len(raw) != length:
        raise ConsensusError(f"{what} must be {length} bytes, got {len(raw)}")
    return raw


def _int(value: str, what: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise ConsensusError(f"malformed integer in {what}: {value!r}") from exc


def _datetime(args: list[str], what: str) -> datetime:
    """Parse the two-argument DateWsTime form, e.g. ``2026-01-01 12:00:00``."""
    if len(args) < 2:
        raise ConsensusError(f"{what} needs a date and a time")
    try:
        parsed = datetime.strptime(f"{args[0]} {args[1]}", "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise ConsensusError(f"malformed timestamp in {what}: {args[0]} {args[1]!r}") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _ipv4(value: str, what: str) -> str:
    match = _IPV4_RE.match(value)
    if match is None or any(int(octet) > 255 for octet in match.groups()):
        raise ConsensusError(f"malformed IPv4 address in {what}: {value!r}")
    return value


def _shared_random(args: list[str], what: str) -> bytes:
    """``shared-rand-*-value NumReveals Value`` with a 256-bit base64 value."""
    if len(args) < 2:
        raise ConsensusError(f"{what} needs a reveal count and a value")
    return _b64(args[1], length=32, what=what)


def _params(args: list[str]) -> dict[str, int]:
    params: dict[str, int] = {}
    for arg in args:
        key, sep, value = arg.partition("=")
        if not sep or not key:
            raise ConsensusError(f"malformed params entry: {arg!r}")
        params[key] = _int(value, f"params {key}")
    return params


class _RouterBuilder:
    """Accumulates one router status entry between ``r`` lines."""

    def __init__(self, args: list[str]) -> None:
        # md-flavor r line: nickname identity publication-date publication-time
        # IP ORPort DirPort (no descriptor digest field).
        if len(args) < 7:
            raise ConsensusError(f"malformed md-consensus r line: {' '.join(args)!r}")
        self.nickname = args[0]
        self.fingerprint = _b64(args[1], length=20, what="router identity")
        # args[2:4] is the publication timestamp; a fixed dummy in md consensuses.
        self.address = _ipv4(args[4], "r line")
        self.or_port = _int(args[5], "r line ORPort")
        self.dir_port = _int(args[6], "r line DirPort")
        self.flags: frozenset[str] = frozenset()
        self.bandwidth = 0
        self.microdescriptor_digest: bytes | None = None

    def build(self) -> RouterStatus:
        return RouterStatus(
            nickname=self.nickname,
            fingerprint=self.fingerprint,
            address=self.address,
            or_port=self.or_port,
            dir_port=self.dir_port,
            flags=self.flags,
            bandwidth=self.bandwidth,
            microdescriptor_digest=self.microdescriptor_digest,
        )


def _signature(item: _Item) -> ConsensusSignature:
    """Parse a ``directory-signature [algorithm] identity signing-key-digest`` item."""
    args = item.args
    if len(args) == 2:
        algorithm, identity_hex, digest_hex = "sha1", args[0], args[1]  # sha1 is the default
    elif len(args) >= 3:
        algorithm, identity_hex, digest_hex = args[0], args[1], args[2]
    else:
        raise ConsensusError(f"malformed directory-signature line: {' '.join(args)!r}")
    if item.object_label != "SIGNATURE":
        raise ConsensusError("directory-signature item is missing its SIGNATURE object")
    return ConsensusSignature(
        algorithm=algorithm,
        identity=_hex(identity_hex, length=20, what="signature identity"),
        signing_key_digest=_hex(digest_hex, length=20, what="signing-key digest"),
        signature=_b64(item.object_data, length=None, what="SIGNATURE object"),
    )


def parse_consensus(text: str) -> Consensus:
    """Parse a microdescriptor-flavor consensus document.

    Raises :class:`ConsensusError` if the document is not a version-3
    ``microdesc`` consensus or any relied-upon field is malformed. Signatures
    are parsed but not verified here; see
    :func:`torquests._dir.consensus.verify_consensus`.
    """
    items = _items(text.split("\n"))
    first = next(items, None)
    if first is None or first.keyword != "network-status-version":
        raise ConsensusError("document does not start with network-status-version")
    if first.args[:2] != ["3", "microdesc"]:
        raise ConsensusError(f"not a version-3 microdesc consensus: {' '.join(first.args)!r}")

    valid_after: datetime | None = None
    fresh_until: datetime | None = None
    valid_until: datetime | None = None
    params: dict[str, int] = {}
    bandwidth_weights: dict[str, int] = {}
    srv_current: bytes | None = None
    srv_previous: bytes | None = None
    routers: list[RouterStatus] = []
    signatures: list[ConsensusSignature] = []
    current: _RouterBuilder | None = None

    for item in items:
        keyword = item.keyword
        if keyword == "r":
            if current is not None:
                routers.append(current.build())
            current = _RouterBuilder(item.args)
        elif keyword == "s" and current is not None:
            current.flags = frozenset(item.args)
        elif keyword == "w" and current is not None:
            for arg in item.args:
                if arg.startswith("Bandwidth="):
                    current.bandwidth = _int(arg[len("Bandwidth=") :], "w Bandwidth")
                    break
            else:
                raise ConsensusError("w line is missing its Bandwidth= argument")
        elif keyword == "m" and current is not None:
            if not item.args:
                raise ConsensusError("m line is missing its digest argument")
            current.microdescriptor_digest = _b64(
                item.args[0], length=32, what="microdescriptor digest"
            )
        elif keyword == "vote-status":
            if item.args[:1] != ["consensus"]:
                raise ConsensusError(f"vote-status is not consensus: {item.args!r}")
        elif keyword == "valid-after":
            valid_after = _datetime(item.args, keyword)
        elif keyword == "fresh-until":
            fresh_until = _datetime(item.args, keyword)
        elif keyword == "valid-until":
            valid_until = _datetime(item.args, keyword)
        elif keyword == "params":
            params = _params(item.args)
        elif keyword == "bandwidth-weights":
            bandwidth_weights = _params(item.args)
        elif keyword == "shared-rand-current-value":
            srv_current = _shared_random(item.args, keyword)
        elif keyword == "shared-rand-previous-value":
            srv_previous = _shared_random(item.args, keyword)
        elif keyword == "directory-footer":
            if current is not None:
                routers.append(current.build())
                current = None
        elif keyword == "directory-signature":
            if current is not None:  # tolerate a footer-less document
                routers.append(current.build())
                current = None
            signatures.append(_signature(item))
        # Every other keyword ('a', 'v', 'pr', dir-source, known-flags, ...) is
        # deliberately ignored, as netdoc requires for forward compatibility.

    if current is not None:
        routers.append(current.build())
    if valid_after is None or fresh_until is None or valid_until is None:
        raise ConsensusError("consensus is missing valid-after/fresh-until/valid-until")
    if not signatures:
        raise ConsensusError("consensus has no directory-signature items")
    return Consensus(
        valid_after=valid_after,
        fresh_until=fresh_until,
        valid_until=valid_until,
        routers=routers,
        params=params,
        bandwidth_weights=bandwidth_weights,
        shared_random_current=srv_current,
        shared_random_previous=srv_previous,
        signatures=tuple(signatures),
    )


def _parse_microdescriptor(chunk: str) -> Microdescriptor:
    """Parse one microdescriptor from its raw text (starting at ``onion-key``)."""
    ntor_onion_key: bytes | None = None
    ed25519_id: bytes | None = None
    exit_policy: ExitPolicySummary | None = None
    family: frozenset[str] = frozenset()
    for item in _items(chunk.split("\n")):
        if item.keyword == "ntor-onion-key":
            if not item.args:
                raise ConsensusError("ntor-onion-key line is missing its key argument")
            ntor_onion_key = _b64(item.args[0], length=32, what="ntor-onion-key")
        elif item.keyword == "id" and item.args[:1] == ["ed25519"]:
            if len(item.args) < 2:
                raise ConsensusError("id ed25519 line is missing its key argument")
            ed25519_id = _b64(item.args[1], length=32, what="id ed25519")
        elif item.keyword == "p":
            exit_policy = _exit_policy(item.args)
        elif item.keyword == "family":
            family = frozenset(item.args)
        # onion-key (and its optional PEM object), a, p6, family-ids, and
        # other id keytypes are skipped: clients do not need them.
    if ntor_onion_key is None:
        raise ConsensusError("microdescriptor is missing its ntor-onion-key")
    return Microdescriptor(
        digest=hashlib.sha256(chunk.encode("utf-8")).digest(),
        ntor_onion_key=ntor_onion_key,
        ed25519_id=ed25519_id,
        exit_policy=exit_policy,
        family=family,
    )


def _exit_policy(args: list[str]) -> ExitPolicySummary:
    """Parse ``p accept|reject <PortList>``."""
    if len(args) < 2 or args[0] not in ("accept", "reject"):
        raise ConsensusError(f"malformed exit policy summary: {' '.join(args)!r}")
    ranges: list[tuple[int, int]] = []
    for part in args[1].split(","):
        low_text, sep, high_text = part.partition("-")
        low = _int(low_text, "exit policy port")
        high = _int(high_text, "exit policy port") if sep else low
        if not 1 <= low <= high <= 65535:
            raise ConsensusError(f"exit policy port range out of order: {part!r}")
        ranges.append((low, high))
    return ExitPolicySummary(accept=args[0] == "accept", ports=tuple(ranges))


def parse_microdescriptors(text: str) -> list[Microdescriptor]:
    """Parse a batch of concatenated microdescriptors.

    Each entry starts at its ``onion-key`` line and its digest is the SHA-256 of
    its raw text through the start of the next entry, the same bytes the
    consensus ``m`` digest commits to.
    """
    if not text.strip():
        return []
    starts: list[int] = []
    offset = 0
    for line in text.split("\n"):
        if line == "onion-key":
            starts.append(offset)
        offset += len(line) + 1
    if not starts:
        raise ConsensusError("microdescriptor batch contains no onion-key lines")
    if text[: starts[0]].strip():
        raise ConsensusError("garbage before the first microdescriptor")
    bounds = [*starts, len(text)]
    return [_parse_microdescriptor(text[a:b]) for a, b in itertools.pairwise(bounds)]
