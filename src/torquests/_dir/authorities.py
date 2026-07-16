"""The directory authorities: the trust roots for consensus verification.

A consensus is only as trustworthy as the authority set it is checked against, so
:func:`torquests._dir.consensus.verify_consensus` takes the authority list as
an argument rather than a global: tests inject self-generated authorities, and
production uses :data:`DEFAULT_AUTHORITIES`.

The ``v3ident`` fingerprints below are the trust anchor. They are transcribed from
the Tor source (``src/app/config/auth_dirs.inc``) and are the values named in
consensus ``directory-signature`` lines. Each authority signs consensuses with a
medium-term signing key published in its key certificate; those keys rotate, so
they are fetched and verified against the identity fingerprint at bootstrap (see
:mod:`torquests._dir.keycerts`) rather than hardcoded.
"""

from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class DirectoryAuthority:
    """One v3 directory authority."""

    nickname: str
    v3ident: bytes  # 20-byte SHA-1 fingerprint of the identity key
    dir_address: tuple[str, int] = ("", 0)  # (host, DirPort) for bootstrap fetches
    signing_key_pem: bytes | None = None  # current signing key, filled at bootstrap

    def with_signing_key(self, signing_key_pem: bytes) -> DirectoryAuthority:
        return replace(self, signing_key_pem=signing_key_pem)


def _authority(nickname: str, v3ident_hex: str, host: str, dir_port: int) -> DirectoryAuthority:
    return DirectoryAuthority(nickname, bytes.fromhex(v3ident_hex), (host, dir_port))


#: The v3 directory authorities (Tor ``auth_dirs.inc``). Bridge authorities, which
#: do not sign consensuses, are omitted.
DEFAULT_AUTHORITIES: tuple[DirectoryAuthority, ...] = (
    _authority("moria1", "F533C81CEF0BC0267857C99B2F471ADF249FA232", "128.31.0.39", 9231),
    _authority("tor26", "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C", "217.196.147.77", 80),
    _authority("dizum", "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58", "45.66.35.11", 80),
    _authority("gabelmoo", "ED03BB616EB2F60BEC80151114BB25CEF515B226", "131.188.40.189", 80),
    _authority("dannenberg", "0232AF901C31A04EE9848595AF9BB7620D4C5B2E", "193.23.244.244", 80),
    _authority("maatuska", "49015F787433103580E3B66A1707A00E60F2D15B", "171.25.193.9", 443),
    _authority("longclaw", "23D15D965BC35114467363C165C4F724B64B4F66", "199.58.81.140", 80),
    _authority("bastet", "27102BC123E7AF1D4741AE047E160C91ADC76B21", "204.13.164.118", 80),
    _authority("faravahar", "70849B868D606BAECFB6128C5E3D782029AA394F", "216.218.219.41", 80),
)
