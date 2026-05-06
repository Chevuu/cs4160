"""Proof of Work helpers for the Lab 1 submission."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .constants import DIFFICULTY_BITS, MAX_WIRE_NONCE


ProgressCallback = Callable[[int, float], None]


@dataclass(frozen=True)
class WorkUnit:
    """Immutable input tuple for the Proof of Work search."""

    email: str
    github_url: str

    def payload_prefix(self) -> bytes:
        validate_identity_fields(self.email, self.github_url)
        return self.email.encode("utf-8") + b"\n" + self.github_url.encode("utf-8") + b"\n"


def validate_identity_fields(email: str, github_url: str) -> None:
    """Check the client-side constraints that affect PoW construction."""

    email_bytes = email.encode("utf-8")
    github_bytes = github_url.encode("utf-8")

    if not email or b"\n" in email_bytes or len(email_bytes) > 254:
        raise ValueError("email must be non-empty, at most 254 bytes, and contain no newline")
    if not (email.endswith("@tudelft.nl") or email.endswith("@student.tudelft.nl")):
        raise ValueError("email must use a TU Delft domain")
    if not github_url or len(github_bytes) > 512:
        raise ValueError("github_url must be non-empty and at most 512 bytes")
    if any(ord(ch) <= 32 or ord(ch) == 127 for ch in github_url):
        raise ValueError("github_url must not contain whitespace or control characters")


def encode_nonce(nonce: int) -> bytes:
    """Return the nonce as the exact 8-byte big-endian value used by the server."""

    if nonce < 0 or nonce > MAX_WIRE_NONCE:
        raise ValueError("nonce must fit in a signed positive int64")
    return nonce.to_bytes(8, "big", signed=False)


def digest_for(prefix: bytes, nonce: int) -> bytes:
    """Compute SHA256(prefix || nonce64be)."""

    return hashlib.sha256(prefix + encode_nonce(nonce)).digest()


def leading_zero_bits(digest: bytes) -> int:
    """Count zero bits from the start of a hash digest."""

    total = 0
    for byte in digest:
        if byte == 0:
            total += 8
            continue
        total += 8 - byte.bit_length()
        break
    return total


def satisfies_target(digest: bytes, difficulty: int = DIFFICULTY_BITS) -> bool:
    """Return whether the digest reaches the requested leading-zero-bit target."""

    full_zero_bytes, remaining_bits = divmod(difficulty, 8)
    if digest[:full_zero_bytes] != b"\x00" * full_zero_bytes:
        return False
    if remaining_bits == 0:
        return True
    return digest[full_zero_bytes] < (1 << (8 - remaining_bits))


def solve_pow(
    work: WorkUnit,
    *,
    start: int = 0,
    checkpoint_every: int = 250_000,
    progress: Optional[ProgressCallback] = None,
    progress_file: Optional[Path] = None,
) -> int:
    """Search upward from ``start`` until a valid nonce is found."""

    prefix = work.payload_prefix()
    nonce = start
    started_at = time.monotonic()

    while nonce <= MAX_WIRE_NONCE:
        if satisfies_target(digest_for(prefix, nonce)):
            if progress_file is not None:
                write_checkpoint(progress_file, work, nonce)
            return nonce

        nonce += 1
        if checkpoint_every > 0 and nonce % checkpoint_every == 0:
            if progress is not None:
                progress(nonce, time.monotonic() - started_at)
            if progress_file is not None:
                write_checkpoint(progress_file, work, nonce)

    raise RuntimeError("nonce space exhausted without finding a solution")


def write_checkpoint(path: Path, work: WorkUnit, next_nonce: int) -> None:
    """Persist enough state to resume a long mining run."""

    path.write_text(
        json.dumps(
            {
                "email": work.email,
                "github_url": work.github_url,
                "next_nonce": next_nonce,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def read_checkpoint(path: Path, work: WorkUnit) -> Optional[int]:
    """Return a saved nonce only when it belongs to the exact current work input."""

    if not path.exists():
        return None

    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("email") != work.email or data.get("github_url") != work.github_url:
        return None

    nonce = int(data["next_nonce"])
    if nonce < 0 or nonce > MAX_WIRE_NONCE:
        return None
    return nonce
