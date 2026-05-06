"""Orchestration for mining and IPv8 submission."""

from __future__ import annotations

import asyncio
from pathlib import Path

from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8_service import IPv8

from .constants import DEFAULT_KEY_FILE, DEFAULT_PROGRESS_FILE, GITHUB_URL, PRECOMPUTED_NONCE, STUDENT_EMAIL
from .pow import WorkUnit, digest_for, leading_zero_bits, read_checkpoint, satisfies_target, solve_pow
from .protocol import LabRegistrationOverlay, ServerReply


IPV8_PORT = 0
RESPONSE_TIMEOUT_SECONDS = 180.0


def obtain_nonce(work: WorkUnit, supplied_nonce: int | None, progress_file: Path) -> int:
    if supplied_nonce is not None:
        digest = digest_for(work.payload_prefix(), supplied_nonce)
        if not satisfies_target(digest):
            zeros = leading_zero_bits(digest)
            raise ValueError(f"supplied nonce only has {zeros} leading zero bits")
        print(f"Using supplied nonce {supplied_nonce}.")
        return supplied_nonce

    resume_from = read_checkpoint(progress_file, work) or 0
    if resume_from:
        print(f"Resuming Proof of Work search from nonce {resume_from}.")
    else:
        print("Starting Proof of Work search at nonce 0.")

    def report(next_nonce: int, elapsed: float) -> None:
        rate = next_nonce / elapsed if elapsed > 0 else 0.0
        print(f"Checked through nonce {next_nonce:,} ({rate:,.0f} hashes/s).")

    nonce = solve_pow(work, start=resume_from, progress=report, progress_file=progress_file)
    zeros = leading_zero_bits(digest_for(work.payload_prefix(), nonce))
    print(f"Found valid nonce {nonce} with {zeros} leading zero bits.")
    return nonce


def ipv8_configuration(key_path: Path, port: int) -> dict:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(port)
    builder.add_key("student", "curve25519", str(key_path))
    builder.add_overlay(
        "LabRegistrationOverlay",
        "student",
        [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )
    return builder.finalize()


async def submit_over_ipv8(
    email: str,
    github_url: str,
    nonce: int,
    *,
    key_path: Path,
    port: int,
    timeout: float,
) -> ServerReply:
    config = ipv8_configuration(key_path, port)
    ipv8 = IPv8(config, extra_communities={"LabRegistrationOverlay": LabRegistrationOverlay})

    await ipv8.start()
    try:
        overlay = next(overlay for overlay in ipv8.overlays if isinstance(overlay, LabRegistrationOverlay))
        waiter: asyncio.Future[ServerReply] = asyncio.get_running_loop().create_future()
        overlay.queue_submission(email, github_url, nonce, waiter)
        return await asyncio.wait_for(waiter, timeout=timeout)
    finally:
        await ipv8.stop()


async def run_async() -> int:
    work = WorkUnit(STUDENT_EMAIL, GITHUB_URL)
    nonce = obtain_nonce(work, PRECOMPUTED_NONCE, Path(DEFAULT_PROGRESS_FILE))

    reply = await submit_over_ipv8(
        work.email,
        work.github_url,
        nonce,
        key_path=Path(DEFAULT_KEY_FILE),
        port=IPV8_PORT,
        timeout=RESPONSE_TIMEOUT_SECONDS,
    )
    print(f"Server replied: success={reply.success}, message={reply.message}")
    return 0 if reply.success else 1


def main() -> int:
    return asyncio.run(run_async())
