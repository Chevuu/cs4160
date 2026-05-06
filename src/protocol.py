"""IPv8 overlay and payloads for the Lab 1 wire protocol."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional, Tuple

from ipv8.community import Community
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer

from .constants import COMMUNITY_ID_HEX, SERVER_PUBLIC_KEY_HEX


@vp_compile
class SubmissionPayload(VariablePayload):
    """Client-to-server message with the solved PoW tuple."""

    msg_id = 1
    names = ["email", "github_url", "nonce"]
    format_list = ["varlenHutf8", "varlenHutf8", "q"]


@vp_compile
class ResponsePayload(VariablePayload):
    """Server response message."""

    msg_id = 2
    names = ["success", "message"]
    format_list = ["?", "varlenHutf8"]


@dataclass(frozen=True)
class ServerReply:
    success: bool
    message: str


class LabRegistrationOverlay(Community):
    """Community client that only trusts the published Lab 1 server key."""

    community_id = bytes.fromhex(COMMUNITY_ID_HEX)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._expected_server_key = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)
        self._pending_submission: Optional[Tuple[str, str, int]] = None
        self._reply_waiter: Optional[asyncio.Future[ServerReply]] = None
        self._sent_once = False
        self.add_message_handler(ResponsePayload, self._handle_response)

    def queue_submission(
        self,
        email: str,
        github_url: str,
        nonce: int,
        reply_waiter: asyncio.Future[ServerReply],
    ) -> None:
        """Start looking for the server and send once it appears."""

        self._pending_submission = (email, github_url, nonce)
        self._reply_waiter = reply_waiter
        self._sent_once = False
        self.register_task("lab1-submit-when-server-visible", self._send_when_possible, interval=2.0, delay=0.0)

    async def _send_when_possible(self) -> None:
        if self._sent_once or self._pending_submission is None:
            return

        server = self._find_server_peer()
        if server is None:
            print("Waiting for the registered Lab 1 server peer...")
            return

        email, github_url, nonce = self._pending_submission
        print(f"Server discovered at {server.address}; sending authenticated submission.")
        self.ez_send(server, SubmissionPayload(email, github_url, nonce))
        self._sent_once = True

    def _find_server_peer(self) -> Optional[Peer]:
        for peer in self.get_peers():
            if self._peer_key_bytes(peer) == self._expected_server_key:
                return peer
        return None

    @lazy_wrapper(ResponsePayload)
    def _handle_response(self, peer: Peer, payload: ResponsePayload) -> None:
        if self._peer_key_bytes(peer) != self._expected_server_key:
            print("Ignoring response from a peer whose public key does not match the Lab 1 server.")
            return

        reply = ServerReply(payload.success, payload.message)
        if self._reply_waiter is not None and not self._reply_waiter.done():
            self._reply_waiter.set_result(reply)

    @staticmethod
    def _peer_key_bytes(peer: Peer) -> bytes:
        return peer.public_key.key_to_bin()
