"""An SNS signing identity: RSA key, certificate served at an sns.<region>.amazonaws.com URL."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from self_healing_infrastructure_agents.security.sns import SnsEnvelope
from tests.conftest import START, TOPIC_ARN

CERT_URL = "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0000000000000000.pem"


@dataclass
class SnsSigner:
    key: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    confirmations: list[str] = field(default_factory=list)

    def certificate_pem(self) -> bytes:
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sns.amazonaws.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(1)
            .not_valid_before(START - timedelta(days=30))
            .not_valid_after(START + timedelta(days=365))
            .sign(self.key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM)

    def transport(self) -> httpx.MockTransport:
        pem = self.certificate_pem()

        def handler(request: httpx.Request) -> httpx.Response:
            if str(request.url) == CERT_URL:
                return httpx.Response(200, content=pem)
            if request.url.host == "sns.us-east-1.amazonaws.com":
                self.confirmations.append(str(request.url))
                return httpx.Response(200, text="<ConfirmSubscriptionResponse/>")
            return httpx.Response(404)

        return httpx.MockTransport(handler)

    def envelope(
        self,
        message: str,
        *,
        kind: str = "Notification",
        topic: str = TOPIC_ARN,
        timestamp: str = "2026-10-14T13:56:03.123Z",
        cert_url: str = CERT_URL,
        version: str = "2",
        **extra: Any,
    ) -> dict[str, Any]:
        document: dict[str, Any] = {
            "Type": kind,
            "MessageId": "6f3c1a2b-9d8e-4f70-a1b2-c3d4e5f60718",
            "TopicArn": topic,
            "Message": message,
            "Timestamp": timestamp,
            "SignatureVersion": version,
            "SigningCertURL": cert_url,
            **extra,
        }
        if kind == "Notification":
            document.setdefault("Subject", "ALARM: orders-db-FreeStorageSpace-low")
            document["UnsubscribeURL"] = (
                "https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=x"
            )
        to_sign = SnsEnvelope.parse({**document, "Signature": "x"}).string_to_sign()
        signature = self.key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
        document["Signature"] = base64.b64encode(signature).decode()
        return document

    def body(self, document: dict[str, Any]) -> bytes:
        return json.dumps(document).encode()


@pytest.fixture
def sns_signer() -> SnsSigner:
    return SnsSigner()
