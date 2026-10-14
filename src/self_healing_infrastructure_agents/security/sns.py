"""Amazon SNS message signature verification.

SNS signs every HTTP(S) delivery. We accept only SignatureVersion 2
(SHA256withRSA); topics are configured with ``SignatureVersion=2`` so the
SHA1-based version 1 never needs to be trusted. Verification checks:

* the signing certificate URL is HTTPS on an ``sns.<region>.amazonaws.com``
  host and the region matches the topic ARN;
* the certificate is within its validity period (injected clock);
* the RSA signature over the canonical string-to-sign;
* the topic is on the configured allow list;
* the message timestamp is recent (replay window).
"""

from __future__ import annotations

import base64
import re
from datetime import timedelta
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from self_healing_infrastructure_agents.domain.errors import (
    IntegrationUnavailableError,
    UnauthorizedError,
)
from self_healing_infrastructure_agents.domain.ports import Clock

_SNS_HOST = re.compile(r"^sns\.(?P<region>[a-z0-9-]+)\.amazonaws\.com(\.cn)?$")
_TOPIC_ARN = re.compile(r"^arn:aws(-cn|-us-gov)?:sns:(?P<region>[a-z0-9-]+):\d{12}:[\w-]{1,256}$")

_NOTIFICATION_FIELDS = ("Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type")
_CONFIRMATION_FIELDS = (
    "Message",
    "MessageId",
    "SubscribeURL",
    "Timestamp",
    "Token",
    "TopicArn",
    "Type",
)


class SnsEnvelope(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    type: Literal["Notification", "SubscriptionConfirmation", "UnsubscribeConfirmation"] = Field(
        alias="Type"
    )
    message_id: str = Field(alias="MessageId", max_length=100)
    topic_arn: str = Field(alias="TopicArn", max_length=300)
    subject: str | None = Field(default=None, alias="Subject", max_length=100)
    message: str = Field(alias="Message", max_length=262_144)
    timestamp: AwareDatetime = Field(alias="Timestamp")
    signature_version: str = Field(alias="SignatureVersion")
    signature: str = Field(alias="Signature", max_length=2048)
    signing_cert_url: str = Field(alias="SigningCertURL", max_length=2048)
    subscribe_url: str | None = Field(default=None, alias="SubscribeURL", max_length=4096)
    token: str | None = Field(default=None, alias="Token", max_length=2048)
    # The exact timestamp string AWS signed; kept separately because datetime
    # round-tripping would change its formatting.
    raw_timestamp: str = Field(default="", exclude=True)

    def string_to_sign(self) -> bytes:
        values: dict[str, Any] = {
            "Message": self.message,
            "MessageId": self.message_id,
            "Subject": self.subject,
            "SubscribeURL": self.subscribe_url,
            "Timestamp": self.raw_timestamp,
            "Token": self.token,
            "TopicArn": self.topic_arn,
            "Type": self.type,
        }
        fields = _NOTIFICATION_FIELDS if self.type == "Notification" else _CONFIRMATION_FIELDS
        parts: list[str] = []
        for name in fields:
            value = values[name]
            if value is None:
                if name == "Subject":
                    continue  # optional for notifications
                raise UnauthorizedError(f"SNS message is missing {name}")
            parts.append(f"{name}\n{value}\n")
        return "".join(parts).encode()

    @classmethod
    def parse(cls, document: dict[str, Any]) -> SnsEnvelope:
        envelope = cls.model_validate(document)
        return envelope.model_copy(update={"raw_timestamp": str(document.get("Timestamp", ""))})


class SnsVerifier:
    def __init__(
        self,
        *,
        allowed_topics: frozenset[str],
        http: httpx.AsyncClient,
        clock: Clock,
        max_age: timedelta = timedelta(hours=1),
    ) -> None:
        self._allowed = allowed_topics
        self._http = http
        self._clock = clock
        self._max_age = max_age
        self._certs: dict[str, x509.Certificate] = {}

    @staticmethod
    def region_of_topic(topic_arn: str) -> str:
        match = _TOPIC_ARN.fullmatch(topic_arn)
        if match is None:
            raise UnauthorizedError("malformed SNS topic ARN")
        return match.group("region")

    @staticmethod
    def check_aws_url(url: str, *, region: str, require_pem: bool) -> None:
        parsed = urlparse(url)
        host = _SNS_HOST.fullmatch(parsed.hostname or "")
        if parsed.scheme != "https" or host is None or parsed.port not in (None, 443):
            raise UnauthorizedError("URL is not an HTTPS Amazon SNS endpoint")
        if host.group("region") != region:
            raise UnauthorizedError("SNS endpoint region does not match the topic")
        if parsed.username or parsed.password:
            raise UnauthorizedError("SNS URL must not carry credentials")
        if require_pem and not parsed.path.endswith(".pem"):
            raise UnauthorizedError("signing certificate URL must reference a .pem file")

    async def _certificate(self, url: str) -> x509.Certificate:
        cached = self._certs.get(url)
        if cached is not None:
            return cached
        try:
            response = await self._http.get(url)
            response.raise_for_status()
            certificate = x509.load_pem_x509_certificate(response.content)
        except (httpx.HTTPError, ValueError) as exc:
            raise UnauthorizedError("cannot obtain the SNS signing certificate") from exc
        self._certs[url] = certificate
        return certificate

    async def verify(self, envelope: SnsEnvelope) -> None:
        if envelope.topic_arn not in self._allowed:
            raise UnauthorizedError("SNS topic is not on the allow list")
        if envelope.signature_version != "2":
            raise UnauthorizedError("only SNS SignatureVersion 2 (SHA256) is accepted")
        region = self.region_of_topic(envelope.topic_arn)
        self.check_aws_url(envelope.signing_cert_url, region=region, require_pem=True)

        now = self._clock.now()
        if abs(now - envelope.timestamp) > self._max_age:
            raise UnauthorizedError("SNS message timestamp outside the replay window")

        certificate = await self._certificate(envelope.signing_cert_url)
        if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
            raise UnauthorizedError("SNS signing certificate is not currently valid")
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise UnauthorizedError("SNS signing certificate does not hold an RSA key")
        try:
            signature = base64.b64decode(envelope.signature, validate=True)
            public_key.verify(
                signature, envelope.string_to_sign(), padding.PKCS1v15(), hashes.SHA256()
            )
        except (InvalidSignature, ValueError) as exc:
            raise UnauthorizedError("SNS signature verification failed") from exc

    async def confirm_subscription(self, envelope: SnsEnvelope) -> None:
        """Visit SubscribeURL after the envelope itself has been verified."""
        if envelope.subscribe_url is None:
            raise UnauthorizedError("subscription confirmation without SubscribeURL")
        region = self.region_of_topic(envelope.topic_arn)
        self.check_aws_url(envelope.subscribe_url, region=region, require_pem=False)
        try:
            response = await self._http.get(envelope.subscribe_url)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise IntegrationUnavailableError("SNS subscription confirmation failed") from exc
