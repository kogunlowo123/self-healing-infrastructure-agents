"""Forged, replayed and spoofed alert notifications are rejected (threat model T1-T4)."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from self_healing_infrastructure_agents.api.app import create_app
from self_healing_infrastructure_agents.domain.errors import UnauthorizedError
from self_healing_infrastructure_agents.runtime.container import Container
from self_healing_infrastructure_agents.security.sns import SnsEnvelope, SnsVerifier
from tests.conftest import (
    ALERTMANAGER_TOKEN,
    PUBLIC_URL,
    TOPIC_ARN,
    FakeClock,
    FakeCluster,
    FakeIdp,
    FakeTerraform,
    load,
    make_settings,
    wired,
)
from tests.security.conftest import CERT_URL, SnsSigner

pytestmark = pytest.mark.security

ALARM = json.dumps(load("alerts/cloudwatch-rds-storage.json"))


@pytest.fixture
def sns_client(
    tmp_path: Path,
    cluster: FakeCluster,
    terraform: FakeTerraform,
    clock: FakeClock,
    operator_idp: FakeIdp,
    agent_idp: FakeIdp,
    sns_signer: SnsSigner,
) -> Iterator[TestClient]:
    async def factory() -> Container:
        return await wired(
            make_settings(tmp_path),
            cluster=cluster,
            terraform=terraform,
            clock=clock,
            operator_idp=operator_idp,
            agent_idp=agent_idp,
            http=httpx.AsyncClient(transport=sns_signer.transport()),
        )

    with TestClient(create_app(factory), base_url=PUBLIC_URL) as client:
        yield client


def post(client: TestClient, document: dict[str, object]) -> httpx.Response:
    return client.post(
        "/v1/alerts/cloudwatch",
        content=json.dumps(document),
        headers={
            "Content-Type": "text/plain; charset=UTF-8",
            "x-amz-sns-message-type": str(document.get("Type")),
        },
    )


class TestCloudWatchSns:
    def test_signed_alarm_is_ingested(self, sns_client: TestClient, sns_signer: SnsSigner) -> None:
        response = post(sns_client, sns_signer.envelope(ALARM))
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "accepted"
        assert len(response.json()["opened"]) == 1

    def test_subscription_confirmation_visits_aws_only(
        self, sns_client: TestClient, sns_signer: SnsSigner
    ) -> None:
        subscribe = "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=abc"
        response = post(
            sns_client,
            sns_signer.envelope(
                "You have chosen to subscribe",
                kind="SubscriptionConfirmation",
                SubscribeURL=subscribe,
                Token="abc",
            ),
        )
        assert response.json()["status"] == "subscribed"
        assert sns_signer.confirmations == [subscribe]
        evil = post(
            sns_client,
            sns_signer.envelope(
                "x",
                kind="SubscriptionConfirmation",
                SubscribeURL="https://attacker.test/?Action=ConfirmSubscription",
                Token="abc",
            ),
        )
        assert evil.status_code == 401
        unsub = post(
            sns_client,
            sns_signer.envelope(
                "bye", kind="UnsubscribeConfirmation", SubscribeURL=subscribe, Token="abc"
            ),
        )
        assert unsub.json()["status"] == "unsubscribed"

    def test_tampered_message_rejected(self, sns_client: TestClient, sns_signer: SnsSigner) -> None:
        document = sns_signer.envelope(ALARM)
        document["Message"] = document["Message"].replace("ALARM", "OK")
        assert post(sns_client, document).status_code == 401

    def test_signature_from_another_key_rejected(
        self, sns_client: TestClient, sns_signer: SnsSigner
    ) -> None:
        forged = SnsSigner().envelope(ALARM)  # different private key, same cert URL
        assert post(sns_client, forged).status_code == 401

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("cert_url", "https://sns.us-east-1.amazonaws.com.attacker.test/cert.pem"),
            ("cert_url", "http://sns.us-east-1.amazonaws.com/cert.pem"),
            ("cert_url", "https://sns.eu-west-1.amazonaws.com/cert.pem"),
            ("cert_url", "https://sns.us-east-1.amazonaws.com/cert.txt"),
            ("cert_url", "https://user:pw@sns.us-east-1.amazonaws.com/cert.pem"),
            ("topic", "arn:aws:sns:us-east-1:123456789012:someone-elses-topic"),
            ("timestamp", "2026-10-14T10:00:00.000Z"),
            ("version", "1"),
        ],
    )
    def test_spoofing_and_replay(
        self, sns_client: TestClient, sns_signer: SnsSigner, field: str, value: str
    ) -> None:
        document = sns_signer.envelope(ALARM, **{field: value})
        response = post(sns_client, document)
        assert response.status_code == 401, response.text
        assert response.headers["www-authenticate"] == "Bearer"

    def test_malformed_bodies(self, sns_client: TestClient) -> None:
        assert sns_client.post("/v1/alerts/cloudwatch", content=b"[1]").status_code == 400
        assert sns_client.post("/v1/alerts/cloudwatch", content=b"{").status_code == 400
        assert sns_client.post("/v1/alerts/cloudwatch", json={"Type": "x"}).status_code == 400
        big = b"{" + b" " * (1024 * 1024 + 1) + b"}"
        assert sns_client.post("/v1/alerts/cloudwatch", content=big).status_code == 400

    def test_signed_but_not_an_alarm(self, sns_client: TestClient, sns_signer: SnsSigner) -> None:
        response = post(sns_client, sns_signer.envelope("hello"))
        assert response.status_code == 400
        insufficient = json.loads(ALARM)
        insufficient["NewStateValue"] = "INSUFFICIENT_DATA"
        ignored = post(sns_client, sns_signer.envelope(json.dumps(insufficient)))
        assert ignored.json()["status"] == "ignored"


class TestVerifierDirect:
    async def test_bad_certificate_document(self, sns_signer: SnsSigner) -> None:
        bad = httpx.MockTransport(lambda _: httpx.Response(200, content=b"not a certificate"))
        verifier = SnsVerifier(
            allowed_topics=frozenset({TOPIC_ARN}),
            http=httpx.AsyncClient(transport=bad),
            clock=FakeClock(),
        )
        envelope = SnsEnvelope.parse(sns_signer.envelope(ALARM))
        with pytest.raises(UnauthorizedError, match="cannot obtain"):
            await verifier.verify(envelope)

    async def test_expired_certificate(self, sns_signer: SnsSigner) -> None:
        later = FakeClock()
        later.advance(400 * 86400)
        verifier = SnsVerifier(
            allowed_topics=frozenset({TOPIC_ARN}),
            http=httpx.AsyncClient(transport=sns_signer.transport()),
            clock=later,
        )
        document = sns_signer.envelope(ALARM, timestamp=later.now().isoformat())
        with pytest.raises(UnauthorizedError, match="not currently valid"):
            await verifier.verify(SnsEnvelope.parse(document))

    async def test_non_rsa_certificate_and_bad_base64(self, sns_signer: SnsSigner) -> None:
        verifier = SnsVerifier(
            allowed_topics=frozenset({TOPIC_ARN}),
            http=httpx.AsyncClient(transport=sns_signer.transport()),
            clock=FakeClock(),
        )
        document = sns_signer.envelope(ALARM)
        document["Signature"] = "!!!" + base64.b64encode(b"x").decode()
        with pytest.raises(UnauthorizedError, match="verification failed"):
            await verifier.verify(SnsEnvelope.parse(document))

    def test_missing_fields_and_bad_arn(self) -> None:
        envelope = SnsEnvelope.parse(
            {
                "Type": "SubscriptionConfirmation",
                "MessageId": "m",
                "TopicArn": TOPIC_ARN,
                "Message": "x",
                "Timestamp": "2026-10-14T13:56:03.123Z",
                "SignatureVersion": "2",
                "Signature": "x",
                "SigningCertURL": CERT_URL,
            }
        )
        with pytest.raises(UnauthorizedError, match="missing SubscribeURL"):
            envelope.string_to_sign()
        with pytest.raises(UnauthorizedError, match="malformed"):
            SnsVerifier.region_of_topic("arn:aws:s3:::bucket")

    async def test_confirmation_without_url_and_failure(self, sns_signer: SnsSigner) -> None:
        from self_healing_infrastructure_agents.domain.errors import IntegrationUnavailableError

        down = httpx.MockTransport(lambda _: httpx.Response(500))
        verifier = SnsVerifier(
            allowed_topics=frozenset({TOPIC_ARN}),
            http=httpx.AsyncClient(transport=down),
            clock=FakeClock(),
        )
        no_url = SnsEnvelope.parse(sns_signer.envelope("x"))
        with pytest.raises(UnauthorizedError, match="without SubscribeURL"):
            await verifier.confirm_subscription(no_url)
        with_url = SnsEnvelope.parse(
            sns_signer.envelope(
                "x",
                kind="SubscriptionConfirmation",
                Token="t",
                SubscribeURL="https://sns.us-east-1.amazonaws.com/?a=b",
            )
        )
        with pytest.raises(IntegrationUnavailableError):
            await verifier.confirm_subscription(with_url)


class TestAlertmanagerWebhook:
    def test_credential_required(self, client: TestClient) -> None:
        body = load("alerts/alertmanager-crashloop.json")
        assert client.post("/v1/alerts/alertmanager", json=body).status_code == 401
        wrong = client.post(
            "/v1/alerts/alertmanager", json=body, headers={"Authorization": "Bearer guessed"}
        )
        assert wrong.status_code == 401
        ok = client.post(
            "/v1/alerts/alertmanager",
            json=body,
            headers={"Authorization": f"Bearer {ALERTMANAGER_TOKEN}"},
        )
        assert ok.status_code == 202

    def test_invalid_payload(self, client: TestClient) -> None:
        response = client.post(
            "/v1/alerts/alertmanager",
            json={"version": "4"},
            headers={"Authorization": f"Bearer {ALERTMANAGER_TOKEN}"},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_disabled_when_unconfigured(
        self,
        tmp_path: Path,
        cluster: FakeCluster,
        terraform: FakeTerraform,
        clock: FakeClock,
        operator_idp: FakeIdp,
        agent_idp: FakeIdp,
    ) -> None:
        async def factory() -> Container:
            return await wired(
                make_settings(tmp_path, alertmanager_token=None),
                cluster=cluster,
                terraform=terraform,
                clock=clock,
                operator_idp=operator_idp,
                agent_idp=agent_idp,
            )

        with TestClient(create_app(factory), base_url=PUBLIC_URL) as client:
            response = client.post(
                "/v1/alerts/alertmanager",
                json={},
                headers={"Authorization": f"Bearer {ALERTMANAGER_TOKEN}"},
            )
            assert response.status_code == 404
