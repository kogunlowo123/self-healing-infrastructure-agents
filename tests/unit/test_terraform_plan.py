"""Terraform plan analysis against recorded `terraform show -json` documents."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from agentic_core.domain.classification import RiskLevel

from self_healing_infrastructure_agents.analysis.terraform_plan import (
    STATEFUL_TYPES,
    DependencyGraph,
    analyze_plan,
    build_graph,
    config_address,
)
from self_healing_infrastructure_agents.domain.errors import InvalidPlanError
from self_healing_infrastructure_agents.domain.models import ChangeAction
from tests.conftest import load


def minimal(changes: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.7.5",
        "resource_changes": changes,
        **extra,
    }


def change(address: str, rtype: str, actions: list[str], **fields: Any) -> dict[str, Any]:
    return {
        "address": address,
        "type": rtype,
        "mode": "managed",
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {"actions": actions, **fields},
    }


class TestRecordedPlans:
    def test_terraform_data_resize_is_low_risk(self) -> None:
        analysis = analyze_plan(load("terraform/terraform-data-resize.plan.json"))
        assert analysis.terraform_version == "1.7.5"
        assert analysis.counts["update"] == 2
        assert analysis.counts["no-op"] == 2
        assert analysis.destructive == ()
        assert analysis.risk is RiskLevel.LOW
        # The module consumes the database id: it is in the blast radius though unchanged.
        assert "module.network.terraform_data.route" in analysis.blast_radius
        assert analysis.applyable

    def test_terraform_data_replace_reports_destruction(self) -> None:
        analysis = analyze_plan(load("terraform/terraform-data-replace.plan.json"))
        assert set(analysis.destructive) == {"terraform_data.database", "terraform_data.legacy"}
        database = next(c for c in analysis.changes if c.address == "terraform_data.database")
        assert database.action is ChangeAction.REPLACE
        assert database.replace_paths == ("triggers_replace",)
        assert analysis.stateful_deletes == ()
        assert analysis.risk is RiskLevel.HIGH

    def test_aws_storage_resize(self) -> None:
        analysis = analyze_plan(load("terraform/aws-rds-storage-resize.plan.json"))
        db = next(c for c in analysis.changes if c.address == "aws_db_instance.orders")
        assert db.stateful
        assert db.action is ChangeAction.UPDATE
        assert db.changed_attributes == ("allocated_storage",)
        assert analysis.stateful_deletes == ()
        assert analysis.risk is RiskLevel.LOW
        assert analysis.plan_digest.startswith("sha256:")

    def test_aws_replace_and_delete_is_critical(self) -> None:
        analysis = analyze_plan(load("terraform/aws-rds-replace-and-bucket-delete.plan.json"))
        assert analysis.stateful_deletes == ("aws_s3_bucket.exports",)
        assert analysis.stateful_replacements == ("aws_db_instance.orders",)
        assert analysis.risk is RiskLevel.CRITICAL
        assert analysis.risk_score == 100
        assert any("stateful resource deleted" in f for f in analysis.findings)

    def test_protection_disabled(self) -> None:
        analysis = analyze_plan(load("terraform/aws-rds-protection-disabled.plan.json"))
        assert analysis.protection_disabled == (
            "aws_db_instance.orders.deletion_protection",
            "aws_db_instance.orders.skip_final_snapshot",
        )
        assert analysis.risk is RiskLevel.HIGH

    def test_digest_changes_with_content(self) -> None:
        plan = load("terraform/aws-rds-storage-resize.plan.json")
        first = analyze_plan(plan).plan_digest
        mutated = copy.deepcopy(plan)
        mutated["resource_changes"][0]["change"]["after"] = {"tampered": True}
        assert analyze_plan(mutated).plan_digest != first
        assert analyze_plan(copy.deepcopy(plan)).plan_digest == first


class TestRules:
    def test_security_sensitive_and_creates(self) -> None:
        analysis = analyze_plan(
            minimal(
                [
                    change(
                        "aws_iam_role_policy.x",
                        "aws_iam_role_policy",
                        ["update"],
                        before={"policy": "a"},
                        after={"policy": "b"},
                    ),
                    change("aws_instance.a", "aws_instance", ["create"]),
                    change("aws_instance.b", "aws_instance", ["no-op"]),
                    {
                        "address": "data.aws_ami.x",
                        "type": "aws_ami",
                        "mode": "data",
                        "change": {"actions": ["read"]},
                    },
                ]
            )
        )
        assert analysis.security_changes == ("aws_iam_role_policy.x",)
        assert analysis.counts["create"] == 1
        assert all(c.address != "data.aws_ami.x" for c in analysis.changes)
        assert analysis.risk is RiskLevel.MODERATE

    @pytest.mark.parametrize(
        ("attribute", "before", "after", "flagged"),
        [
            ("force_destroy", False, True, True),
            ("backup_retention_period", 7, 0, True),
            ("publicly_accessible", False, True, True),
            ("storage_encrypted", True, False, True),
            ("deletion_protection", False, False, False),
            ("backup_retention_period", 7, 14, False),
        ],
    )
    def test_protection_predicates(
        self, attribute: str, before: Any, after: Any, flagged: bool
    ) -> None:
        analysis = analyze_plan(
            minimal(
                [
                    change(
                        "aws_db_instance.a",
                        "aws_db_instance",
                        ["update"],
                        before={attribute: before},
                        after={attribute: after},
                    )
                ]
            )
        )
        assert bool(analysis.protection_disabled) is flagged

    def test_unknown_values_count_as_changed(self) -> None:
        analysis = analyze_plan(
            minimal(
                [
                    change(
                        "aws_instance.a",
                        "aws_instance",
                        ["update"],
                        before={"ami": "x"},
                        after={"ami": "x"},
                        after_unknown={"arn": True},
                    )
                ]
            )
        )
        assert analysis.changes[0].changed_attributes == ("arn",)

    def test_errored_plan_is_not_applyable(self) -> None:
        analysis = analyze_plan(minimal([], errored=True))
        assert analysis.errored
        assert not analysis.applyable
        assert analysis.risk_score == 100
        assert "plan errored" in analysis.findings[0]

    def test_drift_is_reported(self) -> None:
        analysis = analyze_plan(
            minimal([], resource_drift=[{"address": "aws_instance.a"}, {"bogus": True}])
        )
        assert analysis.drifted == ("aws_instance.a",)
        assert "drifted" in analysis.findings[-1]

    def test_forget_is_a_no_op(self) -> None:
        analysis = analyze_plan(minimal([change("aws_instance.a", "aws_instance", ["forget"])]))
        assert analysis.changes[0].action is ChangeAction.NO_OP


class TestInvalidDocuments:
    @pytest.mark.parametrize(
        "document",
        [
            [],
            {"format_version": "0.2"},
            {"format_version": 1},
            minimal("x"),  # type: ignore[arg-type]
            minimal([{"address": "a"}]),
            minimal([{"change": {"actions": ["update"]}, "address": 3, "type": "t"}]),
            minimal([{"change": {"actions": "update"}, "address": "a.b", "type": "t"}]),
            minimal([change("a.b", "t", ["delete", "update"])]),
            minimal([change("a.b", "t", ["update"], replace_paths=7)]),
        ],
    )
    def test_rejected(self, document: Any) -> None:
        with pytest.raises(InvalidPlanError):
            analyze_plan(document)

    def test_size_limit(self) -> None:
        many = [change(f"aws_instance.i{i}", "aws_instance", ["no-op"]) for i in range(10_001)]
        with pytest.raises(InvalidPlanError, match="more than"):
            analyze_plan(minimal(many))


class TestDependencyGraph:
    def test_config_address_strips_instance_keys(self) -> None:
        assert config_address('module.a["x"].aws_s3_bucket.b[0]') == "module.a.aws_s3_bucket.b"

    def test_references_depends_on_and_modules(self) -> None:
        plan = {
            "configuration": {
                "root_module": {
                    "resources": [
                        {"address": "aws_db_instance.db", "expressions": {}},
                        {
                            "address": "aws_lambda_function.fn",
                            "expressions": {
                                "environment": [
                                    {
                                        "variables": {
                                            "references": [
                                                "aws_db_instance.db.address",
                                                "aws_db_instance.db",
                                                "var.x",
                                            ]
                                        }
                                    }
                                ]
                            },
                        },
                        {
                            "address": "aws_cloudwatch_dashboard.d",
                            "depends_on": ["module.app"],
                            "expressions": {},
                        },
                        {
                            "address": "aws_route53_record.r",
                            "expressions": {"records": {"references": ["data.aws_lb.x.dns_name"]}},
                        },
                    ],
                    "module_calls": {
                        "app": {
                            "expressions": {"fn": {"references": ["aws_lambda_function.fn.arn"]}},
                            "module": {
                                "resources": [{"address": "aws_sqs_queue.q", "expressions": {}}],
                                "module_calls": {
                                    "inner": {
                                        "module": {
                                            "resources": [
                                                {"address": "aws_sns_topic.t", "expressions": {}}
                                            ]
                                        }
                                    }
                                },
                            },
                        }
                    },
                }
            },
            "prior_state": {
                "values": {
                    "root_module": {
                        "resources": [
                            {"address": "aws_iam_role.r[0]", "depends_on": ["aws_db_instance.db"]}
                        ],
                        "child_modules": [
                            {
                                "resources": [
                                    {
                                        "address": "module.app.aws_sqs_queue.q",
                                        "depends_on": ["aws_kms_key.k"],
                                    }
                                ]
                            }
                        ],
                    }
                }
            },
        }
        graph = build_graph(plan)
        radius = graph.blast_radius({"aws_db_instance.db"})
        assert {
            "aws_db_instance.db",
            "aws_lambda_function.fn",
            "module.app.aws_sqs_queue.q",
            "module.app.module.inner.aws_sns_topic.t",
            "aws_cloudwatch_dashboard.d",
            "aws_iam_role.r",
        } <= radius
        assert "aws_route53_record.r" not in radius
        assert "module.app.aws_sqs_queue.q" in graph.blast_radius({"aws_kms_key.k"})
        assert graph.blast_radius({"data.aws_lb.x"}) == {"data.aws_lb.x", "aws_route53_record.r"}

    def test_self_references_are_ignored(self) -> None:
        graph = DependencyGraph()
        graph.add("a.b", "a.b")
        assert graph.depends_on == {}

    def test_stateful_catalogue_covers_three_clouds(self) -> None:
        assert {
            "aws_db_instance",
            "azurerm_postgresql_flexible_server",
            "google_sql_database_instance",
        } <= STATEFUL_TYPES
