"""Risk analysis of ``terraform show -json <planfile>`` documents (plan format 1.x).

What it extracts:

* every resource change, normalised to one action (create, update, delete,
  replace, read, no-op) with the attributes that change;
* destructive changes (delete and replace) and, among them, changes to
  stateful resources (databases, volumes, buckets, keys, ...);
* changes that switch a safety attribute off (``deletion_protection``,
  ``skip_final_snapshot``, ``force_destroy``, ...);
* security-sensitive changes (IAM, network ACLs and firewalls, KMS, RBAC);
* drift Terraform detected in the refresh (``resource_drift``);
* the blast radius: changed resources plus every resource that depends on
  them, transitively, using references and ``depends_on`` from the plan's
  ``configuration`` block and the prior state;
* a 0-100 risk score and a risk tier.

The analysis is deterministic and side-effect free so it can run in CI,
behind the MCP tool, and again at apply time to prove the plan did not
change between review and execution.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from collections.abc import Iterable, Iterator
from typing import Any

from agentic_core.domain.classification import RiskLevel
from agentic_core.domain.provenance import canonical_json, content_digest

from self_healing_infrastructure_agents.domain.errors import InvalidPlanError
from self_healing_infrastructure_agents.domain.models import (
    ChangeAction,
    PlanAnalysis,
    ResourceChange,
)

MAX_RESOURCE_CHANGES = 10_000

# Resource types whose deletion or replacement loses data.
STATEFUL_TYPES = frozenset(
    {
        # AWS
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_rds_cluster_instance",
        "aws_dynamodb_table",
        "aws_s3_bucket",
        "aws_ebs_volume",
        "aws_efs_file_system",
        "aws_elasticache_cluster",
        "aws_elasticache_replication_group",
        "aws_docdb_cluster",
        "aws_neptune_cluster",
        "aws_redshift_cluster",
        "aws_opensearch_domain",
        "aws_elasticsearch_domain",
        "aws_kinesis_stream",
        "aws_msk_cluster",
        "aws_sqs_queue",
        "aws_kms_key",
        "aws_secretsmanager_secret",
        "aws_backup_vault",
        "aws_fsx_lustre_file_system",
        "aws_fsx_windows_file_system",
        # Azure
        "azurerm_postgresql_flexible_server",
        "azurerm_postgresql_flexible_server_database",
        "azurerm_mssql_server",
        "azurerm_mssql_database",
        "azurerm_mysql_flexible_server",
        "azurerm_cosmosdb_account",
        "azurerm_storage_account",
        "azurerm_storage_container",
        "azurerm_managed_disk",
        "azurerm_key_vault",
        "azurerm_redis_cache",
        "azurerm_servicebus_namespace",
        "azurerm_eventhub_namespace",
        # Google Cloud
        "google_sql_database_instance",
        "google_sql_database",
        "google_spanner_instance",
        "google_spanner_database",
        "google_bigtable_instance",
        "google_bigquery_dataset",
        "google_bigquery_table",
        "google_storage_bucket",
        "google_compute_disk",
        "google_filestore_instance",
        "google_redis_instance",
        "google_kms_crypto_key",
        "google_secret_manager_secret",
        "google_pubsub_topic",
        # Kubernetes provider
        "kubernetes_persistent_volume",
        "kubernetes_persistent_volume_claim",
        "kubernetes_stateful_set",
        "kubernetes_stateful_set_v1",
        "kubernetes_persistent_volume_claim_v1",
    }
)

_SECURITY_PATTERNS = tuple(
    re.compile(p)
    for p in (
        r"^aws_iam_",
        r"^aws_(vpc_)?security_group",
        r"^aws_network_acl",
        r"^aws_kms_",
        r"^aws_s3_bucket_(policy|public_access_block|acl)$",
        r"^aws_lb_listener",
        r"^aws_wafv2_",
        r"^azurerm_role_",
        r"^azurerm_network_security_",
        r"^azurerm_key_vault_access_policy$",
        r"^azurerm_firewall",
        r"^google_.*_iam_(member|binding|policy)$",
        r"^google_compute_firewall",
        r"^google_kms_",
        r"^kubernetes_(cluster_)?role",
        r"^kubernetes_network_policy",
    )
)

_FALSEY = (False, None, "false", 0)


def _turned_off(before: Any, after: Any) -> bool:
    return before is True and after in _FALSEY


def _turned_on(before: Any, after: Any) -> bool:
    return before in _FALSEY and after is True


def _zeroed(before: Any, after: Any) -> bool:
    return isinstance(before, int) and before > 0 and after == 0


# attribute -> predicate(before, after) that is true when safety is reduced
PROTECTION_ATTRIBUTES = {
    "deletion_protection": _turned_off,
    "deletion_protection_enabled": _turned_off,
    "enable_deletion_protection": _turned_off,
    "termination_protection": _turned_off,
    "disable_api_termination": _turned_off,
    "storage_encrypted": _turned_off,
    "encrypted": _turned_off,
    "point_in_time_recovery_enabled": _turned_off,
    "purge_protection_enabled": _turned_off,
    "versioning_enabled": _turned_off,
    "skip_final_snapshot": _turned_on,
    "force_destroy": _turned_on,
    "publicly_accessible": _turned_on,
    "public_network_access_enabled": _turned_on,
    "backup_retention_period": _zeroed,
    "backup_retention_days": _zeroed,
}

_INDEX = re.compile(r"\[[^\]]*\]")
_NON_RESOURCE_ROOTS = frozenset(
    {"var", "local", "each", "count", "path", "terraform", "self", "module"}
)


def config_address(address: str) -> str:
    """``module.a["x"].aws_s3_bucket.b[0]`` -> ``module.a.aws_s3_bucket.b``."""
    return _INDEX.sub("", address)


def _normalise_actions(actions: list[str]) -> ChangeAction:
    key = tuple(actions)
    mapping = {
        ("no-op",): ChangeAction.NO_OP,
        ("create",): ChangeAction.CREATE,
        ("read",): ChangeAction.READ,
        ("update",): ChangeAction.UPDATE,
        ("delete",): ChangeAction.DELETE,
        ("delete", "create"): ChangeAction.REPLACE,
        ("create", "delete"): ChangeAction.REPLACE,
        ("forget",): ChangeAction.NO_OP,
    }
    try:
        return mapping[key]
    except KeyError as exc:
        raise InvalidPlanError(f"unsupported change actions {list(actions)}") from exc


def _changed_attributes(change: dict[str, Any]) -> tuple[str, ...]:
    before = change.get("before") or {}
    after = change.get("after") or {}
    unknown = change.get("after_unknown") or {}
    if not isinstance(before, dict) or not isinstance(after, dict):
        return ()
    keys = set(before) | set(after) | (set(unknown) if isinstance(unknown, dict) else set())
    changed = {
        k
        for k in keys
        if before.get(k) != after.get(k)
        or (isinstance(unknown, dict) and unknown.get(k) not in (None, False, {}, []))
    }
    return tuple(sorted(changed))


def _protection_disabled(change: dict[str, Any]) -> tuple[str, ...]:
    before = change.get("before") or {}
    after = change.get("after") or {}
    if not isinstance(before, dict) or not isinstance(after, dict):
        return ()
    hits = [
        attribute
        for attribute, reduces_safety in PROTECTION_ATTRIBUTES.items()
        if attribute in after and reduces_safety(before.get(attribute), after.get(attribute))
    ]
    return tuple(sorted(hits))


def _references(node: Any) -> Iterator[str]:
    """Every string in any ``references`` list, at any depth of an expressions tree."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "references" and isinstance(value, list):
                yield from (r for r in value if isinstance(r, str))
            else:
                yield from _references(value)
    elif isinstance(node, list):
        for item in node:
            yield from _references(item)


def _referenced_address(reference: str, prefix: str) -> str | None:
    parts = reference.split(".")
    if parts[0] == "module" and len(parts) >= 2:
        return f"{prefix}module.{_INDEX.sub('', parts[1])}"
    if parts[0] in _NON_RESOURCE_ROOTS:
        return None
    if parts[0] == "data" and len(parts) >= 3:
        return prefix + _INDEX.sub("", ".".join(parts[:3]))
    if len(parts) >= 2:
        return prefix + _INDEX.sub("", ".".join(parts[:2]))
    return None


class DependencyGraph:
    """Resource dependency graph; edges point from a resource to what it depends on."""

    def __init__(self) -> None:
        self.depends_on: dict[str, set[str]] = defaultdict(set)
        self.modules: dict[str, set[str]] = defaultdict(set)  # "module.x" -> resources

    def add(self, resource: str, dependency: str) -> None:
        if resource != dependency:
            self.depends_on[resource].add(dependency)

    def members(self, address: str) -> set[str]:
        """Everything inside a module, including nested modules' resources."""
        return self._expand(address) - {address}

    def _expand(self, address: str) -> set[str]:
        """A module reference stands for every resource inside that module."""
        expanded = {address}
        if address in self.modules:
            for inner in self.modules[address]:
                expanded |= self._expand(inner) | {inner}
        return expanded

    def dependents(self) -> dict[str, set[str]]:
        reverse: dict[str, set[str]] = defaultdict(set)
        for resource, deps in self.depends_on.items():
            for dep in deps:
                for target in self._expand(dep):
                    reverse[target].add(resource)
        return reverse

    def blast_radius(self, changed: Iterable[str]) -> set[str]:
        reverse = self.dependents()
        seen = set(changed)
        queue = deque(seen)
        while queue:
            current = queue.popleft()
            for dependent in reverse.get(current, ()):
                if dependent not in seen:
                    seen.add(dependent)
                    queue.append(dependent)
        return seen


def _walk_config(module: dict[str, Any], prefix: str, graph: DependencyGraph) -> None:
    for resource in module.get("resources", []) or []:
        address = resource.get("address")
        if not isinstance(address, str):
            continue
        full = prefix + address
        if prefix:
            graph.modules[prefix.rstrip(".")].add(full)
        for reference in _references(resource.get("expressions", {})):
            target = _referenced_address(reference, prefix)
            if target:
                graph.add(full, target)
        for explicit in resource.get("depends_on", []) or []:
            target = _referenced_address(str(explicit), prefix)
            if target:
                graph.add(full, target)
    for name, call in (module.get("module_calls", {}) or {}).items():
        child_prefix = f"{prefix}module.{name}."
        # Inputs to the module make everything inside depend on what they reference.
        inputs = [
            target
            for reference in _references(call.get("expressions", {}))
            if (target := _referenced_address(reference, prefix))
        ]
        child = call.get("module", {}) or {}
        _walk_config(child, child_prefix, graph)
        for inner in graph.members(child_prefix.rstrip(".")):
            for target in inputs:
                graph.add(inner, target)
        if prefix:
            graph.modules[prefix.rstrip(".")].add(child_prefix.rstrip("."))


def _walk_state(module: dict[str, Any], graph: DependencyGraph) -> None:
    for resource in module.get("resources", []) or []:
        address = resource.get("address")
        if isinstance(address, str):
            for dep in resource.get("depends_on", []) or []:
                graph.add(config_address(address), config_address(str(dep)))
    for child in module.get("child_modules", []) or []:
        _walk_state(child, graph)


def build_graph(plan: dict[str, Any]) -> DependencyGraph:
    graph = DependencyGraph()
    root = (plan.get("configuration") or {}).get("root_module") or {}
    _walk_config(root, "", graph)
    state_root = ((plan.get("prior_state") or {}).get("values") or {}).get("root_module") or {}
    _walk_state(state_root, graph)
    return graph


def _is_security_sensitive(resource_type: str) -> bool:
    return any(p.search(resource_type) for p in _SECURITY_PATTERNS)


def _score(
    *,
    stateful_deletes: int,
    stateful_replacements: int,
    deletes: int,
    replacements: int,
    security: int,
    protection: int,
    updates: int,
    creates: int,
    blast_radius: int,
    errored: bool,
) -> int:
    if errored:
        return 100
    raw = (
        50 * stateful_deletes
        + 40 * stateful_replacements
        + 15 * deletes
        + 10 * replacements
        + 25 * protection
        + 10 * security
        + 2 * updates
        + 1 * creates
        + 2 * max(0, blast_radius - 1)
    )
    return min(100, raw)


def _tier(score: int) -> RiskLevel:
    if score >= 60:
        return RiskLevel.CRITICAL
    if score >= 30:
        return RiskLevel.HIGH
    if score >= 10:
        return RiskLevel.MODERATE
    return RiskLevel.LOW


def analyze_plan(plan: dict[str, Any]) -> PlanAnalysis:
    """Analyse a plan document; any structural surprise is reported as an invalid plan."""
    try:
        return _analyze(plan)
    except InvalidPlanError:
        raise
    except (TypeError, AttributeError, ValueError, KeyError) as exc:
        raise InvalidPlanError(f"malformed plan document: {type(exc).__name__}") from exc


def _analyze(plan: dict[str, Any]) -> PlanAnalysis:
    if not isinstance(plan, dict):
        raise InvalidPlanError("plan document must be a JSON object")
    format_version = plan.get("format_version")
    if not isinstance(format_version, str) or not format_version.startswith("1."):
        raise InvalidPlanError("unsupported plan format_version; expected 1.x")
    raw_changes = plan.get("resource_changes", [])
    if not isinstance(raw_changes, list):
        raise InvalidPlanError("resource_changes must be a list")
    if len(raw_changes) > MAX_RESOURCE_CHANGES:
        raise InvalidPlanError(f"plan has more than {MAX_RESOURCE_CHANGES} resource changes")

    changes = [c for c in (_resource_change(item) for item in raw_changes) if c is not None]
    return _summarise(plan, format_version, changes)


def _resource_change(item: Any) -> ResourceChange | None:
    """One ``resource_changes`` entry; data sources yield None."""
    if not isinstance(item, dict) or not isinstance(item.get("change"), dict):
        raise InvalidPlanError("resource change entries need an object 'change'")
    if item.get("mode", "managed") != "managed":
        return None  # data sources are read, never changed
    address, rtype = item.get("address"), item.get("type")
    if not isinstance(address, str) or not isinstance(rtype, str):
        raise InvalidPlanError("resource change entries need address and type")
    change = item["change"]
    actions = change.get("actions")
    if not isinstance(actions, list):
        raise InvalidPlanError(f"{address}: change.actions must be a list")
    action = _normalise_actions(actions)
    replace_paths = tuple(
        ".".join(str(p) for p in path)
        for path in change.get("replace_paths", []) or []
        if isinstance(path, list)
    )
    return ResourceChange(
        address=address,
        type=rtype,
        provider=str(item.get("provider_name", "")),
        action=action,
        stateful=rtype in STATEFUL_TYPES,
        security_sensitive=_is_security_sensitive(rtype),
        changed_attributes=(
            _changed_attributes(change)
            if action in {ChangeAction.UPDATE, ChangeAction.REPLACE}
            else ()
        ),
        replace_paths=replace_paths,
        protection_disabled=(_protection_disabled(change) if action is ChangeAction.UPDATE else ()),
    )


def _summarise(
    plan: dict[str, Any], format_version: str, changes: list[ResourceChange]
) -> PlanAnalysis:
    effective = [c for c in changes if c.action not in {ChangeAction.NO_OP, ChangeAction.READ}]
    counts = {a.value: 0 for a in ChangeAction}
    for c in changes:
        counts[c.action.value] += 1

    deletes = [c for c in effective if c.action is ChangeAction.DELETE]
    replaces = [c for c in effective if c.action is ChangeAction.REPLACE]
    stateful_deletes = [c.address for c in deletes if c.stateful]
    stateful_replacements = [c.address for c in replaces if c.stateful]
    security = [c.address for c in effective if c.security_sensitive]
    protection = [f"{c.address}.{attr}" for c in effective for attr in c.protection_disabled]
    drifted = sorted(
        str(d.get("address"))
        for d in plan.get("resource_drift", []) or []
        if isinstance(d, dict) and d.get("address")
    )

    graph = build_graph(plan)
    changed_config = {config_address(c.address) for c in effective}
    blast = sorted(graph.blast_radius(changed_config)) if changed_config else []

    errored = bool(plan.get("errored", False))
    applyable = bool(plan.get("applyable", not errored)) and not errored
    score = _score(
        stateful_deletes=len(stateful_deletes),
        stateful_replacements=len(stateful_replacements),
        deletes=len(deletes),
        replacements=len(replaces),
        security=len(security),
        protection=len(protection),
        updates=counts[ChangeAction.UPDATE.value],
        creates=counts[ChangeAction.CREATE.value],
        blast_radius=len(blast),
        errored=errored,
    )

    findings: list[str] = []
    if errored:
        findings.append("plan errored; it cannot be applied")
    findings.extend(f"stateful resource deleted: {a}" for a in stateful_deletes)
    findings.extend(f"stateful resource replaced: {a}" for a in stateful_replacements)
    findings.extend(
        f"resource deleted: {c.address}" for c in deletes if c.address not in stateful_deletes
    )
    findings.extend(
        f"resource replaced ({', '.join(c.replace_paths) or 'provider decision'}): {c.address}"
        for c in replaces
        if c.address not in stateful_replacements
    )
    findings.extend(f"safety attribute switched off: {p}" for p in protection)
    findings.extend(f"security-sensitive change: {a}" for a in security)
    if drifted:
        findings.append(f"{len(drifted)} resources drifted outside Terraform")
    if len(blast) > len(changed_config):
        findings.append(
            f"blast radius {len(blast)} resources ({len(blast) - len(changed_config)} dependents)"
        )

    return PlanAnalysis(
        plan_digest=content_digest(canonical_json(plan)),
        format_version=format_version,
        terraform_version=str(plan.get("terraform_version", "unknown")),
        applyable=applyable,
        errored=errored,
        changes=tuple(changes),
        counts=counts,
        destructive=tuple(c.address for c in (*deletes, *replaces)),
        stateful_deletes=tuple(stateful_deletes),
        stateful_replacements=tuple(stateful_replacements),
        security_changes=tuple(security),
        protection_disabled=tuple(protection),
        drifted=tuple(drifted),
        blast_radius=tuple(blast),
        risk_score=score,
        risk=_tier(score),
        findings=tuple(findings),
    )
