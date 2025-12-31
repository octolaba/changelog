#!/usr/bin/env python3
"""Validate the frozen pilot inventory and contract fixtures with stdlib only.

This is a specification verifier, not the future application.  It deliberately
implements the semantic and RFC 3339 checks that JSON Schema alone cannot make
relational, and that basic jsonschema installations may treat as annotations.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from copy import deepcopy
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
errors: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def load(name: str) -> dict:
    with (ROOT / name).open(encoding="utf-8") as handle:
        return json.load(handle)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def valid_datetime(value: object) -> bool:
    """Strict RFC 3339 assertion equivalent for the two schema date-time fields."""
    if not isinstance(value, str) or not RFC3339_UTC.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def update_key(update: dict) -> tuple[str, str, str]:
    return (update.get("repository", ""), update.get("manifest", ""), update.get("module", ""))


def item_key(item: dict) -> tuple[str, str, str]:
    consumer = item.get("consumer", {})
    return (consumer.get("repository", ""), consumer.get("manifest", ""), item.get("to", {}).get("declared", {}).get("module", ""))


def add_issue(issues: list[tuple[str, str]], condition: bool, code: str, message: str) -> None:
    if not condition:
        issues.append((code, message))


def validate_signal(signal: dict, trusted_authoritative_updates: object, label: str) -> list[tuple[str, str]]:
    """Validate one submitted signal against a separate server-captured update set.

    trusted_authoritative_updates is deliberately not read from signal.  Missing
    authority therefore fails closed instead of shrinking to client items or
    coverage.expectedUpdates.
    """
    issues: list[tuple[str, str]] = []
    require = lambda condition, code, message: add_issue(issues, condition, code, f"{label}: {message}")
    required = {"schemaVersion", "reviewId", "recordedAt", "actor", "generation", "idempotencyKey", "pullRequest", "items"}
    require(isinstance(signal, dict) and set(signal) == required, "INVALID_SIGNAL", "envelope fields differ from schema")
    if not isinstance(signal, dict):
        return issues
    require(signal.get("schemaVersion") == "1.0.0", "INVALID_SIGNAL", "schemaVersion")
    require(bool(UUID.fullmatch(signal.get("reviewId", ""))), "INVALID_SIGNAL", "reviewId")
    require(valid_datetime(signal.get("recordedAt")), "INVALID_TIMESTAMP", "invalid recordedAt timestamp")
    require(isinstance(signal.get("generation"), int) and signal.get("generation", 0) >= 1, "INVALID_SIGNAL", "generation")
    require(isinstance(signal.get("idempotencyKey"), str) and len(signal.get("idempotencyKey", "")) >= 8, "INVALID_SIGNAL", "idempotencyKey")

    authority_is_available = isinstance(trusted_authoritative_updates, list) and bool(trusted_authoritative_updates)
    require(authority_is_available, "INCOMPLETE_COVERAGE", "trusted authoritative update set is missing")
    authoritative_rows = trusted_authoritative_updates if authority_is_available else []
    authoritative_keys = {update_key(update) for update in authoritative_rows if isinstance(update, dict)}
    require(
        len(authoritative_keys) == len(authoritative_rows)
        and all(isinstance(update, dict) and set(update) == {"repository", "manifest", "module"} for update in authoritative_rows),
        "INCOMPLETE_COVERAGE",
        "trusted authoritative update set is malformed or contains duplicates",
    )

    items = signal.get("items", [])
    require(isinstance(items, list) and bool(items), "INVALID_SIGNAL", "empty or malformed items")
    items = items if isinstance(items, list) else []
    item_ids = [item.get("itemId") for item in items if isinstance(item, dict)]
    require(len(item_ids) == len(items) and len(set(item_ids)) == len(items), "DUPLICATE_ITEM_ID", "duplicate itemId")
    semantic_key_list = [item_key(item) for item in items if isinstance(item, dict)]
    semantic_keys = set(semantic_key_list)
    require(len(semantic_key_list) == len(items) and len(semantic_keys) == len(items), "DUPLICATE_SEMANTIC_IDENTITY", "duplicate semantic item identity")
    require(semantic_keys == authoritative_keys, "INCOMPLETE_COVERAGE", "submitted manifest-specific item set differs from trusted authority")
    expected_group: set[tuple[str, str, str]] | None = None
    for index, item in enumerate(items):
        item_label = f"{label}.items[{index}]"
        if not isinstance(item, dict):
            issues.append(("INVALID_SIGNAL", f"{item_label}: item is not an object"))
            continue
        item_require = lambda condition, code, message: add_issue(issues, condition, code, f"{item_label}: {message}")
        required_item = {"itemId", "decision", "reason", "consumer", "from", "to", "analysis", "coverage"}
        item_require(set(item) == required_item, "INVALID_SIGNAL", "fields differ from schema")
        item_require(item.get("decision") in {"accept", "decline"}, "INVALID_SIGNAL", "decision")
        item_require(item.get("reason") is None or isinstance(item.get("reason"), str), "INVALID_SIGNAL", "reason")
        consumer = item.get("consumer", {})
        item_require(isinstance(consumer, dict) and consumer.get("manifest") in {"go.mod", "tools/go.mod"}, "INVALID_SIGNAL", "manifest")
        item_require(bool(HEX40.fullmatch(consumer.get("commit", ""))), "INVALID_SIGNAL", "consumer commit")
        item_require(bool(HEX64.fullmatch(consumer.get("manifestSha256", ""))), "INVALID_SIGNAL", "manifest hash")
        for side in ("from", "to"):
            endpoint = item.get(side, {})
            item_require(isinstance(endpoint, dict) and set(endpoint) == {"declared", "effective"}, "INVALID_SIGNAL", f"{side} identities")
            for identity in ("declared", "effective"):
                value = endpoint.get(identity, {})
                item_require(isinstance(value, dict) and set(value) == {"module", "version", "revision"}, "INVALID_SIGNAL", f"{side}.{identity} fields")
                item_require(str(value.get("version", "")).startswith("v"), "INVALID_SIGNAL", f"{side}.{identity} version")
                item_require(bool(HEX40.fullmatch(value.get("revision", ""))), "INVALID_SIGNAL", f"{side}.{identity} revision")
        analysis = item.get("analysis", {})
        item_require(isinstance(analysis, dict) and str(analysis.get("path", "")).startswith("results/"), "INVALID_SIGNAL", "analysis path")
        item_require(bool(HEX40.fullmatch(analysis.get("revision", ""))), "INVALID_SIGNAL", "analysis revision")
        item_require(bool(HEX64.fullmatch(analysis.get("sha256", ""))), "INVALID_SIGNAL", "analysis hash")
        item_require(valid_datetime(analysis.get("cutoff")), "INVALID_TIMESTAMP", "invalid analysis cutoff")
        item_require(isinstance(analysis.get("sourceIds"), list) and len(set(analysis.get("sourceIds", []))) >= 2, "INVALID_SIGNAL", "insufficient source IDs")
        coverage = item.get("coverage", {})
        expected = {update_key(update) for update in coverage.get("expectedUpdates", [])}
        reviewed = {update_key(update) for update in coverage.get("reviewedUpdates", [])}
        item_require(len(expected) == len(coverage.get("expectedUpdates", [])), "INCOMPLETE_COVERAGE", "duplicate expected update identity")
        item_require(len(reviewed) == len(coverage.get("reviewedUpdates", [])), "INCOMPLETE_COVERAGE", "duplicate reviewed update identity")
        item_require(item_key(item) in authoritative_keys, "INCOMPLETE_COVERAGE", "item is absent from trusted authority")
        item_require(expected == authoritative_keys, "INCOMPLETE_COVERAGE", "client expectedUpdates differs from trusted authority")
        item_require(reviewed == semantic_keys == authoritative_keys, "INCOMPLETE_COVERAGE", "reviewedUpdates or submitted items differ from trusted authority")
        item_require(coverage.get("complete") is True and expected == reviewed == authoritative_keys, "INCOMPLETE_COVERAGE", "complete flag or coverage sets disagree with trusted authority")
        if expected_group is None:
            expected_group = expected
        else:
            item_require(expected == expected_group, "INCOMPLETE_COVERAGE", "group expected coverage differs between items")
    return issues


def primary_signal_error(issues: list[tuple[str, str]]) -> str:
    precedence = ["DUPLICATE_ITEM_ID", "DUPLICATE_SEMANTIC_IDENTITY", "INVALID_TIMESTAMP", "INVALID_SIGNAL", "INCOMPLETE_COVERAGE"]
    codes = {code for code, _ in issues}
    return next((code for code in precedence if code in codes), "NONE")


def observed_manifest(source: dict) -> tuple[set[tuple[str, str]], set[tuple[str, str, str, str]]]:
    path = Path(source["path"])
    check(path.is_file(), f"missing source manifest: {path}")
    if not path.is_file():
        return set(), set()
    check(sha256(path) == source["sha256"], f"source hash drift: {path}")
    repo = path.parent if source["manifest"] == "go.mod" else path.parent.parent
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
    check(commit == source["consumerCommit"], f"consumer commit drift: {source['consumer']}")
    parsed = json.loads(subprocess.run(["go", "mod", "edit", "-json", str(path)], check=True, text=True, capture_output=True).stdout)
    direct = {(entry["Path"], entry["Version"]) for entry in parsed.get("Require", []) if not entry.get("Indirect", False)}
    replacements = {(entry["Old"]["Path"], entry["Old"].get("Version", ""), entry["New"]["Path"], entry["New"].get("Version", "")) for entry in parsed.get("Replace", [])}
    return direct, replacements


def evaluate_negative(case: dict) -> str:
    data = case["fixture"]
    if case["name"] == "missing-patch-release":
        return "VERSION_GAP" if set(data["eligibleVersions"]) != set(data["analyzedVersions"]) else "NONE"
    if case["name"] == "insufficient-sources":
        return "NONE" if data["hasSourceCode"] or data["substantiveClaims"] == 0 else "INSUFFICIENT_EVIDENCE"
    if case["name"] == "stale-decision":
        return "NONE" if data["recordedAnalysisRevision"] == data["currentAnalysisRevision"] else "STALE_SIGNAL"
    if case["name"] == "duplicate-item-id":
        return "NONE" if len(set(data["itemIds"])) == len(data["itemIds"]) else "DUPLICATE_ITEM_ID"
    if case["name"] == "malformed-timestamp":
        return "NONE" if valid_datetime(data["recordedAt"]) else "INVALID_TIMESTAMP"
    if case["name"] == "idempotent-rerun":
        return "NONE" if len(set(data["idempotencyKeys"])) == data["expectedStoredRecords"] else "DUPLICATE_RECORD"
    if case["name"] == "concurrent-write":
        return "NONE" if data["expectedGeneration"] == data["submittedGeneration"] else "GENERATION_CONFLICT"
    return "UNKNOWN_FIXTURE"


def apply_mutations(document: object, mutations: list[dict]) -> object:
    """Apply the small, generic JSON-Pointer mutation vocabulary used by fixtures."""
    result = deepcopy(document)
    for mutation in mutations:
        tokens = [token.replace("~1", "/").replace("~0", "~") for token in mutation["path"].split("/")[1:]]
        parent = result
        for token in tokens[:-1]:
            parent = parent[int(token)] if isinstance(parent, list) else parent[token]
        leaf = tokens[-1]
        key = int(leaf) if isinstance(parent, list) else leaf
        if mutation["op"] == "remove":
            del parent[key]
        elif mutation["op"] == "replace":
            parent[key] = deepcopy(mutation["value"])
        else:
            raise ValueError(f"unsupported mutation operation: {mutation['op']}")
    return result


def validate_chat_context(request_selection: dict, current_selection: dict, used_analysis_revision: object) -> str:
    fields = {"consumer", "manifest", "module", "from", "to", "analysisRevision"}
    if set(request_selection) != fields or set(current_selection) != fields:
        return "STALE_CHAT_CONTEXT"
    if request_selection != current_selection or used_analysis_revision != request_selection["analysisRevision"]:
        return "STALE_CHAT_CONTEXT"
    return "NONE"


def validate_analysis_fixture(fixture: dict) -> list[tuple[str, str]]:
    issues: list[tuple[str, str]] = []
    require = lambda condition, code, message: add_issue(issues, condition, code, message)
    require(fixture.get("language") == "en" and fixture.get("synthetic") is True, "ANALYSIS_STRUCTURE", "analysis fixture must be English SYNTHETIC")
    sources = fixture.get("sources", [])
    require(isinstance(sources, list) and bool(sources), "ANALYSIS_STRUCTURE", "analysis sources are required")
    required_source_fields = {"id", "kind", "synthetic", "locator", "sourceRevision", "capturedAt", "status", "content", "contentSha256", "absenceReason"}
    required_source_kinds = {"source-code", "git-diff", "tag-message", "release-notes", "changelog"}
    source_by_id: dict[str, dict] = {}
    for index, source in enumerate(sources if isinstance(sources, list) else []):
        label = f"analysis.sources[{index}]"
        if not isinstance(source, dict):
            issues.append(("INVALID_SOURCE_RECORD", f"{label}: source must be an object"))
            continue
        require(set(source) == required_source_fields, "INVALID_SOURCE_RECORD", f"{label}: fields differ from provenance contract")
        source_id = source.get("id")
        require(isinstance(source_id, str) and bool(source_id), "INVALID_SOURCE_RECORD", f"{label}: id")
        require(source.get("synthetic") is True, "INVALID_SOURCE_RECORD", f"{label}: source must be explicitly SYNTHETIC")
        require(isinstance(source.get("locator"), str) and bool(source.get("locator")), "INVALID_SOURCE_RECORD", f"{label}: locator")
        require(bool(HEX40.fullmatch(source.get("sourceRevision", ""))), "INVALID_SOURCE_RECORD", f"{label}: sourceRevision")
        require(valid_datetime(source.get("capturedAt")), "INVALID_SOURCE_RECORD", f"{label}: capturedAt")
        require(source.get("status") in {"present", "absent", "inaccessible"}, "INVALID_SOURCE_RECORD", f"{label}: status")
        if isinstance(source_id, str):
            require(source_id not in source_by_id, "DUPLICATE_SOURCE_ID", f"{label}: duplicate source id")
            source_by_id[source_id] = source
        if source.get("status") == "present":
            content = source.get("content")
            content_hash = source.get("contentSha256")
            require(isinstance(content, str) and bool(content) and bool(HEX64.fullmatch(content_hash or "")), "INVALID_SOURCE_CONTENT", f"{label}: present source needs literal UTF-8 content and SHA-256")
            require(source.get("absenceReason") is None, "INVALID_SOURCE_CONTENT", f"{label}: present source cannot have absenceReason")
            if isinstance(content, str) and isinstance(content_hash, str):
                actual_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                require(actual_hash == content_hash, "CONTENT_HASH_MISMATCH", f"{label}: literal content SHA-256 mismatch")
        elif source.get("status") in {"absent", "inaccessible"}:
            require(source.get("content") is None and source.get("contentSha256") is None, "UNEXPECTED_SOURCE_BYTES", f"{label}: unavailable source must not invent bytes or hash")
            require(isinstance(source.get("absenceReason"), str) and bool(source.get("absenceReason")), "MISSING_ABSENCE_REASON", f"{label}: unavailable source needs an explicit reason")
    source_kinds = {source.get("kind") for source in sources if isinstance(source, dict)}
    require(required_source_kinds <= source_kinds, "MISSING_SOURCE_KIND", "analysis fixture omits code, diff, tag/message, release notes, or changelog")

    required_baseline = {"version", "capabilities", "publicApi", "compatibilityEnvelope", "evidence", "uncertainty"}
    required_release = {"version", "previous", "compareUrl", "summary", "apiChanges", "compatibility", "migration", "evidenceAndProvenance", "impact", "uncertainty"}
    baseline, release = fixture.get("baseline", {}), fixture.get("release", {})
    require(set(baseline) == required_baseline, "ANALYSIS_STRUCTURE", "analysis fixture baseline sections")
    require(set(release) == required_release, "ANALYSIS_STRUCTURE", "analysis fixture release sections")
    claim_groups: list[tuple[list[dict], set[str]]] = [
        (baseline.get("capabilities", []), {"source-code"}),
        (baseline.get("publicApi", []), {"source-code"}),
        (baseline.get("compatibilityEnvelope", []), {"source-code"}),
        (baseline.get("evidence", []), {"source-code"}),
        (baseline.get("uncertainty", []), required_source_kinds),
        (release.get("summary", []), {"source-code", "git-diff", "release-notes"}),
        (release.get("apiChanges", []), {"source-code", "git-diff"}),
        (release.get("compatibility", []), {"source-code", "git-diff", "consumer-usage"}),
        (release.get("migration", []), {"source-code", "git-diff", "consumer-usage"}),
        (release.get("evidenceAndProvenance", []), required_source_kinds | {"consumer-usage"}),
        (release.get("uncertainty", []), required_source_kinds),
    ]
    for impact in release.get("impact", []):
        claim_groups.extend([
            (impact.get("changes", []), {"git-diff", "consumer-usage"}),
            (impact.get("risks", []), {"git-diff", "consumer-usage"}),
            (impact.get("benefits", []), {"git-diff", "consumer-usage"}),
        ])
    for group, suitable_kinds in claim_groups:
        for claim in group:
            require(claim.get("certainty") in {"confirmed", "inference", "unknown"}, "ANALYSIS_CLAIM", "analysis claim certainty")
            ids = claim.get("sourceIds", [])
            require(isinstance(ids, list) and all(source_id in source_by_id for source_id in ids), "UNRESOLVED_SOURCE_REFERENCE", "analysis claim references an unknown source")
            if claim.get("certainty") in {"confirmed", "inference"}:
                require(bool(ids), "ANALYSIS_CLAIM", "substantive analysis claim lacks provenance")
                resolved = [source_by_id[source_id] for source_id in ids if source_id in source_by_id]
                require(bool(resolved) and all(source.get("status") == "present" for source in resolved), "SOURCE_UNAVAILABLE_FOR_CLAIM", "substantive analysis claim cites unavailable content")
                require(any(source.get("kind") in suitable_kinds for source in resolved), "UNSUITABLE_SOURCE_REFERENCE", "analysis claim lacks a suitable source kind")
            if claim.get("certainty") == "inference":
                require(bool(claim.get("reasoning")) and bool(claim.get("bounds")), "ANALYSIS_CLAIM", "inference lacks reasoning or bounds")
    require(bool(release.get("compareUrl")), "ANALYSIS_STRUCTURE", "release lacks compare URL")
    return issues


def main() -> int:
    inventory, schema, examples = load("inventory.json"), load("decision.schema.json"), load("examples.json")
    counts = inventory["snapshot"]["counts"]
    check(len(inventory["sources"]) == counts["sourceManifests"] == 6, "manifest count must be 6")
    check(len(inventory["relationships"]) == counts["relationships"] == 44, "relationship count must be 44")
    declared_modules = {row["module"] for row in inventory["relationships"]}
    check(len(declared_modules) == counts["declaredModulePaths"] == 25, "declared module count must be 25")
    check({row["path"] for row in inventory["modules"]} == declared_modules, "module catalog must exactly cover declared modules")
    check(len(inventory["replacementDirectives"]) == counts["replacementDirectives"] == 8, "replacement count must be 8")
    check(len({row["effectiveModule"] for row in inventory["replacementDirectives"]}) == counts["replacementModulePaths"] == 3, "replacement module path count must be 3")
    check({row["id"] for row in inventory["replacementAssessments"]} == {row["assessmentId"] for row in inventory["replacementDirectives"]}, "replacement assessments incomplete")
    expected_relationships = {(row["consumer"], row["manifest"], row["module"], row["version"]) for row in inventory["relationships"]}
    expected_replacements = {(row["consumer"], row["manifest"], row["declaredModule"], "", row["effectiveModule"], row["effectiveVersion"]) for row in inventory["replacementDirectives"]}
    actual_relationships, actual_replacements = set(), set()
    for source in inventory["sources"]:
        direct, replacements = observed_manifest(source)
        actual_relationships |= {(source["consumer"], source["manifest"], module, version) for module, version in direct}
        actual_replacements |= {(source["consumer"], source["manifest"], old, old_version, new, new_version) for old, old_version, new, new_version in replacements}
    check(actual_relationships == expected_relationships, "inventory relationships differ from the six go.mod files")
    check(actual_replacements == expected_replacements, "inventory replacements differ from the six go.mod files")
    check(schema.get("$schema", "").endswith("2020-12/schema"), "schema draft must be 2020-12")
    check(schema.get("properties", {}).get("schemaVersion", {}).get("const") == "1.0.0", "schema version contract")
    check(schema.get("$defs", {}).get("coverage", {}).get("properties", {}).get("expectedUpdates", {}).get("items", {}).get("$ref") == "#/$defs/updateIdentity", "manifest-specific coverage schema")
    valid_signal_fixtures = {fixture["name"]: fixture for fixture in examples["validSignals"]}
    for fixture in valid_signal_fixtures.values():
        signal_issues = validate_signal(fixture["signal"], fixture.get("trustedAuthoritativeUpdates"), fixture["name"])
        for _, message in signal_issues:
            check(False, message)
    mixed = next(item for item in examples["validSignals"] if item["name"] == "fresh-grouped-mixed-review")
    check({item["decision"] for item in mixed["signal"]["items"]} == {"accept", "decline"}, "grouped fixture must be mixed")
    check(mixed["expectedEvaluation"] == "manual-block-mixed", "mixed group must block automation")
    for case in examples["negativeCases"]:
        check(evaluate_negative(case) == case["expectedError"], f"negative case failed: {case['name']}")
    for case in examples["signalValidationCases"]:
        if "signal" in case:
            signal = case["signal"]
            authority = case.get("trustedAuthoritativeUpdates")
        else:
            base = valid_signal_fixtures[case["basedOn"]]
            signal = apply_mutations(base["signal"], case.get("mutations", []))
            authority = base["trustedAuthoritativeUpdates"] if case.get("trustedAuthoritativeUpdates") == "from-base" else case.get("trustedAuthoritativeUpdates")
        result = primary_signal_error(validate_signal(signal, authority, case["name"]))
        check(result == case["expectedError"], f"signal validator case failed: {case['name']} returned {result}")
    analysis_issues = validate_analysis_fixture(examples["analysisFixture"])
    for _, message in analysis_issues:
        check(False, message)
    for case in examples["analysisMutationCases"]:
        mutated = apply_mutations(examples["analysisFixture"], case["mutations"])
        codes = {code for code, _ in validate_analysis_fixture(mutated)}
        check(case["expectedError"] in codes, f"analysis validator mutation failed: {case['name']} returned {sorted(codes)}")
    chat = examples["chatFixture"]
    check(chat["response"]["canWriteDecision"] is False and chat["response"]["decisionAuthority"] == "owner", "chatbot authority boundary")
    chat_status = validate_chat_context(chat["request"]["selection"], chat["currentSelection"], chat["response"]["usedAnalysisRevision"])
    check(chat_status == "NONE" and chat["expectedContextStatus"] == "current", "chat current-selection comparison")
    for case in examples["chatValidationCases"]:
        result = validate_chat_context(case["requestSelection"], case["currentSelection"], case["usedAnalysisRevision"])
        check(result == case["expectedError"], f"chat context regression failed: {case['name']} returned {result}")
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PASS: 6 manifests, 44 direct relationships, 25 declared modules, 8 replacements, 3 replacement paths")
    boundary_count = len(examples["negativeCases"]) + len(examples["signalValidationCases"]) + len(examples["analysisMutationCases"]) + len(examples["chatValidationCases"])
    print(f"PASS: {len(examples['validSignals'])} valid signals and {boundary_count} negative boundary cases")
    print("PASS: trusted manifest-specific coverage, reproducible provenance, strict timestamps, freshness, and read-only chatbot boundaries are consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
