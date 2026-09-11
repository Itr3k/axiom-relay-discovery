"""Exact-decimal, issuer-lifecycle and correction checks for MER Draft 0.1.

This module never fetches keys, receipts, payment records or private data.
"""
from datetime import datetime, timezone
import re

KEY_STATUSES = {"ACTIVE", "ROTATED", "RETIRED", "REVOKED", "COMPROMISED"}
CORRECTIONS = {"correction", "refund", "reversal", "dispute", "replacement", "revocation"}


def record(value):
    return value if isinstance(value, dict) else {}


def timestamp(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,3})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        # Integer arithmetic matches JavaScript milliseconds, including pre-epoch values.
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        delta = parsed - epoch
        return delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000
    except (ValueError, OverflowError):
        return None


def decimal_units(value):
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"(0|[1-9][0-9]*)(?:\.([0-9]{1,18}))?", value)
    return int(match[1] + (match[2] or "").ljust(18, "0")) if match else None


def money(value):
    value = record(value)
    amount = decimal_units(value.get("amount"))
    currency = value.get("currency")
    return {"amount": amount, "currency": currency, "network": value.get("network")} if amount is not None and isinstance(currency, str) and currency else None


def issue(issues, code, path="$.receipt", message=None):
    issues.append({"code": code, "path": path, "message": message or code.replace("_", " ").capitalize() + "."})


def same_currency(issues, values):
    currencies = [value["currency"] for value in values if value]
    if len(set(currencies)) > 1:
        issue(issues, "ECONOMIC_CURRENCY_MISMATCH", "$.receipt.economics")


def evaluate_key_lifecycle(events, proof_created, verification_time):
    issues = []
    proof_at, verified_at = timestamp(proof_created), timestamp(verification_time)
    if proof_at is None or verified_at is None:
        issue(issues, "KEY_LIFECYCLE_TIME_INVALID", "$.proof.created")
        return issues
    if not events:
        issue(issues, "KEY_LIFECYCLE_UNAVAILABLE", "$.receipt.issuer.keyId")
        return issues
    ordered = sorted(events, key=lambda event: (timestamp(event.get("recordedAt")) or 0, timestamp(event.get("effectiveAt")) or 0))
    if ordered[0].get("status") != "ACTIVE":
        issue(issues, "KEY_LIFECYCLE_INVALID", "$.receipt.issuer.keyId")
    prior = None
    for index, event in enumerate(ordered):
        status = event.get("status")
        effective, recorded = timestamp(event.get("effectiveAt")), timestamp(event.get("recordedAt"))
        invalid = timestamp(event.get("invalidFrom"))
        path = f"$.keyLifecycle[{index}]"
        if effective is None or recorded is None or effective > recorded:
            issue(issues, "KEY_LIFECYCLE_INVALID", path)
        if (status in {"REVOKED", "COMPROMISED"}) != (invalid is not None):
            issue(issues, "KEY_LIFECYCLE_INVALID", path + ".invalidFrom")
        if invalid is not None and effective is not None and invalid > effective:
            issue(issues, "KEY_LIFECYCLE_INVALID", path + ".invalidFrom")
        if index > 0 and status == "ACTIVE":
            issue(issues, "KEY_LIFECYCLE_INVALID", path + ".status")
        if status not in KEY_STATUSES:
            issue(issues, "KEY_LIFECYCLE_INVALID", path + ".status")
        if (status == "ROTATED") != bool(event.get("successorKeyId")):
            issue(issues, "KEY_LIFECYCLE_INVALID", path + ".successorKeyId")
        previous_effective = timestamp(ordered[index - 1].get("effectiveAt")) if index else None
        if previous_effective is not None and effective is not None and effective < previous_effective:
            issue(issues, "KEY_LIFECYCLE_INVALID", path + ".effectiveAt")
        if prior in {"REVOKED", "COMPROMISED"}:
            issue(issues, "KEY_LIFECYCLE_INVALID", path + ".status")
        if prior in {"ROTATED", "RETIRED"} and status not in {"REVOKED", "COMPROMISED"}:
            issue(issues, "KEY_LIFECYCLE_INVALID", path + ".status")
        prior = status
    for event in ordered:
        invalid = timestamp(event.get("invalidFrom"))
        if event.get("status") in {"REVOKED", "COMPROMISED"} and invalid is not None and invalid <= proof_at:
            issue(issues, "KEY_COMPROMISED_AT_PROOF" if event["status"] == "COMPROMISED" else "KEY_REVOKED_AT_PROOF", "$.proof.created")
    effective = sorted([event for event in ordered if timestamp(event.get("effectiveAt")) is not None and timestamp(event["effectiveAt"]) <= proof_at], key=lambda event: timestamp(event["effectiveAt"]))
    status = effective[-1].get("status") if effective else None
    if status is None:
        issue(issues, "KEY_NOT_YET_ACTIVE", "$.proof.created")
    elif status != "ACTIVE":
        issue(issues, "KEY_NOT_ACTIVE_AT_PROOF", "$.proof.created")
    return issues


def immutable_economics(value):
    return {**{key: value.get(key) for key in ("payerRole", "principal", "axiomRelayFee", "totalAuthorized")}, "otherFees": value.get("otherFees", []), "paymentFunding": value.get("paymentFunding")}


def immutable_commerce(value):
    if not isinstance(value, dict):
        return None
    keys = ("orderId", "quoteId", "expectationId", "executionId", "merchantRef", "merchantType", "pricing", "grossEconomicVolume", "providerPrincipal", "axiomRevenue", "activityClass", "realMoneyMoved", "commercialPolicy")
    return {key: value.get(key) for key in keys}


def semantic_integrity(envelope, lifecycle, at, predecessor=None, predecessor_digest=None):
    issues = []
    receipt, proof = record(envelope.get("receipt")), record(envelope.get("proof"))
    event, economics = record(receipt.get("event")), record(receipt.get("economics"))
    issued, created = receipt.get("issuedAt"), proof.get("created")
    issued_at, event_at, verified_at = timestamp(issued), timestamp(event.get("occurredAt")), timestamp(at)
    if issued and created and issued != created:
        issue(issues, "PROOF_CREATED_NOT_BOUND", "$.proof.created")
    if issued_at is not None and verified_at is not None and issued_at > verified_at + 300000:
        issue(issues, "PROOF_CREATED_IN_FUTURE", "$.proof.created")
    if event_at is not None and issued_at is not None and event_at > issued_at:
        issue(issues, "EVENT_AFTER_ISSUANCE", "$.receipt.event.occurredAt")
    if created:
        issues.extend(evaluate_key_lifecycle(lifecycle, created, at))
    principal, relay_fee, total = (money(economics.get(key)) for key in ("principal", "axiomRelayFee", "totalAuthorized"))
    if not all((principal, relay_fee, total)):
        return issues
    fees = [fee for fee in map(money, economics.get("otherFees", [])) if fee]
    currencies = [principal, relay_fee, total, *fees]
    funding = record(economics.get("paymentFunding"))
    adjustment = 0
    if funding.get("model") == "STRIPE_MINIMUM_WITH_SERVICE_CREDIT":
        charged, price, credit = (money(funding.get(key)) for key in ("chargedAmount", "servicePrice", "serviceCreditGranted"))
        if all((charged, price, credit)):
            currencies.extend((charged, price, credit))
            if price["amount"] != principal["amount"] or charged["amount"] != total["amount"]:
                issue(issues, "FUNDING_RELATIONSHIP_INVALID", "$.receipt.economics.paymentFunding")
            adjustment = credit["amount"]
            if price["amount"] + relay_fee["amount"] + sum(fee["amount"] for fee in fees) + adjustment != charged["amount"]:
                issue(issues, "FUNDING_RELATIONSHIP_INVALID", "$.receipt.economics.paymentFunding")
    elif funding.get("model") == "SERVICE_CREDIT_REDEMPTION":
        debited = money(funding.get("debitedAmount"))
        if debited:
            currencies.append(debited)
            if debited["amount"] != total["amount"]:
                issue(issues, "FUNDING_RELATIONSHIP_INVALID", "$.receipt.economics.paymentFunding.debitedAmount")
    same_currency(issues, currencies)
    if principal["amount"] + relay_fee["amount"] + sum(fee["amount"] for fee in fees) + adjustment != total["amount"]:
        issue(issues, "ECONOMIC_TOTAL_MISMATCH", "$.receipt.economics.totalAuthorized.amount")
    if principal["network"] and total["network"] and principal["network"] != total["network"]:
        issue(issues, "ECONOMIC_NETWORK_MISMATCH", "$.receipt.economics.totalAuthorized.network")
    if len({value["network"] for value in [principal, relay_fee, total, *fees] if value["network"]}) > 1:
        issue(issues, "ECONOMIC_NETWORK_MISMATCH", "$.receipt.economics")
    commerce = record(receipt.get("commerce"))
    if commerce:
        price, gross, provider, revenue = (money(commerce.get(key)) for key in ("pricing", "grossEconomicVolume", "providerPrincipal", "axiomRevenue"))
        if all((price, gross, provider, revenue)):
            same_currency(issues, [*currencies, price, gross, provider, revenue])
            if price["amount"] != principal["amount"] or gross["amount"] != price["amount"]:
                issue(issues, "COMMERCE_PRINCIPAL_MISMATCH", "$.receipt.commerce.pricing")
            if provider["amount"] + revenue["amount"] != gross["amount"]:
                issue(issues, "COMMERCE_ALLOCATION_MISMATCH", "$.receipt.commerce")
        settlement = record(commerce.get("settlement"))
        settled = decimal_units(settlement.get("amount"))
        if settlement.get("asset") == total["currency"] and settled is not None and settled != total["amount"]:
            issue(issues, "SETTLEMENT_TOTAL_MISMATCH", "$.receipt.commerce.settlement.amount")
        finality, state = settlement.get("finality"), economics.get("settlement")
        if (state == "SETTLED" and finality != "CONFIRMED") or (state == "PARTIALLY_REVERSED" and finality != state) or (state == "REVERSED" and finality != state) or (finality in {"PARTIALLY_REVERSED", "REVERSED"} and state != finality):
            issue(issues, "SETTLEMENT_STATE_MISMATCH", "$.receipt.commerce.settlement.finality")
        subject, raw_principal = record(receipt.get("subject")), record(economics.get("principal"))
        if commerce.get("merchantType") == "AXIOM_FIRST_PARTY" and (subject.get("providerId") != "axiom" or commerce.get("merchantRef") != "merchant.axiom" or raw_principal.get("recipientRole") != "axiom_first_party_merchant"):
            issue(issues, "ECONOMIC_PROVIDER_MISMATCH", "$.receipt.subject.providerId")
        if commerce.get("merchantType") == "THIRD_PARTY_PROVIDER" and (subject.get("providerId") != commerce.get("merchantRef") or raw_principal.get("recipientRole") != "provider"):
            issue(issues, "ECONOMIC_PROVIDER_MISMATCH", "$.receipt.subject.providerId")
    correction, event_type = record(receipt.get("correction")), event.get("type")
    if event_type not in CORRECTIONS:
        if correction:
            issue(issues, "UNEXPECTED_CORRECTION_DETAILS", "$.receipt.correction")
        return issues
    if not correction:
        issue(issues, "CORRECTION_DETAILS_REQUIRED", "$.receipt.correction")
        return issues
    if correction.get("type") != event_type:
        issue(issues, "CORRECTION_TYPE_MISMATCH", "$.receipt.correction.type")
    root_id, parent_id = correction.get("rootReceiptId"), correction.get("predecessorReceiptId")
    if not root_id or not parent_id or root_id == receipt.get("receiptId") or parent_id == receipt.get("receiptId"):
        issue(issues, "CORRECTION_LINEAGE_INVALID", "$.receipt.correction")
    if parent_id not in record(receipt.get("lineage")).get("previousEventIds", []):
        issue(issues, "CORRECTION_LINEAGE_INVALID", "$.receipt.lineage.previousEventIds")
    if predecessor is None:
        issue(issues, "CORRECTION_PREDECESSOR_UNRESOLVED", "$.receipt.correction.predecessorReceiptId")
    else:
        parent_event, parent_correction = record(predecessor.get("event")), record(predecessor.get("correction"))
        parent_root = parent_correction.get("rootReceiptId") if parent_correction else predecessor.get("receiptId")
        sequence = parent_event.get("sequence")
        if predecessor.get("receiptId") != parent_id or predecessor_digest != correction.get("predecessorDigest") or parent_root != root_id or type(sequence) is not int or event.get("sequence") != sequence + 1:
            issue(issues, "CORRECTION_LINEAGE_INVALID", "$.receipt.correction")
        if receipt.get("subject") != predecessor.get("subject"):
            issue(issues, "CORRECTION_SUBJECT_MISMATCH", "$.receipt.subject")
        if not isinstance(predecessor.get("economics"), dict) or immutable_economics(economics) != immutable_economics(predecessor["economics"]):
            issue(issues, "CORRECTION_ECONOMICS_MISMATCH", "$.receipt.economics")
        if immutable_commerce(receipt.get("commerce")) != immutable_commerce(predecessor.get("commerce")):
            issue(issues, "CORRECTION_COMMERCE_MISMATCH", "$.receipt.commerce")
        parent_issued, parent_event_at = timestamp(predecessor.get("issuedAt")), timestamp(parent_event.get("occurredAt"))
        if None in (parent_issued, parent_event_at, event_at, issued_at) or parent_event_at > parent_issued or issued_at < parent_issued:
            issue(issues, "CORRECTION_TIME_INVALID", "$.receipt.event.occurredAt")
    amount, cumulative = money(correction.get("amount")), money(correction.get("cumulativeAdjustedAmount"))
    source = record(correction.get("source"))
    if source and not valid_source(source, event_type, event, correction):
        issue(issues, "CORRECTION_SOURCE_INVALID", "$.receipt.correction.source")
    scope, resolution, state = correction.get("scope"), correction.get("resolution"), economics.get("settlement")
    if amount:
        same_currency(issues, [total, amount])
        invalid_amount = (scope == "NOT_APPLICABLE" and amount["amount"] != 0) or (scope == "FULL" and amount["amount"] != total["amount"]) or (scope == "PARTIAL" and (amount["amount"] == 0 or amount["amount"] >= total["amount"])) or amount["amount"] > total["amount"]
        if invalid_amount:
            issue(issues, "CORRECTION_AMOUNT_INVALID", "$.receipt.correction.amount")
        if source.get("type") == "STRIPE_PAYMENT_ADJUSTMENT":
            raw = money(source.get("sourceAmount"))
            if not raw or raw["currency"] != amount["currency"] or raw["amount"] < amount["amount"]:
                issue(issues, "CORRECTION_SOURCE_AMOUNT_INVALID", "$.receipt.correction.source.sourceAmount")
        if (event_type in {"refund", "reversal", "dispute"} and scope == "NOT_APPLICABLE") or (event_type in {"replacement", "revocation"} and scope != "NOT_APPLICABLE"):
            issue(issues, "CORRECTION_AMOUNT_INVALID", "$.receipt.correction.scope")
        if cumulative is None:
            if predecessor is not None and record(predecessor.get("correction")):
                issue(issues, "CORRECTION_CUMULATIVE_REQUIRED", "$.receipt.correction.cumulativeAdjustedAmount")
        else:
            same_currency(issues, [total, cumulative])
            if cumulative["amount"] > total["amount"]:
                issue(issues, "CORRECTION_CUMULATIVE_EXCEEDED", "$.receipt.correction.cumulativeAdjustedAmount")
            if predecessor is not None:
                parent_correction = record(predecessor.get("correction"))
                prior = money(parent_correction.get("cumulativeAdjustedAmount")) if parent_correction else {"amount": 0, "currency": total["currency"]}
                if prior is None:
                    issue(issues, "CORRECTION_PREDECESSOR_CUMULATIVE_INVALID", "$.receipt.correction.predecessorReceiptId")
                else:
                    contributes = event_type in {"refund", "reversal"} or (event_type == "dispute" and resolution == "APPLIED") or (event_type == "correction" and scope != "NOT_APPLICABLE" and resolution == "APPLIED")
                    credit = (source.get("type") == "STRIPE_PAYMENT_ADJUSTMENT" and source.get("economicDirection") == "CREDIT") or source.get("type") == "SERVICE_CREDIT_FUNDING_RESTORATION"
                    expected = prior["amount"] + ((-amount["amount"] if credit else amount["amount"]) if contributes else 0)
                    if prior["currency"] != cumulative["currency"] or expected < 0 or expected != cumulative["amount"]:
                        issue(issues, "CORRECTION_CUMULATIVE_MISMATCH", "$.receipt.correction.cumulativeAdjustedAmount")
                    if expected > total["amount"]:
                        issue(issues, "CORRECTION_CUMULATIVE_EXCEEDED", "$.receipt.correction.cumulativeAdjustedAmount")
    fully_adjusted = cumulative["amount"] == total["amount"] if cumulative else scope == "FULL"
    if event_type == "refund":
        if state != ("REFUNDED" if fully_adjusted else "PARTIALLY_REFUNDED"):
            issue(issues, "CORRECTION_SETTLEMENT_MISMATCH", "$.receipt.economics.settlement")
        if resolution not in {"APPLIED", "RESOLVED"}:
            issue(issues, "CORRECTION_RESOLUTION_MISMATCH", "$.receipt.correction.resolution")
    if event_type == "reversal":
        if state != ("REVERSED" if fully_adjusted else "PARTIALLY_REVERSED"):
            issue(issues, "CORRECTION_SETTLEMENT_MISMATCH", "$.receipt.economics.settlement")
        if resolution != "APPLIED":
            issue(issues, "CORRECTION_RESOLUTION_MISMATCH", "$.receipt.correction.resolution")
    if event_type == "dispute":
        if state not in {"DISPUTED", "SETTLED"}:
            issue(issues, "CORRECTION_SETTLEMENT_MISMATCH", "$.receipt.economics.settlement")
        if (state == "DISPUTED" and resolution not in {"OPEN", "APPLIED"}) or (state == "SETTLED" and resolution not in {"RESOLVED", "REJECTED"}):
            issue(issues, "CORRECTION_RESOLUTION_MISMATCH", "$.receipt.correction.resolution")
    restoration = (source.get("type") == "STRIPE_PAYMENT_ADJUSTMENT" and source.get("economicDirection") == "CREDIT") or source.get("type") == "SERVICE_CREDIT_FUNDING_RESTORATION"
    if event_type == "correction" and restoration and cumulative and ((cumulative["amount"] == 0 and state != "SETTLED") or (cumulative["amount"] > 0 and state not in {"PARTIALLY_REFUNDED", "PARTIALLY_REVERSED"})):
        issue(issues, "CORRECTION_SETTLEMENT_MISMATCH", "$.receipt.economics.settlement")
    return issues


def valid_source(source, kind, event, correction):
    if source.get("type") == "SERVICE_CREDIT_FUNDING_REVERSAL":
        return kind == "reversal" and correction.get("reasonCode") == "SERVICE_CREDIT_FUNDING_REVERSED" and correction.get("resolution") == "APPLIED"
    if source.get("type") == "SERVICE_CREDIT_FUNDING_RESTORATION":
        patterns = {"restorationId": "crrst", "correctionId": "crcor", "lotId": "lot", "allocationId": "alloc", "fundingRestorationEventId": "crevt"}
        return kind == "correction" and event.get("status") == "funding_restoration_recorded" and correction.get("reasonCode") == "SERVICE_CREDIT_FUNDING_RESTORED" and correction.get("resolution") == "APPLIED" and all(re.fullmatch(prefix + r"_[a-f0-9]{32}", str(source.get(key, ""))) for key, prefix in patterns.items())
    if source.get("type") != "STRIPE_PAYMENT_ADJUSTMENT" or correction.get("resolution") != "APPLIED":
        return False
    expected = {
        "STRIPE_REFUND_SUCCEEDED": ("refund", "DEBIT", "refund_applied"),
        "STRIPE_DISPUTE_LOST": ("dispute", "DEBIT", "dispute_lost"),
        "STRIPE_REFUND_REVERSED": ("correction", "CREDIT", "refund_reversed"),
        "STRIPE_DISPUTE_RESTORED": ("correction", "CREDIT", "dispute_restored"),
    }.get(correction.get("reasonCode"))
    patterns = {"queueId": r"pmlq_[a-f0-9]{32}", "adjustmentId": r"adj_[a-f0-9]{32}", "providerEventId": r"[A-Za-z0-9._:-]{3,255}", "providerEventType": r"[a-z0-9._]{3,120}", "rawPayloadHash": r"sha256:[a-f0-9]{64}"}
    return expected == (kind, source.get("economicDirection"), event.get("status")) and all(isinstance(source.get(key), str) and re.fullmatch(pattern, source[key]) for key, pattern in patterns.items()) and money(source.get("sourceAmount")) is not None
