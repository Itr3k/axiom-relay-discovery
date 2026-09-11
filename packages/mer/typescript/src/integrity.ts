import { merTimestamp } from "./time.js";
export const MER_KEY_STATUSES = [
  "ACTIVE",
  "ROTATED",
  "RETIRED",
  "REVOKED",
  "COMPROMISED",
] as const;

export type MerKeyStatus = (typeof MER_KEY_STATUSES)[number];

export type MerKeyStatusEvent = {
  status: MerKeyStatus;
  effectiveAt: string;
  recordedAt: string;
  invalidFrom?: string | null;
  successorKeyId?: string | null;
};

export type MerIntegrityIssue = {
  code: string;
  path: string;
  message: string;
};

export type MerLineageContext = {
  canonicalDigest: string;
  receipt: Record<string, unknown>;
};

type RecordValue = Record<string, unknown>;

const CORRECTION_EVENT_TYPES = new Set([
  "correction",
  "refund",
  "reversal",
  "dispute",
  "replacement",
  "revocation",
]);

const TERMINAL_KEY_STATUSES = new Set<MerKeyStatus>(["REVOKED", "COMPROMISED"]);
const DECIMAL_SCALE = 18;
const FUTURE_CLOCK_SKEW_MS = 5 * 60 * 1_000;

function record(value: unknown): RecordValue | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as RecordValue
    : null;
}

function string(value: unknown) {
  return typeof value === "string" ? value : null;
}

const timestamp = merTimestamp;

function decimalUnits(value: unknown) {
  const text = string(value);
  const match = text?.match(/^(0|[1-9][0-9]*)(?:\.([0-9]{1,18}))?$/);
  if (!match) return null;
  return BigInt(`${match[1]}${(match[2] ?? "").padEnd(DECIMAL_SCALE, "0")}`);
}

function money(value: unknown) {
  const candidate = record(value);
  if (!candidate) return null;
  const amount = decimalUnits(candidate.amount);
  const currency = string(candidate.currency);
  return amount === null || !currency
    ? null
    : { amount, currency, network: string(candidate.network) };
}

function issue(
  issues: MerIntegrityIssue[],
  code: string,
  path: string,
  message: string,
) {
  issues.push({ code, path, message });
}

function assertSameCurrency(
  issues: MerIntegrityIssue[],
  values: ReadonlyArray<{ currency: string; path: string }>,
) {
  const expected = values[0]?.currency;
  if (expected && values.some((entry) => entry.currency !== expected)) {
    issue(
      issues,
      "ECONOMIC_CURRENCY_MISMATCH",
      "$.receipt.economics",
      "Principal, fees, funding, commerce, and corrections must use one declared currency.",
    );
  }
}

function structurallyEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((entry, index) => structurallyEqual(entry, right[index]));
  }
  const leftRecord = record(left);
  const rightRecord = record(right);
  if (!leftRecord || !rightRecord) return false;
  const leftKeys = Object.keys(leftRecord).sort();
  const rightKeys = Object.keys(rightRecord).sort();
  return leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) =>
      key === rightKeys[index] && structurallyEqual(leftRecord[key], rightRecord[key]));
}

function immutableEconomics(value: RecordValue) {
  return {
    payerRole: value.payerRole,
    principal: value.principal,
    axiomRelayFee: value.axiomRelayFee,
    otherFees: value.otherFees ?? [],
    totalAuthorized: value.totalAuthorized,
    paymentFunding: value.paymentFunding ?? null,
  };
}

function immutableCommerce(value: unknown) {
  const commerce = record(value);
  if (!commerce) return null;
  return {
    orderId: commerce.orderId ?? null,
    quoteId: commerce.quoteId ?? null,
    expectationId: commerce.expectationId ?? null,
    executionId: commerce.executionId ?? null,
    merchantRef: commerce.merchantRef,
    merchantType: commerce.merchantType,
    pricing: commerce.pricing,
    grossEconomicVolume: commerce.grossEconomicVolume,
    providerPrincipal: commerce.providerPrincipal,
    axiomRevenue: commerce.axiomRevenue,
    activityClass: commerce.activityClass,
    realMoneyMoved: commerce.realMoneyMoved,
    commercialPolicy: commerce.commercialPolicy ?? null,
  };
}

export function evaluateMerKeyLifecycle(
  events: ReadonlyArray<MerKeyStatusEvent>,
  proofCreated: string,
  verificationTime = new Date().toISOString(),
) {
  const issues: MerIntegrityIssue[] = [];
  const proofAt = timestamp(proofCreated);
  const verifiedAt = timestamp(verificationTime);
  if (proofAt === null || verifiedAt === null) {
    issue(issues, "KEY_LIFECYCLE_TIME_INVALID", "$.proof.created", "Key lifecycle evaluation requires valid timestamps.");
    return { valid: false, structureValid: false, statusAtProof: null, issues };
  }
  if (events.length === 0) {
    issue(issues, "KEY_LIFECYCLE_UNAVAILABLE", "$.receipt.issuer.keyId", "The verification key has no append-only lifecycle evidence.");
    return { valid: false, structureValid: false, statusAtProof: null, issues };
  }

  const ordered = [...events].sort((left, right) => {
    const recorded = (timestamp(left.recordedAt) ?? 0) - (timestamp(right.recordedAt) ?? 0);
    return recorded || (timestamp(left.effectiveAt) ?? 0) - (timestamp(right.effectiveAt) ?? 0);
  });
  if (ordered[0]?.status !== "ACTIVE") {
    issue(issues, "KEY_LIFECYCLE_INVALID", "$.receipt.issuer.keyId", "The first key lifecycle event must activate the key.");
  }

  let priorStatus: MerKeyStatus | null = null;
  for (const [index, event] of ordered.entries()) {
    const effectiveAt = timestamp(event.effectiveAt);
    const recordedAt = timestamp(event.recordedAt);
    const invalidFrom = event.invalidFrom == null ? null : timestamp(event.invalidFrom);
    if (effectiveAt === null || recordedAt === null || effectiveAt > recordedAt) {
      issue(issues, "KEY_LIFECYCLE_INVALID", `$.keyLifecycle[${index}]`, "Key lifecycle event times are invalid or effective after recording.");
    }
    if ((event.status === "REVOKED" || event.status === "COMPROMISED") !== (invalidFrom !== null)) {
      issue(issues, "KEY_LIFECYCLE_INVALID", `$.keyLifecycle[${index}].invalidFrom`, "Revoked or compromised keys require an invalid-from time; other states forbid it.");
    }
    if (invalidFrom !== null && effectiveAt !== null && invalidFrom > effectiveAt) {
      issue(issues, "KEY_LIFECYCLE_INVALID", `$.keyLifecycle[${index}].invalidFrom`, "A revocation cannot begin after its effective time.");
    }
    if (index > 0 && event.status === "ACTIVE") {
      issue(issues, "KEY_LIFECYCLE_INVALID", `$.keyLifecycle[${index}].status`, "A signing key cannot be reactivated.");
    }
    if (!MER_KEY_STATUSES.includes(event.status)) {
      issue(issues, "KEY_LIFECYCLE_INVALID", `$.keyLifecycle[${index}].status`, "Key lifecycle status is not supported.");
    }
    if ((event.status === "ROTATED") !== Boolean(event.successorKeyId)) {
      issue(issues, "KEY_LIFECYCLE_INVALID", `$.keyLifecycle[${index}].successorKeyId`, "Only rotation requires a distinct successor key.");
    }
    if (event.status === "ROTATED" && event.successorKeyId === "") {
      issue(issues, "KEY_LIFECYCLE_INVALID", `$.keyLifecycle[${index}].successorKeyId`, "Rotation successor key cannot be empty.");
    }
    const previousEffectiveAt = index > 0 ? timestamp(ordered[index - 1]?.effectiveAt) : null;
    if (
      previousEffectiveAt !== null &&
      effectiveAt !== null &&
      effectiveAt < previousEffectiveAt
    ) {
      issue(
        issues,
        "KEY_LIFECYCLE_INVALID",
        `$.keyLifecycle[${index}].effectiveAt`,
        "Key status transitions must be effective in recorded order; invalidFrom may separately backdate emergency invalidity.",
      );
    }
    if (priorStatus && TERMINAL_KEY_STATUSES.has(priorStatus)) {
      issue(issues, "KEY_LIFECYCLE_INVALID", `$.keyLifecycle[${index}].status`, "No event may follow a terminal key compromise or revocation.");
    }
    if (priorStatus === "ROTATED" || priorStatus === "RETIRED") {
      if (event.status !== "REVOKED" && event.status !== "COMPROMISED") {
        issue(issues, "KEY_LIFECYCLE_INVALID", `$.keyLifecycle[${index}].status`, "A rotated or retired key may only be revoked or marked compromised later.");
      }
    }
    priorStatus = event.status;
  }

  for (const event of ordered) {
    if (
      (event.status === "REVOKED" || event.status === "COMPROMISED") &&
      event.invalidFrom &&
      (timestamp(event.invalidFrom) ?? Number.POSITIVE_INFINITY) <= proofAt
    ) {
      issue(
        issues,
        event.status === "COMPROMISED" ? "KEY_COMPROMISED_AT_PROOF" : "KEY_REVOKED_AT_PROOF",
        "$.proof.created",
        `The receipt was created within the key's ${event.status.toLowerCase()} interval.`,
      );
    }
  }

  const effective = ordered
    .filter((event) => (timestamp(event.effectiveAt) ?? Number.POSITIVE_INFINITY) <= proofAt)
    .sort((left, right) => (timestamp(left.effectiveAt) ?? 0) - (timestamp(right.effectiveAt) ?? 0));
  const statusAtProof = effective.at(-1)?.status ?? null;
  if (!statusAtProof) {
    issue(issues, "KEY_NOT_YET_ACTIVE", "$.proof.created", "The receipt predates the signing key's activation.");
  } else if (statusAtProof !== "ACTIVE") {
    issue(issues, "KEY_NOT_ACTIVE_AT_PROOF", "$.proof.created", `The signing key was ${statusAtProof.toLowerCase()} when the receipt was created.`);
  }

  const structureValid = !issues.some((entry) =>
    entry.code === "KEY_LIFECYCLE_INVALID" ||
    entry.code === "KEY_LIFECYCLE_TIME_INVALID" ||
    entry.code === "KEY_LIFECYCLE_UNAVAILABLE");
  return { valid: issues.length === 0, structureValid, statusAtProof, issues };
}

export function verifyMerSemanticIntegrity(
  value: unknown,
  keyLifecycle: ReadonlyArray<MerKeyStatusEvent>,
  verificationTime = new Date().toISOString(),
  lineageContext: MerLineageContext | null = null,
) {
  const issues: MerIntegrityIssue[] = [];
  const root = record(value);
  const receipt = record(root?.receipt);
  const proof = record(root?.proof);
  const event = record(receipt?.event);
  const economics = record(receipt?.economics);
  if (!receipt || !proof || !event || !economics) return { valid: false, issues };

  const issuedAt = string(receipt.issuedAt);
  const proofCreated = string(proof.created);
  const eventAt = timestamp(event.occurredAt);
  const issuedTimestamp = timestamp(issuedAt);
  const verifiedTimestamp = timestamp(verificationTime);
  if (issuedAt && proofCreated && issuedAt !== proofCreated) {
    issue(
      issues,
      "PROOF_CREATED_NOT_BOUND",
      "$.proof.created",
      "proof.created must exactly equal the signed receipt.issuedAt value.",
    );
  }
  if (
    issuedTimestamp !== null &&
    verifiedTimestamp !== null &&
    issuedTimestamp > verifiedTimestamp + FUTURE_CLOCK_SKEW_MS
  ) {
    issue(issues, "PROOF_CREATED_IN_FUTURE", "$.proof.created", "The receipt proof is unreasonably far in the future.");
  }
  if (eventAt !== null && issuedTimestamp !== null && eventAt > issuedTimestamp) {
    issue(issues, "EVENT_AFTER_ISSUANCE", "$.receipt.event.occurredAt", "An economic event cannot occur after its receipt was issued.");
  }

  if (proofCreated) {
    issues.push(...evaluateMerKeyLifecycle(keyLifecycle, proofCreated, verificationTime).issues);
  }

  const principal = money(economics.principal);
  const relayFee = money(economics.axiomRelayFee);
  const total = money(economics.totalAuthorized);
  const otherFees = Array.isArray(economics.otherFees)
    ? economics.otherFees.map((entry) => money(entry)).filter((entry): entry is NonNullable<typeof entry> => Boolean(entry))
    : [];
  if (principal && relayFee && total) {
    const currencyValues = [
      { currency: principal.currency, path: "$.receipt.economics.principal.currency" },
      { currency: relayFee.currency, path: "$.receipt.economics.axiomRelayFee.currency" },
      { currency: total.currency, path: "$.receipt.economics.totalAuthorized.currency" },
      ...otherFees.map((entry, index) => ({ currency: entry.currency, path: `$.receipt.economics.otherFees[${index}].currency` })),
    ];
    const funding = record(economics.paymentFunding);
    let fundingAdjustment = 0n;
    if (funding?.model === "STRIPE_MINIMUM_WITH_SERVICE_CREDIT") {
      const charged = money(funding.chargedAmount);
      const servicePrice = money(funding.servicePrice);
      const creditGranted = money(funding.serviceCreditGranted);
      if (charged && servicePrice && creditGranted) {
        currencyValues.push(
          { currency: charged.currency, path: "$.receipt.economics.paymentFunding.chargedAmount.currency" },
          { currency: servicePrice.currency, path: "$.receipt.economics.paymentFunding.servicePrice.currency" },
          { currency: creditGranted.currency, path: "$.receipt.economics.paymentFunding.serviceCreditGranted.currency" },
        );
        if (servicePrice.amount !== principal.amount || charged.amount !== total.amount) {
          issue(issues, "FUNDING_RELATIONSHIP_INVALID", "$.receipt.economics.paymentFunding", "Stripe funding must bind the service price to principal and charged amount to total authorized.");
        }
        fundingAdjustment = creditGranted.amount;
        const fundingTotal = servicePrice.amount + relayFee.amount +
          otherFees.reduce((sum, entry) => sum + entry.amount, 0n) + creditGranted.amount;
        if (fundingTotal !== charged.amount) {
          issue(issues, "FUNDING_RELATIONSHIP_INVALID", "$.receipt.economics.paymentFunding", "Stripe service price, declared fees, and granted service credit must equal the charged amount.");
        }
      }
    } else if (funding?.model === "SERVICE_CREDIT_REDEMPTION") {
      const debited = money(funding.debitedAmount);
      if (debited) {
        currencyValues.push({ currency: debited.currency, path: "$.receipt.economics.paymentFunding.debitedAmount.currency" });
        if (debited.amount !== total.amount) {
          issue(issues, "FUNDING_RELATIONSHIP_INVALID", "$.receipt.economics.paymentFunding.debitedAmount", "Service-credit debit must equal total authorized.");
        }
      }
    }
    assertSameCurrency(issues, currencyValues);
    const expected = principal.amount + relayFee.amount + otherFees.reduce((sum, entry) => sum + entry.amount, 0n) + fundingAdjustment;
    if (expected !== total.amount) {
      issue(
        issues,
        "ECONOMIC_TOTAL_MISMATCH",
        "$.receipt.economics.totalAuthorized.amount",
        "Total authorized must equal principal, Axiom fee, other fees, and any separately granted service credit.",
      );
    }
    if (principal.network && total.network && principal.network !== total.network) {
      issue(issues, "ECONOMIC_NETWORK_MISMATCH", "$.receipt.economics.totalAuthorized.network", "Money denominated on a network must use one network.");
    }
    const declaredNetworks = [principal, relayFee, total, ...otherFees]
      .map((entry) => entry.network)
      .filter((entry): entry is string => Boolean(entry));
    if (new Set(declaredNetworks).size > 1) {
      issue(issues, "ECONOMIC_NETWORK_MISMATCH", "$.receipt.economics", "All network-denominated economic amounts must use one network.");
    }

    const commerce = record(receipt.commerce);
    if (commerce) {
      const pricing = money(commerce.pricing);
      const gross = money(commerce.grossEconomicVolume);
      const provider = money(commerce.providerPrincipal);
      const revenue = money(commerce.axiomRevenue);
      if (pricing && gross && provider && revenue) {
        assertSameCurrency(issues, [
          ...currencyValues,
          { currency: pricing.currency, path: "$.receipt.commerce.pricing.currency" },
          { currency: gross.currency, path: "$.receipt.commerce.grossEconomicVolume.currency" },
          { currency: provider.currency, path: "$.receipt.commerce.providerPrincipal.currency" },
          { currency: revenue.currency, path: "$.receipt.commerce.axiomRevenue.currency" },
        ]);
        if (pricing.amount !== principal.amount || gross.amount !== pricing.amount) {
          issue(issues, "COMMERCE_PRINCIPAL_MISMATCH", "$.receipt.commerce.pricing", "Commerce pricing, gross value, and receipt principal must agree.");
        }
        if (provider.amount + revenue.amount !== gross.amount) {
          issue(issues, "COMMERCE_ALLOCATION_MISMATCH", "$.receipt.commerce", "Provider principal plus Axiom revenue must equal gross economic value.");
        }
      }
      const settlement = record(commerce.settlement);
      if (settlement?.asset === total.currency) {
        const settledAmount = decimalUnits(settlement.amount);
        if (settledAmount !== null && settledAmount !== total.amount) {
          issue(issues, "SETTLEMENT_TOTAL_MISMATCH", "$.receipt.commerce.settlement.amount", "Same-currency settlement must equal total authorized.");
        }
      }
      const settlementFinality = string(settlement?.finality);
      const economicSettlement = string(economics.settlement);
      if (
        (economicSettlement === "SETTLED" && settlementFinality !== "CONFIRMED") ||
        (economicSettlement === "PARTIALLY_REVERSED" && settlementFinality !== "PARTIALLY_REVERSED") ||
        (economicSettlement === "REVERSED" && settlementFinality !== "REVERSED") ||
        (settlementFinality === "PARTIALLY_REVERSED" && economicSettlement !== "PARTIALLY_REVERSED") ||
        (settlementFinality === "REVERSED" && economicSettlement !== "REVERSED")
      ) {
        issue(issues, "SETTLEMENT_STATE_MISMATCH", "$.receipt.commerce.settlement.finality", "Commerce finality and the signed economic settlement state contradict one another.");
      }
      if (commerce.merchantType === "AXIOM_FIRST_PARTY") {
        const subject = record(receipt.subject);
        if (
          subject?.providerId !== "axiom" ||
          commerce.merchantRef !== "merchant.axiom" ||
          record(economics.principal)?.recipientRole !== "axiom_first_party_merchant"
        ) {
          issue(issues, "ECONOMIC_PROVIDER_MISMATCH", "$.receipt.subject.providerId", "First-party commerce must bind Axiom as the subject, merchant, and principal recipient.");
        }
      }
      if (commerce.merchantType === "THIRD_PARTY_PROVIDER") {
        const subject = record(receipt.subject);
        if (
          subject?.providerId !== commerce.merchantRef ||
          record(economics.principal)?.recipientRole !== "provider"
        ) {
          issue(
            issues,
            "ECONOMIC_PROVIDER_MISMATCH",
            "$.receipt.subject.providerId",
            "Third-party commerce must bind the signed provider subject to the exact merchant reference and provider principal recipient.",
          );
        }
      }
    }

    const eventType = string(event.type);
    const correction = record(receipt.correction);
    if (eventType && CORRECTION_EVENT_TYPES.has(eventType)) {
      if (!correction) {
        issue(issues, "CORRECTION_DETAILS_REQUIRED", "$.receipt.correction", "Correction lifecycle events require signed correction details.");
      } else {
        const correctionType = string(correction.type);
        const receiptId = string(receipt.receiptId);
        const rootReceiptId = string(correction.rootReceiptId);
        const predecessorReceiptId = string(correction.predecessorReceiptId);
        const previousEventIds = record(receipt.lineage)?.previousEventIds;
        if (correctionType !== eventType) {
          issue(issues, "CORRECTION_TYPE_MISMATCH", "$.receipt.correction.type", "Correction type must match the signed event type.");
        }
        if (!rootReceiptId || !predecessorReceiptId || rootReceiptId === receiptId || predecessorReceiptId === receiptId) {
          issue(issues, "CORRECTION_LINEAGE_INVALID", "$.receipt.correction", "Correction lineage cannot be empty or self-referential.");
        }
        if (!Array.isArray(previousEventIds) || !previousEventIds.includes(predecessorReceiptId)) {
          issue(issues, "CORRECTION_LINEAGE_INVALID", "$.receipt.lineage.previousEventIds", "Correction lineage must include its immediate predecessor receipt.");
        }
        if (!lineageContext) {
          issue(
            issues,
            "CORRECTION_PREDECESSOR_UNRESOLVED",
            "$.receipt.correction.predecessorReceiptId",
            "A correction receipt is valid only when its immutable predecessor receipt is supplied or resolved.",
          );
        } else {
          const predecessor = lineageContext.receipt;
          const predecessorReceiptId = string(predecessor.receiptId);
          const predecessorEvent = record(predecessor.event);
          const predecessorCorrection = record(predecessor.correction);
          const predecessorRootReceiptId = predecessorCorrection
            ? string(predecessorCorrection.rootReceiptId)
            : predecessorReceiptId;
          const predecessorSequence = predecessorEvent?.sequence;
          if (
            predecessorReceiptId !== string(correction.predecessorReceiptId) ||
            lineageContext.canonicalDigest !== string(correction.predecessorDigest) ||
            predecessorRootReceiptId !== rootReceiptId ||
            !Number.isInteger(predecessorSequence) ||
            !Number.isInteger(event.sequence) ||
            Number(event.sequence) !== Number(predecessorSequence) + 1
          ) {
            issue(
              issues,
              "CORRECTION_LINEAGE_INVALID",
              "$.receipt.correction",
              "Correction root, predecessor identity, digest, and event sequence must resolve to the supplied predecessor.",
            );
          }
          if (!structurallyEqual(receipt.subject, predecessor.subject)) {
            issue(issues, "CORRECTION_SUBJECT_MISMATCH", "$.receipt.subject", "A correction cannot change the signed service or provider subject.");
          }
          const predecessorEconomics = record(predecessor.economics);
          if (!predecessorEconomics || !structurallyEqual(immutableEconomics(economics), immutableEconomics(predecessorEconomics))) {
            issue(issues, "CORRECTION_ECONOMICS_MISMATCH", "$.receipt.economics", "A lifecycle successor cannot rewrite the original economic contract.");
          }
          if (!structurallyEqual(immutableCommerce(receipt.commerce), immutableCommerce(predecessor.commerce))) {
            issue(issues, "CORRECTION_COMMERCE_MISMATCH", "$.receipt.commerce", "A lifecycle successor cannot rewrite commerce identity or allocation.");
          }
          const predecessorIssuedAt = timestamp(predecessor.issuedAt);
          const predecessorEventAt = timestamp(predecessorEvent?.occurredAt);
          if (
            predecessorIssuedAt === null ||
            predecessorEventAt === null ||
            eventAt === null ||
            issuedTimestamp === null
          ) {
            issue(issues, "CORRECTION_TIME_INVALID", "$.receipt.event.occurredAt", "A lifecycle event and its predecessor require valid signed timestamps.");
          } else if (
            predecessorEventAt > predecessorIssuedAt ||
            issuedTimestamp < predecessorIssuedAt
          ) {
            issue(
              issues,
              "CORRECTION_TIME_INVALID",
              "$.receipt.event.occurredAt",
              "A correction lifecycle successor cannot be issued before its signed predecessor, and each signed event must not postdate its own receipt.",
            );
          }
        }
        const adjustment = money(correction.amount);
        const cumulativeAdjusted = money(correction.cumulativeAdjustedAmount);
        const source = record(correction.source);
        if (source) {
          const validServiceCreditSource =
            source.type === "SERVICE_CREDIT_FUNDING_REVERSAL" &&
            eventType === "reversal" &&
            correction.reasonCode === "SERVICE_CREDIT_FUNDING_REVERSED" &&
            correction.resolution === "APPLIED";
          const validServiceCreditRestorationSource =
            source.type === "SERVICE_CREDIT_FUNDING_RESTORATION" &&
            eventType === "correction" &&
            string(event.status) === "funding_restoration_recorded" &&
            correction.reasonCode === "SERVICE_CREDIT_FUNDING_RESTORED" &&
            correction.resolution === "APPLIED" &&
            typeof source.restorationId === "string" && /^crrst_[a-f0-9]{32}$/.test(source.restorationId) &&
            typeof source.correctionId === "string" && /^crcor_[a-f0-9]{32}$/.test(source.correctionId) &&
            typeof source.lotId === "string" && /^lot_[a-f0-9]{32}$/.test(source.lotId) &&
            typeof source.allocationId === "string" && /^alloc_[a-f0-9]{32}$/.test(source.allocationId) &&
            typeof source.fundingRestorationEventId === "string" && /^crevt_[a-f0-9]{32}$/.test(source.fundingRestorationEventId);
          const validStripeAdjustmentSource =
            source.type === "STRIPE_PAYMENT_ADJUSTMENT" &&
            (eventType === "refund" || eventType === "dispute" || eventType === "correction") &&
            correction.resolution === "APPLIED" &&
            (source.economicDirection === "DEBIT" || source.economicDirection === "CREDIT") &&
            (
              (source.economicDirection === "DEBIT" && (eventType === "refund" || eventType === "dispute")) ||
              (source.economicDirection === "CREDIT" && eventType === "correction")
            ) &&
            (
              (eventType === "refund" && correction.reasonCode === "STRIPE_REFUND_SUCCEEDED") ||
              (eventType === "dispute" && correction.reasonCode === "STRIPE_DISPUTE_LOST") ||
              (eventType === "correction" && (
                correction.reasonCode === "STRIPE_REFUND_REVERSED" ||
                correction.reasonCode === "STRIPE_DISPUTE_RESTORED"
              ))
            ) &&
            (
              (correction.reasonCode === "STRIPE_REFUND_SUCCEEDED" && string(event.status) === "refund_applied") ||
              (correction.reasonCode === "STRIPE_DISPUTE_LOST" && string(event.status) === "dispute_lost") ||
              (correction.reasonCode === "STRIPE_REFUND_REVERSED" && string(event.status) === "refund_reversed") ||
              (correction.reasonCode === "STRIPE_DISPUTE_RESTORED" && string(event.status) === "dispute_restored")
            ) &&
            typeof source.queueId === "string" && /^pmlq_[a-f0-9]{32}$/.test(source.queueId) &&
            typeof source.adjustmentId === "string" && /^adj_[a-f0-9]{32}$/.test(source.adjustmentId) &&
            typeof source.providerEventId === "string" && /^[A-Za-z0-9._:-]{3,255}$/.test(source.providerEventId) &&
            typeof source.providerEventType === "string" && /^[a-z0-9._]{3,120}$/.test(source.providerEventType) &&
            typeof source.rawPayloadHash === "string" && /^sha256:[a-f0-9]{64}$/.test(source.rawPayloadHash) &&
            Boolean(money(source.sourceAmount));
          if (!validServiceCreditSource && !validServiceCreditRestorationSource && !validStripeAdjustmentSource) {
            issue(issues, "CORRECTION_SOURCE_INVALID", "$.receipt.correction.source", "Correction source evidence does not match its signed lifecycle event.");
          }
        }
        if (adjustment) {
          assertSameCurrency(issues, [
            { currency: total.currency, path: "$.receipt.economics.totalAuthorized.currency" },
            { currency: adjustment.currency, path: "$.receipt.correction.amount.currency" },
          ]);
          const scope = string(correction.scope);
          if (scope === "NOT_APPLICABLE" && adjustment.amount !== 0n) {
            issue(issues, "CORRECTION_AMOUNT_INVALID", "$.receipt.correction.amount", "A non-monetary correction must declare a zero amount.");
          }
          if (scope === "FULL" && adjustment.amount !== total.amount) {
            issue(issues, "CORRECTION_AMOUNT_INVALID", "$.receipt.correction.amount", "A full correction must equal total authorized.");
          }
          if (scope === "PARTIAL" && (adjustment.amount === 0n || adjustment.amount >= total.amount)) {
            issue(issues, "CORRECTION_AMOUNT_INVALID", "$.receipt.correction.amount", "A partial correction must be greater than zero and less than total authorized.");
          }
          if (adjustment.amount > total.amount) {
            issue(issues, "CORRECTION_AMOUNT_INVALID", "$.receipt.correction.amount", "A correction cannot exceed total authorized.");
          }
          if (source?.type === "STRIPE_PAYMENT_ADJUSTMENT") {
            const sourceAmount = money(source.sourceAmount);
            if (
              !sourceAmount ||
              sourceAmount.currency !== adjustment.currency ||
              sourceAmount.amount < adjustment.amount
            ) {
              issue(issues, "CORRECTION_SOURCE_AMOUNT_INVALID", "$.receipt.correction.source.sourceAmount", "A Stripe lifecycle correction must bind the exact provider-event amount, and its effective adjustment cannot exceed that source amount.");
            }
          }
          if (
            (eventType === "refund" || eventType === "reversal" || eventType === "dispute") &&
            scope === "NOT_APPLICABLE"
          ) {
            issue(issues, "CORRECTION_AMOUNT_INVALID", "$.receipt.correction.scope", "Refund, reversal, and dispute receipts require an explicit partial or full amount scope.");
          }
          if ((eventType === "replacement" || eventType === "revocation") && scope !== "NOT_APPLICABLE") {
            issue(issues, "CORRECTION_AMOUNT_INVALID", "$.receipt.correction.scope", "Replacement and revocation receipts are non-monetary lifecycle records.");
          }

          if (!cumulativeAdjusted) {
            if (lineageContext && record(lineageContext.receipt.correction)) {
              issue(issues, "CORRECTION_CUMULATIVE_REQUIRED", "$.receipt.correction.cumulativeAdjustedAmount", "A chained lifecycle receipt must bind its cumulative economic adjustment from the root receipt.");
            }
          } else {
            assertSameCurrency(issues, [
              { currency: total.currency, path: "$.receipt.economics.totalAuthorized.currency" },
              { currency: cumulativeAdjusted.currency, path: "$.receipt.correction.cumulativeAdjustedAmount.currency" },
            ]);
            if (cumulativeAdjusted.amount > total.amount) {
              issue(issues, "CORRECTION_CUMULATIVE_EXCEEDED", "$.receipt.correction.cumulativeAdjustedAmount", "Cumulative lifecycle adjustments cannot exceed the root economic total.");
            }
            if (lineageContext) {
              const predecessorCorrection = record(lineageContext.receipt.correction);
              const predecessorCumulative = predecessorCorrection
                ? money(predecessorCorrection.cumulativeAdjustedAmount)
                : { amount: 0n, currency: total.currency, network: undefined };
              if (!predecessorCumulative) {
                issue(issues, "CORRECTION_PREDECESSOR_CUMULATIVE_INVALID", "$.receipt.correction.predecessorReceiptId", "The predecessor does not bind the cumulative adjustment required to verify this successor.");
              } else {
                const contributesToAdjustedTotal =
                  eventType === "refund" ||
                  eventType === "reversal" ||
                  (eventType === "dispute" && correction.resolution === "APPLIED") ||
                  (eventType === "correction" && scope !== "NOT_APPLICABLE" && correction.resolution === "APPLIED");
                const signedAdjustment = (
                  (source?.type === "STRIPE_PAYMENT_ADJUSTMENT" && source.economicDirection === "CREDIT") ||
                  source?.type === "SERVICE_CREDIT_FUNDING_RESTORATION"
                )
                  ? -adjustment.amount
                  : adjustment.amount;
                const expectedCumulative = predecessorCumulative.amount +
                  (contributesToAdjustedTotal ? signedAdjustment : 0n);
                if (
                  predecessorCumulative.currency !== cumulativeAdjusted.currency ||
                  expectedCumulative < 0n ||
                  expectedCumulative !== cumulativeAdjusted.amount
                ) {
                  issue(issues, "CORRECTION_CUMULATIVE_MISMATCH", "$.receipt.correction.cumulativeAdjustedAmount", "The signed cumulative adjustment must equal the predecessor cumulative amount plus this event's economic effect.");
                }
                if (expectedCumulative > total.amount) {
                  issue(issues, "CORRECTION_CUMULATIVE_EXCEEDED", "$.receipt.correction.cumulativeAdjustedAmount", "Chained lifecycle adjustments cannot exceed the root economic total.");
                }
              }
            }
          }
        }
        const settlementState = string(economics.settlement);
        const correctionResolution = string(correction?.resolution);
        const aggregateFullyAdjusted = cumulativeAdjusted
          ? cumulativeAdjusted.amount === total.amount
          : correction.scope === "FULL";
        if (
          eventType === "refund" &&
          ((aggregateFullyAdjusted && settlementState !== "REFUNDED") ||
            (!aggregateFullyAdjusted && settlementState !== "PARTIALLY_REFUNDED"))
        ) {
          issue(issues, "CORRECTION_SETTLEMENT_MISMATCH", "$.receipt.economics.settlement", "A refund receipt must declare refunded or partially refunded settlement.");
        }
        if (eventType === "refund" && correctionResolution !== "APPLIED" && correctionResolution !== "RESOLVED") {
          issue(issues, "CORRECTION_RESOLUTION_MISMATCH", "$.receipt.correction.resolution", "A refund receipt may describe only an applied or resolved provider refund.");
        }
        if (
          eventType === "reversal" &&
          ((aggregateFullyAdjusted && settlementState !== "REVERSED") ||
            (!aggregateFullyAdjusted && settlementState !== "PARTIALLY_REVERSED"))
        ) {
          issue(issues, "CORRECTION_SETTLEMENT_MISMATCH", "$.receipt.economics.settlement", "A reversal receipt must distinguish partial reversal from full reversal.");
        }
        if (eventType === "reversal" && correctionResolution !== "APPLIED" && correctionResolution !== "RESOLVED") {
          issue(issues, "CORRECTION_RESOLUTION_MISMATCH", "$.receipt.correction.resolution", "A reversal receipt may describe only an applied or resolved provider reversal.");
        }
        if (eventType === "dispute" && settlementState !== "DISPUTED" && settlementState !== "SETTLED") {
          issue(issues, "CORRECTION_SETTLEMENT_MISMATCH", "$.receipt.economics.settlement", "A dispute receipt must declare disputed or still-settled economics.");
        }
        if (
          eventType === "dispute" &&
          ((settlementState === "DISPUTED" && correctionResolution !== "OPEN" && correctionResolution !== "APPLIED") ||
            (settlementState === "SETTLED" && correctionResolution !== "RESOLVED" && correctionResolution !== "REJECTED"))
        ) {
          issue(issues, "CORRECTION_RESOLUTION_MISMATCH", "$.receipt.correction.resolution", "Dispute resolution must agree with whether the signed economics remain disputed or settled.");
        }
        if (
          eventType === "correction" &&
          (
            (source?.type === "STRIPE_PAYMENT_ADJUSTMENT" && source.economicDirection === "CREDIT") ||
            source?.type === "SERVICE_CREDIT_FUNDING_RESTORATION"
          ) &&
          cumulativeAdjusted &&
          (
            (cumulativeAdjusted.amount === 0n && settlementState !== "SETTLED") ||
            (cumulativeAdjusted.amount > 0n && settlementState !== "PARTIALLY_REFUNDED" && settlementState !== "PARTIALLY_REVERSED")
          )
        ) {
          issue(issues, "CORRECTION_SETTLEMENT_MISMATCH", "$.receipt.economics.settlement", "A provider restoration must declare settled economics only after the signed cumulative adjustment reaches zero; otherwise it must remain explicitly partial.");
        }
      }
    } else if (correction) {
      issue(issues, "UNEXPECTED_CORRECTION_DETAILS", "$.receipt.correction", "Only typed correction lifecycle events may carry correction details.");
    }
  }

  return { valid: issues.length === 0, issues };
}
