import { merTimestamp } from "./time.js";
import {
  createHash,
  createPublicKey,
  verify as verifySignature,
  type JsonWebKey as NodeJsonWebKey,
} from "node:crypto";
import {
  verifyMerSemanticIntegrity,
  type MerIntegrityIssue,
  type MerKeyStatusEvent,
  type MerLineageContext,
} from "./integrity.js";

export const MER_DRAFT_VERSION = "0.1.0-draft";
export const MER_CONTRACT_VERSION = "2026-09-02.mer-draft-0.1-integrity-3";
export const MER_MAX_INPUT_BYTES = 65_536;
export type MerTrustedVerificationKey = {
  keyId: string;
  verificationMethod: string;
  publicJwk: NodeJsonWebKey & { kid?: string };
  environment: "SANDBOX" | "TEST" | "PRODUCTION";
  issuerId?: string;
  keyLifecycle: ReadonlyArray<MerKeyStatusEvent>;
};

type JsonSchema = {
  type?: "object" | "array" | "string" | "integer" | "boolean";
  const?: unknown;
  enum?: ReadonlyArray<unknown>;
  format?: "date-time" | "uri";
  pattern?: string;
  minimum?: number;
  minItems?: number;
  maxItems?: number;
  required?: ReadonlyArray<string>;
  properties?: Record<string, JsonSchema>;
  items?: JsonSchema;
  oneOf?: ReadonlyArray<JsonSchema>;
  additionalProperties?: boolean;
};

const moneyAmountSchema: JsonSchema = {
  type: "string",
  pattern: "^(0|[1-9][0-9]*)(\\.[0-9]{1,18})?$",
};

const moneySchema = {
  type: "object",
  additionalProperties: false,
  required: ["amount", "currency"],
  properties: {
    amount: moneyAmountSchema,
    currency: { type: "string", pattern: "^[A-Z0-9]{2,12}$" },
    network: { type: "string", pattern: "^[a-z0-9-]{1,32}$" },
  },
} satisfies JsonSchema;

export const merEnvelopeSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://axiomrelay.io/schemas/mer/receipt-0.1.schema.json",
  title: "Machine Economic Receipt Draft 0.1 envelope",
  description:
    "Portable receipt envelope linking a scoped economic lifecycle event to exact economics, evidence hashes, privacy mode, lineage, and an environment-bound Ed25519 proof.",
  type: "object",
  additionalProperties: false,
  required: ["receipt", "proof"],
  properties: {
    receipt: {
      type: "object",
      additionalProperties: false,
      required: [
        "specVersion",
        "receiptId",
        "issuedAt",
        "issuer",
        "subject",
        "event",
        "economics",
        "evidence",
        "privacy",
        "lineage",
      ],
      properties: {
        specVersion: { const: MER_DRAFT_VERSION },
        receiptId: { type: "string", pattern: "^mer_[A-Za-z0-9_-]{3,120}$" },
        issuedAt: { type: "string", format: "date-time" },
        issuer: {
          type: "object",
          additionalProperties: false,
          required: ["id", "keyId"],
          properties: {
            id: { type: "string", pattern: "^[a-z0-9.-]{2,120}$" },
            keyId: { type: "string", pattern: "^[A-Za-z0-9._-]{3,160}$" },
          },
        },
        subject: {
          type: "object",
          additionalProperties: false,
          required: ["serviceId", "serviceVersion", "providerId"],
          properties: {
            serviceId: { type: "string", pattern: "^[A-Za-z0-9._-]{3,160}$" },
            serviceVersion: { type: "string", pattern: "^[A-Za-z0-9._-]{1,80}$" },
            providerId: { type: "string", pattern: "^[A-Za-z0-9._-]{2,120}$" },
          },
        },
        event: {
          type: "object",
          additionalProperties: false,
          required: ["type", "status", "occurredAt", "sequence"],
          properties: {
            type: {
              enum: [
                "intent",
                "quote",
                "authorization",
                "execution",
                "settlement",
                "fulfillment",
                "aftercare",
                "correction",
                "refund",
                "reversal",
                "dispute",
                "replacement",
                "revocation",
              ],
            },
            status: { type: "string", pattern: "^[a-z][a-z0-9_]{1,63}$" },
            occurredAt: { type: "string", format: "date-time" },
            sequence: { type: "integer", minimum: 1 },
          },
        },
        economics: {
          type: "object",
          additionalProperties: false,
          required: ["payerRole", "principal", "axiomRelayFee", "totalAuthorized"],
          properties: {
            payerRole: { type: "string", pattern: "^[a-z][a-z0-9_]{1,63}$" },
            principal: {
              ...moneySchema,
              required: ["amount", "currency", "recipientRole"],
              properties: {
                ...moneySchema.properties,
                recipientRole: { type: "string", pattern: "^[a-z][a-z0-9_]{1,63}$" },
              },
            },
            axiomRelayFee: {
              ...moneySchema,
              required: ["amount", "currency", "status"],
              properties: {
                ...moneySchema.properties,
                status: { enum: ["charged", "waived_first_party", "sponsored"] },
              },
            },
            otherFees: {
              type: "array",
              maxItems: 32,
              items: moneySchema,
            },
            totalAuthorized: moneySchema,
            settlement: {
              enum: [
                "NOT_APPLICABLE",
                "SIMULATED",
                "SETTLED",
                "DISPUTED",
                "PARTIALLY_REFUNDED",
                "PARTIALLY_REVERSED",
                "REFUNDED",
                "REVERSED",
              ],
            },
            paymentFunding: {
              oneOf: [
                {
                  type: "object",
                  additionalProperties: false,
                  required: [
                    "model",
                    "processor",
                    "environment",
                    "chargedAmount",
                    "servicePrice",
                    "serviceCreditGranted",
                    "creditAccountId",
                    "transferable",
                    "cashRedeemable",
                  ],
                  properties: {
                    model: { const: "STRIPE_MINIMUM_WITH_SERVICE_CREDIT" },
                    processor: { const: "stripe" },
                    environment: { enum: ["TEST", "PRODUCTION"] },
                    chargedAmount: moneySchema,
                    servicePrice: moneySchema,
                    serviceCreditGranted: moneySchema,
                    creditAccountId: { type: "string", pattern: "^credit_[a-f0-9]{32}$" },
                    transferable: { const: false },
                    cashRedeemable: { const: false },
                  },
                },
                {
                  type: "object",
                  additionalProperties: false,
                  required: [
                    "model",
                    "provider",
                    "environment",
                    "debitedAmount",
                    "creditAccountId",
                    "transferable",
                    "cashRedeemable",
                  ],
                  properties: {
                    model: { const: "SERVICE_CREDIT_REDEMPTION" },
                    provider: { const: "axiom" },
                    environment: { enum: ["TEST", "PRODUCTION"] },
                    debitedAmount: moneySchema,
                    creditAccountId: { type: "string", pattern: "^credit_[a-f0-9]{32}$" },
                    transferable: { const: false },
                    cashRedeemable: { const: false },
                  },
                },
              ],
            },
          },
        },
        commerce: {
          type: "object",
          additionalProperties: false,
          required: [
            "merchantRef",
            "merchantType",
            "pricing",
            "grossEconomicVolume",
            "providerPrincipal",
            "axiomRevenue",
            "settlement",
            "activityClass",
            "realMoneyMoved",
          ],
          properties: {
            orderId: { type: "string", pattern: "^ord_[a-f0-9]{32}$" },
            quoteId: { type: "string", pattern: "^q_[a-f0-9]{32}$" },
            expectationId: { type: "string", pattern: "^expect_[a-f0-9]{32}$" },
            executionId: { type: "string", pattern: "^job_[a-f0-9]{32}$" },
            merchantRef: { type: "string", pattern: "^merchant\\.[a-z0-9._-]{2,120}$" },
            merchantType: {
              enum: ["AXIOM_FIRST_PARTY", "THIRD_PARTY_PROVIDER", "ENTERPRISE_TENANT", "AGENT_PROVIDER"],
            },
            pricing: moneySchema,
            grossEconomicVolume: moneySchema,
            providerPrincipal: moneySchema,
            axiomRevenue: moneySchema,
            settlement: {
              type: "object",
              additionalProperties: false,
              required: ["amount", "asset", "network", "decimals", "profileRef", "methodRef", "recipient", "paymentReference", "finality"],
              properties: {
                amount: moneyAmountSchema,
                asset: { type: "string", pattern: "^[A-Z0-9]{2,12}$" },
                network: { type: "string", pattern: "^[a-z0-9:-]{2,40}$" },
                decimals: { type: "integer", minimum: 0 },
                profileRef: { type: "string", pattern: "^[A-Za-z0-9._-]{3,120}$" },
                methodRef: { type: "string", pattern: "^[A-Za-z0-9._-]{3,160}$" },
                recipient: { type: "string", pattern: "^[A-Za-z0-9:._-]{3,200}$" },
                paymentReference: { type: "string", pattern: "^[A-Za-z0-9:._-]{3,200}$" },
                finality: { enum: ["PENDING", "CONFIRMED", "PARTIALLY_REVERSED", "REVERSED"] },
              },
            },
            activityClass: { enum: ["INTERNAL_TEST", "QUALIFICATION", "FIRST_PARTY_PRODUCTION", "EXTERNAL"] },
            realMoneyMoved: { type: "boolean" },
            commercialPolicy: {
              type: "object",
              additionalProperties: false,
              required: ["termsPolicyRef", "refundPolicyRef", "acceptedAt"],
              properties: {
                termsPolicyRef: { type: "string", pattern: "^terms\\.axiom\\.[A-Za-z0-9._-]{3,160}$" },
                refundPolicyRef: { type: "string", pattern: "^refund\\.axiom\\.[A-Za-z0-9._-]{3,160}$" },
                acceptedAt: { type: "string", format: "date-time" },
              },
            },
          },
        },
        correction: {
          type: "object",
          additionalProperties: false,
          required: [
            "type",
            "reasonCode",
            "rootReceiptId",
            "predecessorReceiptId",
            "predecessorDigest",
            "amount",
            "scope",
            "resolution",
          ],
          properties: {
            type: { enum: ["correction", "refund", "reversal", "dispute", "replacement", "revocation"] },
            reasonCode: { type: "string", pattern: "^[A-Z][A-Z0-9_]{2,95}$" },
            rootReceiptId: { type: "string", pattern: "^mer_[A-Za-z0-9_-]{3,120}$" },
            predecessorReceiptId: { type: "string", pattern: "^mer_[A-Za-z0-9_-]{3,120}$" },
            predecessorDigest: { type: "string", pattern: "^sha256:[a-f0-9]{64}$" },
            amount: moneySchema,
            cumulativeAdjustedAmount: moneySchema,
            scope: { enum: ["PARTIAL", "FULL", "NOT_APPLICABLE"] },
            resolution: { enum: ["OPEN", "APPLIED", "RESOLVED", "SUPERSEDED", "REJECTED"] },
            providerReference: { type: "string", pattern: "^[A-Za-z0-9:._-]{3,200}$" },
            source: {
              oneOf: [
                {
                  type: "object",
                  additionalProperties: false,
                  required: ["type", "correctionId", "lotId", "allocationId", "fundingReversalEventId"],
                  properties: {
                    type: { const: "SERVICE_CREDIT_FUNDING_REVERSAL" },
                    correctionId: { type: "string", pattern: "^crcor_[a-f0-9]{32}$" },
                    lotId: { type: "string", pattern: "^lot_[a-f0-9]{32}$" },
                    allocationId: { type: "string", pattern: "^alloc_[a-f0-9]{32}$" },
                    fundingReversalEventId: { type: "string", pattern: "^crevt_[a-f0-9]{32}$" },
                  },
                },
                {
                  type: "object",
                  additionalProperties: false,
                  required: ["type", "restorationId", "correctionId", "lotId", "allocationId", "fundingRestorationEventId"],
                  properties: {
                    type: { const: "SERVICE_CREDIT_FUNDING_RESTORATION" },
                    restorationId: { type: "string", pattern: "^crrst_[a-f0-9]{32}$" },
                    correctionId: { type: "string", pattern: "^crcor_[a-f0-9]{32}$" },
                    lotId: { type: "string", pattern: "^lot_[a-f0-9]{32}$" },
                    allocationId: { type: "string", pattern: "^alloc_[a-f0-9]{32}$" },
                    fundingRestorationEventId: { type: "string", pattern: "^crevt_[a-f0-9]{32}$" },
                  },
                },
                {
                  type: "object",
                  additionalProperties: false,
                  required: ["type", "queueId", "adjustmentId", "providerEventId", "providerEventType", "rawPayloadHash", "economicDirection", "sourceAmount"],
                  properties: {
                    type: { const: "STRIPE_PAYMENT_ADJUSTMENT" },
                    queueId: { type: "string", pattern: "^pmlq_[a-f0-9]{32}$" },
                    adjustmentId: { type: "string", pattern: "^adj_[a-f0-9]{32}$" },
                    providerEventId: { type: "string", pattern: "^[A-Za-z0-9._:-]{3,255}$" },
                    providerEventType: { type: "string", pattern: "^[a-z0-9._]{3,120}$" },
                    rawPayloadHash: { type: "string", pattern: "^sha256:[a-f0-9]{64}$" },
                    economicDirection: { enum: ["DEBIT", "CREDIT"] },
                    sourceAmount: moneySchema,
                  },
                },
              ],
            },
          },
        },
        evidence: {
          type: "object",
          additionalProperties: false,
          required: ["inputHash", "resultHash"],
          properties: {
            inputHash: { type: "string", pattern: "^sha256:[a-f0-9]{64}$" },
            resultHash: { type: "string", pattern: "^sha256:[a-f0-9]{64}$" },
          },
        },
        privacy: {
          type: "object",
          additionalProperties: false,
          required: ["intentMode"],
          properties: {
            intentMode: {
              enum: ["public_synthetic", "hash_only", "selective", "encrypted", "private_managed"],
            },
          },
        },
        lineage: {
          type: "object",
          additionalProperties: false,
          required: ["previousEventIds"],
          properties: {
            previousEventIds: {
              type: "array",
              minItems: 0,
              maxItems: 32,
              items: { type: "string", pattern: "^mer_[A-Za-z0-9_-]{3,120}$" },
            },
          },
        },
      },
    },
    proof: {
      type: "object",
      additionalProperties: false,
      required: ["type", "cryptosuite", "created", "verificationMethod", "proofValue"],
      properties: {
        type: { const: "DataIntegrityProof" },
        cryptosuite: { const: "eddsa-jcs-2022" },
        created: { type: "string", format: "date-time" },
        verificationMethod: { type: "string", format: "uri" },
        proofValue: { type: "string", pattern: "^[A-Za-z0-9_-]{86}$" },
      },
    },
  },
} as const satisfies JsonSchema & Record<string, unknown>;

type VerificationIssue = MerIntegrityIssue;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateSchema(
  schema: JsonSchema,
  value: unknown,
  path: string,
  issues: VerificationIssue[],
) {
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((candidate) => {
      const candidateIssues: VerificationIssue[] = [];
      validateSchema(candidate, value, path, candidateIssues);
      return candidateIssues.length === 0;
    });
    if (matches.length !== 1) {
      issues.push({
        code: "SCHEMA_ONE_OF",
        path,
        message: matches.length === 0
          ? "Value does not match any allowed schema."
          : "Value matches more than one mutually exclusive schema.",
      });
    }
    return;
  }

  if (schema.const !== undefined && value !== schema.const) {
    issues.push({ code: "SCHEMA_CONST", path, message: `Must equal ${JSON.stringify(schema.const)}.` });
    return;
  }

  if (schema.enum && !schema.enum.includes(value)) {
    issues.push({ code: "SCHEMA_ENUM", path, message: "Value is not in the allowed set." });
    return;
  }

  if (schema.type === "object") {
    if (!isRecord(value)) {
      issues.push({ code: "SCHEMA_TYPE", path, message: "Must be an object." });
      return;
    }

    for (const requiredKey of schema.required ?? []) {
      if (!(requiredKey in value)) {
        issues.push({ code: "SCHEMA_REQUIRED", path: `${path}.${requiredKey}`, message: "Field is required." });
      }
    }

    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!schema.properties || !(key in schema.properties)) {
          issues.push({ code: "SCHEMA_ADDITIONAL_PROPERTY", path: `${path}.${key}`, message: "Field is not allowed." });
        }
      }
    }

    for (const [key, childSchema] of Object.entries(schema.properties ?? {})) {
      if (key in value) {
        validateSchema(childSchema, value[key], `${path}.${key}`, issues);
      }
    }
    return;
  }

  if (schema.type === "array") {
    if (!Array.isArray(value)) {
      issues.push({ code: "SCHEMA_TYPE", path, message: "Must be an array." });
      return;
    }
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      issues.push({ code: "SCHEMA_MIN_ITEMS", path, message: `Must contain at least ${schema.minItems} items.` });
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      issues.push({ code: "SCHEMA_MAX_ITEMS", path, message: `Must contain no more than ${schema.maxItems} items.` });
    }
    value.forEach((item, index) => {
      if (schema.items) validateSchema(schema.items, item, `${path}[${index}]`, issues);
    });
    return;
  }

  if (schema.type === "string") {
    if (typeof value !== "string") {
      issues.push({ code: "SCHEMA_TYPE", path, message: "Must be a string." });
      return;
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      issues.push({ code: "SCHEMA_PATTERN", path, message: "String does not match the required format." });
    }
    if (schema.format === "date-time" && merTimestamp(value) === null) {
      issues.push({ code: "SCHEMA_FORMAT", path, message: "Must be an ISO 8601 date-time." });
    }
    if (schema.format === "uri") {
      try {
        new URL(value);
      } catch {
        issues.push({ code: "SCHEMA_FORMAT", path, message: "Must be an absolute URI." });
      }
    }
    return;
  }

  if (schema.type === "integer") {
    if (!Number.isInteger(value)) {
      issues.push({ code: "SCHEMA_TYPE", path, message: "Must be an integer." });
      return;
    }
    if (schema.minimum !== undefined && (value as number) < schema.minimum) {
      issues.push({ code: "SCHEMA_MINIMUM", path, message: `Must be at least ${schema.minimum}.` });
    }
  }

  if (schema.type === "boolean" && typeof value !== "boolean") {
    issues.push({ code: "SCHEMA_TYPE", path, message: "Must be a boolean." });
  }
}

export function validateMerDocumentSchema(value: unknown) {
  const issues: VerificationIssue[] = [];
  validateSchema(merEnvelopeSchema, value, "$", issues);
  return { valid: issues.length === 0, issues };
}

export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Canonical JSON cannot contain non-finite numbers.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`)
      .join(",")}}`;
  }
  throw new Error("Canonical JSON accepts only JSON-compatible values.");
}

export function verifyMerEnvelopeWithTrustedKey(
  value: unknown,
  trustedKey: MerTrustedVerificationKey | null,
  options: { verificationTime?: string; predecessorEnvelope?: unknown } = {},
) {
  const issues: VerificationIssue[] = [];
  validateSchema(merEnvelopeSchema, value, "$", issues);

  let canonicalDigest: string | null = null;
  let signatureValid = false;
  let supportedIssuer = false;

  if (isRecord(value) && isRecord(value.receipt) && isRecord(value.proof)) {
    const keyId = isRecord(value.receipt.issuer) ? value.receipt.issuer.keyId : null;
    supportedIssuer = Boolean(
      trustedKey &&
      keyId === trustedKey.keyId &&
      value.proof.verificationMethod === trustedKey.verificationMethod &&
      trustedKey.publicJwk.kid === trustedKey.keyId &&
      trustedKey.publicJwk.kty === "OKP" &&
      trustedKey.publicJwk.crv === "Ed25519" &&
      trustedKey.publicJwk.alg === "EdDSA" &&
      (!trustedKey.issuerId || (isRecord(value.receipt.issuer) && value.receipt.issuer.id === trustedKey.issuerId)),
    );

    if (!supportedIssuer) {
      issues.push({
        code: "UNSUPPORTED_VERIFICATION_METHOD",
        path: "$.proof.verificationMethod",
        message: "The receipt does not use a key in the explicitly configured trusted verification registry.",
      });
    }

    if (
      supportedIssuer &&
      trustedKey &&
      issues.every((issue) => !issue.code.startsWith("SCHEMA_"))
    ) {
      const commerce = isRecord(value.receipt.commerce) ? value.receipt.commerce : null;
      const economics = isRecord(value.receipt.economics) ? value.receipt.economics : null;
      const paymentFunding = economics && isRecord(economics.paymentFunding)
        ? economics.paymentFunding
        : null;

      if (trustedKey.environment === "SANDBOX" || trustedKey.environment === "TEST") {
        if (commerce && commerce.activityClass !== "INTERNAL_TEST") {
          issues.push({
            code: "KEY_ENVIRONMENT_CLAIM_MISMATCH",
            path: "$.receipt.commerce.activityClass",
            message: "A TEST or sandbox signing key may only authenticate INTERNAL_TEST commerce.",
          });
        }
        if (commerce && commerce.realMoneyMoved !== false) {
          issues.push({
            code: "KEY_ENVIRONMENT_CLAIM_MISMATCH",
            path: "$.receipt.commerce.realMoneyMoved",
            message: "A TEST or sandbox signing key cannot authenticate real-money movement.",
          });
        }
        if (paymentFunding && paymentFunding.environment !== "TEST") {
          issues.push({
            code: "KEY_ENVIRONMENT_CLAIM_MISMATCH",
            path: "$.receipt.economics.paymentFunding.environment",
            message: "A TEST or sandbox signing key may only authenticate TEST payment funding.",
          });
        }
      }

      if (trustedKey.environment === "PRODUCTION") {
        if (commerce && commerce.activityClass === "INTERNAL_TEST") {
          issues.push({
            code: "KEY_ENVIRONMENT_CLAIM_MISMATCH",
            path: "$.receipt.commerce.activityClass",
            message: "A production signing key cannot authenticate INTERNAL_TEST commerce.",
          });
        }
        if (paymentFunding && paymentFunding.environment !== "PRODUCTION") {
          issues.push({
            code: "KEY_ENVIRONMENT_CLAIM_MISMATCH",
            path: "$.receipt.economics.paymentFunding.environment",
            message: "A production signing key may only authenticate PRODUCTION payment funding.",
          });
        }
        if (commerce?.realMoneyMoved === true && !isRecord(commerce.commercialPolicy)) {
          issues.push({
            code: "PRODUCTION_COMMERCIAL_POLICY_MISSING",
            path: "$.receipt.commerce.commercialPolicy",
            message: "A production real-money receipt must bind the accepted terms and refund policy.",
          });
        }
      }
    }

    let lineageContext: MerLineageContext | null = null;
    if (options.predecessorEnvelope !== undefined) {
      const predecessor = isRecord(options.predecessorEnvelope) && isRecord(options.predecessorEnvelope.receipt)
        ? options.predecessorEnvelope.receipt
        : isRecord(options.predecessorEnvelope)
          ? options.predecessorEnvelope
          : null;
      if (predecessor) {
        try {
          lineageContext = {
            canonicalDigest: `sha256:${createHash("sha256").update(canonicalizeJson(predecessor)).digest("hex")}`,
            receipt: predecessor,
          };
        } catch {
          lineageContext = null;
        }
      }
    }

    if (trustedKey && issues.every((issue) => !issue.code.startsWith("SCHEMA_"))) {
      issues.push(...verifyMerSemanticIntegrity(
        value,
        trustedKey.keyLifecycle,
        options.verificationTime,
        lineageContext,
      ).issues);
    }

    if (issues.every((issue) => !issue.code.startsWith("SCHEMA_"))) {
      try {
        const canonical = canonicalizeJson(value.receipt);
        canonicalDigest = createHash("sha256").update(canonical).digest("hex");
        if (supportedIssuer && trustedKey && typeof value.proof.proofValue === "string") {
          const publicKey = createPublicKey({ key: trustedKey.publicJwk, format: "jwk" });
          signatureValid = verifySignature(
            null,
            Buffer.from(canonical),
            publicKey,
            Buffer.from(value.proof.proofValue, "base64url"),
          );
        }
      } catch {
        issues.push({
          code: "CANONICALIZATION_FAILED",
          path: "$.receipt",
          message: "The receipt could not be canonicalized safely.",
        });
      }
    }
  }

  if (supportedIssuer && !signatureValid && issues.every((issue) => !issue.code.startsWith("SCHEMA_"))) {
    issues.push({
      code: "SIGNATURE_INVALID",
      path: "$.proof.proofValue",
      message: "The Ed25519 signature does not match the canonical receipt payload.",
    });
  }

  return {
    valid: issues.length === 0 && signatureValid,
    draft: true,
    productionSigning:
      trustedKey?.environment === "PRODUCTION" &&
      issues.length === 0 &&
      signatureValid,
    retained: false,
    checks: {
      schema: issues.every((issue) => !issue.code.startsWith("SCHEMA_")),
      supportedIssuer,
      signature: signatureValid,
      canonicalDigest: canonicalDigest ? `sha256:${canonicalDigest}` : null,
      keyLifecycle: !issues.some((issue) => issue.code.startsWith("KEY_")),
      proofBinding: !issues.some((issue) => issue.code.startsWith("PROOF_") || issue.code === "EVENT_AFTER_ISSUANCE"),
      economicConsistency: !issues.some((issue) =>
        issue.code.startsWith("ECONOMIC_") ||
        issue.code.startsWith("COMMERCE_") ||
        issue.code.startsWith("FUNDING_") ||
        issue.code.startsWith("SETTLEMENT_")),
      correctionLineage: !issues.some((issue) =>
        issue.code.startsWith("CORRECTION_") || issue.code === "UNEXPECTED_CORRECTION_DETAILS"),
    },
    issues,
  };
}
