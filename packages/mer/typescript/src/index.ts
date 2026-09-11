import { createHash } from "node:crypto";
import {
  canonicalizeJson as canonicalizeUnchecked,
  MER_MAX_INPUT_BYTES,
  verifyMerEnvelopeWithTrustedKey,
  type MerTrustedVerificationKey,
} from "./core.js";

export { MER_DRAFT_VERSION, MER_CONTRACT_VERSION, MER_MAX_INPUT_BYTES, merEnvelopeSchema } from "./core.js";
export type { MerTrustedVerificationKey } from "./core.js";
export type { MerKeyStatusEvent, MerIntegrityIssue, MerKeyStatus } from "./integrity.js";

export const MER_KIT_VERSION = "0.1.0";
export type MerVerification = ReturnType<typeof verifyMerEnvelopeWithTrustedKey>;
export type MerVerificationOptions = {
  trustedKeys: ReadonlyArray<MerTrustedVerificationKey>;
  verificationTime?: string;
  predecessorEnvelope?: unknown;
};
export type MerReceipt = {
  specVersion: string;
  receiptId: string;
  issuedAt: string;
  issuer: { id: string; keyId: string };
  subject: { serviceId: string; serviceVersion: string; providerId: string };
  event: { type: string; status: string; occurredAt: string; sequence: number };
  economics: Record<string, unknown>;
  evidence: { inputHash: string; resultHash: string };
  privacy: { intentMode: string };
  lineage: { previousEventIds: string[] };
  correction?: Record<string, unknown>;
  commerce?: Record<string, unknown>;
};
export type MerEnvelope = {
  receipt: MerReceipt;
  proof: { type: "DataIntegrityProof"; cryptosuite: "eddsa-jcs-2022"; created: string; verificationMethod: string; proofValue: string };
};

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** MER's numeric fields are safe integers; monetary amounts are decimal strings. */
function assertJson(value: unknown, depth = 0, seen = new Set<object>(), budget = { nodes: 0 }): void {
  if (++budget.nodes > 8192 || depth > 32) throw new Error("MER JSON exceeds its structural limit.");
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("MER JSON numbers must be safe integers; use decimal strings for amounts.");
    return;
  }
  if (typeof value === "string") {
    if (value.length > MER_MAX_INPUT_BYTES || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) {
      throw new Error("MER JSON contains an oversized string or invalid Unicode.");
    }
    return;
  }
  if (typeof value !== "object" || seen.has(value)) throw new Error("MER accepts finite, acyclic JSON values only.");
  if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new Error("MER objects must be plain JSON objects.");
  }
  seen.add(value);
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (Array.isArray(value) && key === "length") continue;
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error("MER JSON cannot contain accessors or hidden properties.");
    assertJson(key, depth + 1, seen, budget);
    assertJson(descriptor.value, depth + 1, seen, budget);
  }
  if (Array.isArray(value) && Object.keys(value).length !== value.length) throw new Error("MER JSON cannot contain sparse arrays.");
  if (Object.getOwnPropertySymbols(value).length) throw new Error("MER JSON cannot contain symbols.");
  seen.delete(value);
}

export function canonicalizeJson(value: unknown): string {
  assertJson(value);
  const canonical = canonicalizeUnchecked(value);
  if (Buffer.byteLength(canonical, "utf8") > MER_MAX_INPUT_BYTES) throw new Error("A MER document may not exceed 65,536 bytes.");
  return canonical;
}

export function parseMerJson(text: string): unknown {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > MER_MAX_INPUT_BYTES) throw new Error("A MER document may not exceed 65,536 bytes.");
  const parsed: unknown = JSON.parse(text);
  canonicalizeJson(parsed);
  return parsed;
}

export function hashMerValue(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalizeJson(value), "utf8").digest("hex")}`;
}

function keyFor(envelope: unknown, keys: ReadonlyArray<MerTrustedVerificationKey>) {
  if (!Array.isArray(keys) || keys.length > 128) throw new Error("Configure at most 128 explicitly trusted keys.");
  const root = record(envelope) ? envelope : {};
  const receipt = record(root.receipt) ? root.receipt : {};
  const issuer = record(receipt.issuer) ? receipt.issuer : {};
  const proof = record(root.proof) ? root.proof : {};
  const matches = keys.filter((key) => key?.issuerId === issuer.id && key?.keyId === issuer.keyId && key?.verificationMethod === proof.verificationMethod);
  if (matches.length !== 1) return null;
  const key = matches[0];
  if (!key.issuerId || !["SANDBOX", "TEST", "PRODUCTION"].includes(key.environment) || !Array.isArray(key.keyLifecycle) || key.keyLifecycle.length > 128 || !key.keyLifecycle.every(record) || !record(key.publicJwk) || "d" in key.publicJwk || key.publicJwk.use !== "sig") return null;
  return key;
}

/** No network requests, telemetry, embedded-key trust, or private-key access. */
export function verifyMer(envelope: unknown, options: MerVerificationOptions): MerVerification {
  canonicalizeJson(envelope);
  if (options.predecessorEnvelope !== undefined) canonicalizeJson(options.predecessorEnvelope);
  return verifyMerEnvelopeWithTrustedKey(envelope, keyFor(envelope, options.trustedKeys), options);
}

/** Verify every supplied signature and the complete correction chain, without fetching missing parents. */
export function verifyMerChain(envelopes: ReadonlyArray<unknown>, options: Omit<MerVerificationOptions, "predecessorEnvelope">) {
  if (!Array.isArray(envelopes) || envelopes.length < 1 || envelopes.length > 64) throw new Error("A MER chain must contain between 1 and 64 envelopes.");
  const entries = new Map<string, unknown>();
  for (const envelope of envelopes) {
    canonicalizeJson(envelope);
    const receipt = record(envelope) && record(envelope.receipt) ? envelope.receipt : {};
    if (typeof receipt.receiptId !== "string" || entries.has(receipt.receiptId)) throw new Error("A MER chain requires distinct receipt identifiers.");
    entries.set(receipt.receiptId, envelope);
  }
  const results = new Map<string, MerVerification>();
  const visiting = new Set<string>();
  const visit = (id: string): MerVerification => {
    const cached = results.get(id);
    if (cached) return cached;
    if (visiting.has(id)) throw new Error("MER correction lineage contains a cycle.");
    visiting.add(id);
    const envelope = entries.get(id) as Record<string, unknown>;
    const receipt = envelope.receipt as Record<string, unknown>;
    const correction = record(receipt.correction) ? receipt.correction : null;
    const parentId = correction && typeof correction.predecessorReceiptId === "string" ? correction.predecessorReceiptId : null;
    const parent = parentId ? entries.get(parentId) : undefined;
    const result = verifyMer(envelope, { ...options, predecessorEnvelope: parent });
    if (parentId && parent !== undefined && !visit(parentId).valid) {
      result.valid = false;
      result.productionSigning = false;
      result.checks.correctionLineage = false;
      result.issues.push({ code: "CORRECTION_PREDECESSOR_INVALID", path: "$.receipt.correction.predecessorReceiptId", message: "The predecessor does not have a valid trusted receipt chain." });
    }
    visiting.delete(id);
    results.set(id, result);
    return result;
  };
  const receipts = [...entries.keys()].map((receiptId) => ({ receiptId, ...visit(receiptId) }));
  return { valid: receipts.every((item) => item.valid), receipts };
}

/** The issuer supplies its signer (for example KMS); this library never provisions or stores keys. */
export async function signMerReceipt(
  receipt: MerReceipt,
  options: {
    trustedKey: MerTrustedVerificationKey;
    sign: (canonicalReceipt: Uint8Array) => Promise<Uint8Array> | Uint8Array;
    verificationTime?: string;
    predecessorEnvelope?: unknown;
  },
): Promise<MerEnvelope> {
  const snapshot = parseMerJson(canonicalizeJson(receipt)) as MerReceipt;
  const envelope: MerEnvelope = {
    receipt: snapshot,
    proof: { type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", created: snapshot.issuedAt, verificationMethod: options.trustedKey.verificationMethod, proofValue: "A".repeat(86) },
  };
  const verificationOptions = { trustedKeys: [options.trustedKey], verificationTime: options.verificationTime, predecessorEnvelope: options.predecessorEnvelope };
  const preliminary = verifyMer(envelope, verificationOptions);
  const invalid = preliminary.issues.filter((issue) => issue.code !== "SIGNATURE_INVALID");
  if (invalid.length) throw new Error(`Refusing to sign an invalid MER: ${invalid.map((issue) => issue.code).join(", ")}`);
  const signature = await options.sign(Buffer.from(canonicalizeJson(snapshot), "utf8"));
  if (!(signature instanceof Uint8Array) || signature.byteLength !== 64) throw new Error("The signer must return a 64-byte Ed25519 signature.");
  envelope.proof.proofValue = Buffer.from(signature).toString("base64url");
  if (!verifyMer(envelope, verificationOptions).valid) throw new Error("The returned signature does not verify against the configured issuer key.");
  return envelope;
}
