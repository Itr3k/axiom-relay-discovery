#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { parseMerJson, verifyMer, type MerTrustedVerificationKey } from "./index.js";

const [command, receiptPath, trustPath, at] = process.argv.slice(2);
if (command !== "verify" || !receiptPath || !trustPath) {
  process.stderr.write("Usage: axiom-mer verify RECEIPT.json TRUST.json [VERIFICATION_TIME]\n");
  process.exitCode = 2;
} else {
  try {
    const [receiptText, trustText] = await Promise.all([readFile(receiptPath, "utf8"), readFile(trustPath, "utf8")]);
    const receipt = parseMerJson(receiptText);
    const trustedKeys = parseMerJson(trustText) as MerTrustedVerificationKey[];
    const result = verifyMer(receipt, { trustedKeys, verificationTime: at });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = result.valid ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "MER verification failed."}\n`);
    process.exitCode = 2;
  }
}
