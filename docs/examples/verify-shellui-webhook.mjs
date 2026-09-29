#!/usr/bin/env node
/**
 * Reference verifier for Shellui webhook signatures (Standard Webhooks style).
 * Usage: node verify-shellui-webhook.mjs <secret> <raw-body-file>
 */
import crypto from "node:crypto";
import fs from "node:fs";

const MAX_AGE_SECONDS = 300;

function signingKey(secret) {
  const trimmed = secret.trim();
  if (trimmed.startsWith("whsec_")) {
    return Buffer.from(trimmed.slice("whsec_".length), "base64");
  }
  return Buffer.from(trimmed, "utf8");
}

function verify({ secret, webhookId, timestamp, signatureHeader, rawBody }) {
  const prefix = "v1,";
  if (!signatureHeader.startsWith(prefix)) {
    return false;
  }
  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (!Number.isFinite(age) || age > MAX_AGE_SECONDS) {
    return false;
  }
  const signed = Buffer.concat([
    Buffer.from(`${webhookId}.${timestamp}.`, "utf8"),
    rawBody,
  ]);
  const expected = crypto.createHmac("sha256", signingKey(secret)).update(signed).digest();
  const got = Buffer.from(signatureHeader.slice(prefix.length), "base64");
  return got.length === expected.length && crypto.timingSafeEqual(got, expected);
}

const secret = process.argv[2];
const bodyPath = process.argv[3];
const webhookId = process.env.WEBHOOK_ID || "";
const timestamp = process.env.WEBHOOK_TIMESTAMP || "";
const signature = process.env.WEBHOOK_SIGNATURE || "";

if (!secret || !bodyPath) {
  console.error("usage: node verify-shellui-webhook.mjs <secret> <raw-body-file>");
  process.exit(2);
}

const rawBody = fs.readFileSync(bodyPath);
const ok = verify({
  secret,
  webhookId,
  timestamp,
  signatureHeader: signature,
  rawBody,
});
process.exit(ok ? 0 : 1);
