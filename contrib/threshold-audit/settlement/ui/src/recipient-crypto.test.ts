import { expect, it } from "vitest";
import { schnorr } from "@noble/curves/secp256k1.js";
import fixture from "./fixtures/sealed-disclosure.json";
import {
  assetGenerator,
  bytes,
  canonical,
  caseAuthorityKey,
  caseAuthoritySecret,
  freezeOrderDigest,
  signFreezeOrder,
  hex,
  newRecipientKey,
  unlockRecipientKey,
  recoverBundle,
  type DisclosureBundle,
} from "./recipient-crypto";
const bundle = () =>
  structuredClone(fixture.bundle) as unknown as DisclosureBundle;
it("recovers the exact native Python opening from recipient-encrypted guardian contributions", async () => {
  const outputs = await recoverBundle(
    bundle(),
    bytes(fixture.secret),
    "recipient",
  );
  expect(outputs).toHaveLength(1);
  expect(outputs[0]).toMatchObject({
    ...fixture.expected,
    verified_guardians: 2,
  });
});
it("derives the same Elements asset generators as native libsecp256k1", () => {
  for (const [asset, generator] of Object.entries(fixture.generators))
    expect(assetGenerator(asset)).toBe(generator);
});
it("rejects other recipients and private keys", async () => {
  await expect(
    recoverBundle(bundle(), bytes(fixture.secret), "someone-else"),
  ).rejects.toThrow(/not addressed/);
  await expect(
    recoverBundle(bundle(), bytes("00".repeat(31) + "01"), "recipient"),
  ).rejects.toThrow(/not addressed/);
});
it("rejects altered case scope and damaged signed ciphertexts", async () => {
  const changed = bundle();
  changed.outputs[0].output_index = 1;
  await expect(
    recoverBundle(changed, bytes(fixture.secret), "recipient"),
  ).rejects.toThrow(/approved case/);
  const damaged = bundle();
  const envelope = Object.values(damaged.outputs[0].sealed_partials)[0];
  envelope.ciphertext = "00" + envelope.ciphertext.slice(2);
  await expect(
    recoverBundle(damaged, bytes(fixture.secret), "recipient"),
  ).rejects.toThrow(/signature/);
});
it("rejects insufficient and duplicate guardian contributions", async () => {
  const short = bundle();
  delete short.outputs[0].sealed_partials["2"];
  await expect(
    recoverBundle(short, bytes(fixture.secret), "recipient"),
  ).rejects.toThrow(/quorum/);
  const duplicate = bundle();
  duplicate.outputs[0].sealed_partials["2"] =
    duplicate.outputs[0].sealed_partials["1"];
  await expect(
    recoverBundle(duplicate, bytes(fixture.secret), "recipient"),
  ).rejects.toThrow(/Duplicate/);
});
it("password-protects a recipient key and rejects another account or password", async () => {
  const key = await newRecipientKey("recipient", "fixture-only-password");
  const secret = await unlockRecipientKey(
    key,
    "recipient",
    "fixture-only-password",
  );
  expect(hex(secret)).toHaveLength(64);
  expect(key.ciphertext).not.toContain(hex(secret));
  secret.fill(0);
  await expect(
    unlockRecipientKey(key, "other", "fixture-only-password"),
  ).rejects.toThrow(/your account/);
  await expect(
    unlockRecipientKey(key, "recipient", "different-password"),
  ).rejects.toThrow();
  // Several real 210,000-round PBKDF2 derivations; slow on shared CI.
}, 20000);
it("produces the same canonical JSON as Python's json.dumps(ensure_ascii=True)", () => {
  // python3 -c 'json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)'
  expect(
    new TextDecoder().decode(
      canonical({ b: "x\x7f\u00e9\u{1F600}", a: [1, { z: true, y: null }] }),
    ),
  ).toBe('{"a":[1,{"y":null,"z":true}],"b":"x\\u007f\\u00e9\\ud83d\\ude00"}');
});

it("derives the regulator's order-signing key exactly as Python does", () => {
  // settlement/test_freezes.py checks the same vector and this signature.
  const recipient = new Uint8Array(32);
  recipient[31] = 1;
  const secret = caseAuthoritySecret(recipient);
  expect(hex(secret)).toBe(
    "23b8cc6122f8e30aec62f6cdb6d4262a17b74d621d42c2d4ffd3f407cf31df3f",
  );
  const key = caseAuthorityKey(secret);
  expect(key).toBe(
    "5d027bd59943981e1c762a33f03db253e6b403a1722a5905758348259852c4cb",
  );
  const order = {
    format: "concord-freeze-order-v1",
    kind: "freeze",
    id: "f1".repeat(16),
    genesis_hash: "cc".repeat(32),
    authority: "Regulator",
    authority_key: key,
    case_reference: "case-7",
    reason: "Proceeds of a reported theft",
    issued_at: 1795000000,
    outputs: [{ txid: "ab".repeat(32), vout: 1 }],
  };
  const signature = signFreezeOrder(order, secret);
  expect(
    schnorr.verify(bytes(signature), freezeOrderDigest(order), bytes(key)),
  ).toBe(true);
  expect(
    schnorr.verify(
      bytes(signature),
      freezeOrderDigest({ ...order, case_reference: "case-8" }),
      bytes(key),
    ),
  ).toBe(false);
});
