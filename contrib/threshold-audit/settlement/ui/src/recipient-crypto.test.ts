import { expect, it } from "vitest";
import fixture from "./fixtures/sealed-disclosure.json";
import {
  assetGenerator,
  bytes,
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
});
