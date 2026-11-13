// Research recipient implementation. Keys and recovered openings stay local.
// Verifies signed scoped releases, DLEQ partials and recovered commitments.
// Chain inclusion and committee authenticity still require a trusted observer.
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { pbkdf2Async } from "@noble/hashes/pbkdf2.js";
import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
export const hex = bytesToHex;
export const bytes = hexToBytes;
const text = utf8ToBytes;
const Point = secp256k1.Point;
type P = ReturnType<typeof Point.fromBytes>;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const F = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const zero = Point.ZERO;
const G = Point.BASE;
const mod = (x: bigint, p = N) => ((x % p) + p) % p;
const number = (data: Uint8Array) => BigInt("0x" + (hex(data) || "0"));
const concat = (...values: Uint8Array[]) => {
  const out = new Uint8Array(
    values.reduce((sum, value) => sum + value.length, 0),
  );
  let pos = 0;
  for (const value of values) {
    out.set(value, pos);
    pos += value.length;
  }
  return out;
};
const integer = (value: bigint | number, length: number) =>
  bytes(
    BigInt(value)
      .toString(16)
      .padStart(length * 2, "0"),
  );
const u32 = (value: number) => integer(value, 4);
const point = (value: string) =>
  /^0{66}$/.test(value) ? zero : Point.fromHex(value);
const encoded = (value: P) =>
  value.equals(zero) ? new Uint8Array(33) : value.toBytes(true);
const multiply = (p: P, scalar: bigint) =>
  mod(scalar) === 0n ? zero : p.multiplyUnsafe(mod(scalar));
const pow = (value: bigint, exponent: bigint, p = N) => {
  let result = 1n,
    base = mod(value, p);
  for (let e = exponent; e; e >>= 1n) {
    if (e & 1n) result = (result * base) % p;
    base = (base * base) % p;
  }
  return result;
};
const inverse = (x: bigint, p = N) => pow(x, p - 2n, p);
function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, v]) => [k, sorted(v)]),
    );
  return value;
}
export const canonical = (value: unknown) =>
  text(
    JSON.stringify(sorted(value)).replace(
      /[^\x00-\x7f]/g,
      (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
    ),
  );
export const digest = (label: string, ...parts: Uint8Array[]) =>
  sha256(
    concat(
      ...[
        text("Elements/threshold-audit/experiment/v1"),
        text(label),
        ...parts,
      ].flatMap((p) => [integer(p.length, 8), p]),
    ),
  );
const same = (a: Uint8Array, b: Uint8Array) => hex(a) === hex(b);
function requireThat(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}
function confidential(value: string, prefix: number): P {
  const data = bytes(value);
  requireThat(
    data.length === 33 && [prefix, prefix + 1].includes(data[0]),
    "Invalid commitment",
  );
  const x = number(data.slice(1));
  requireThat(x < F, "Invalid commitment coordinate");
  const rhs = mod(x * x * x + 7n, F);
  let y = pow(rhs, (F + 1n) / 4n, F);
  requireThat((y * y) % F === rhs, "Invalid commitment point");
  if ((pow(y, (F - 1n) / 2n, F) === 1n) !== (data[0] === prefix)) y = F - y;
  return Point.fromAffine({ x, y });
}
function svdw(t: bigint): P {
  requireThat(t < F, "Invalid generator seed");
  const negc =
    0xf5d2d456caf80e20dcc88f3d586869d339e092ea25eb132b8272d850e32a03ddn;
  const d = 0x851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40n;
  const t2 = (t * t) % F,
    wd = mod(t2 + 8n, F),
    x3d = mod(-3n * t2, F),
    inv = inverse(wd * x3d, F);
  const x1 = mod(d + negc * t2 * x3d * inv, F),
    x2 = mod(-x1 - 1n, F),
    x3 = mod(1n + wd * wd * wd * inv, F);
  for (const x of [x1, x2, x3]) {
    const rhs = mod(x * x * x + 7n, F),
      y = pow(rhs, (F + 1n) / 4n, F);
    if ((y * y) % F === rhs)
      return Point.fromAffine({ x, y: t & 1n ? F - y : y });
  }
  throw new Error("Invalid generator");
}
export function assetGenerator(asset: string): string {
  const seed = bytes(asset);
  requireThat(seed.length === 32, "Invalid asset ID");
  return hex(
    encoded(
      svdw(number(sha256(concat(text("1st generation: "), seed)))).add(
        svdw(number(sha256(concat(text("2nd generation: "), seed)))),
      ),
    ),
  );
}
export interface RecipientKeyFile {
  format: string;
  user_id: string;
  public_key: string;
  salt: string;
  nonce: string;
  ciphertext: string;
}
export async function newRecipientKey(
  user: string,
  password: string,
): Promise<RecipientKeyFile> {
  requireThat(
    password.length >= 10 && password.length <= 256,
    "Use a recipient key password of 10 to 256 characters",
  );
  const secret = secp256k1.utils.randomSecretKey();
  const public_key = hex(secp256k1.getPublicKey(secret));
  const salt = crypto.getRandomValues(new Uint8Array(16)),
    nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await pbkdf2Async(sha256, text(password), salt, {
    c: 210000,
    dkLen: 32,
  });
  const base = {
    format: "concord-recipient-key-v1",
    user_id: user,
    public_key,
  };
  const ciphertext = gcm(key, nonce, canonical(base)).encrypt(secret);
  secret.fill(0);
  key.fill(0);
  return {
    ...base,
    salt: hex(salt),
    nonce: hex(nonce),
    ciphertext: hex(ciphertext),
  };
}
export async function unlockRecipientKey(
  file: RecipientKeyFile,
  user: string,
  password: string,
): Promise<Uint8Array> {
  requireThat(
    file.format === "concord-recipient-key-v1" &&
      file.user_id === user &&
      file.salt.length === 32 &&
      file.nonce.length === 24 &&
      file.ciphertext.length === 96,
    "This is not a recipient key file for your account",
  );
  const key = await pbkdf2Async(sha256, text(password), bytes(file.salt), {
    c: 210000,
    dkLen: 32,
  });
  try {
    const secret = gcm(
      key,
      bytes(file.nonce),
      canonical({
        format: file.format,
        user_id: file.user_id,
        public_key: file.public_key,
      }),
    ).decrypt(bytes(file.ciphertext));
    requireThat(
      hex(secp256k1.getPublicKey(secret)) === file.public_key,
      "Recipient key mismatch",
    );
    return secret;
  } finally {
    key.fill(0);
  }
}
interface Statement {
  chain_id: string;
  tx_digest: string;
  output_index: number;
  script: string;
  asset_commitment: string;
  value_commitment: string;
  audit_key: string;
  assets: string[];
}
interface Committee {
  epoch: number;
  members: number[];
  commitments: string[];
}
interface Sealed {
  released_at: number;
  scheme: string;
  member: number;
  request_binding: string;
  recipient_key: string;
  ephemeral_key: string;
  nonce: string;
  ciphertext: string;
  signature: string;
}
interface Checkpoint {
  member: number;
  sequence: number;
  head: string;
  signature: string;
}
interface Partial {
  member: number;
  committee_binding: string;
  request_binding: string;
  points: string[];
  proofs: string[][];
  checkpoint: Checkpoint;
}
interface Output {
  txid: string;
  output_index: number;
  creation_block: string;
  statement: Statement;
  committee: Committee;
  identities: [number, string][];
  packet: string;
  request_binding: string;
  request: {
    policy_binding: string;
    statement_binding: string;
    packet_binding: string;
    case_reference: string;
    recipient_key: string;
    expires_at: number;
    delivery: string;
  };
  approvals: Record<string, { signature: string }>;
  sealed_partials: Record<string, Sealed>;
}
export interface DisclosureBundle {
  format: string;
  manifest: {
    created_at: number;
    id: string;
    recipient: { id: string; public_key: string };
    expires_at: number;
    targets: {
      txid: string;
      output_index: number;
      creation_block: string;
      statement: Statement;
      packet_hash: string;
    }[];
    [key: string]: unknown;
  };
  manifest_hash: string;
  outputs: Output[];
}
export interface RecoveredOutput {
  txid: string;
  output_index: number;
  asset_id: string;
  amount_base_units: string;
  asset_blinder: string;
  value_blinder: string;
  verified_guardians: number;
}
function statementBinding(s: Statement) {
  return digest(
    "statement",
    bytes(s.chain_id),
    bytes(s.tx_digest),
    u32(s.output_index),
    bytes(s.script),
    bytes(s.asset_commitment),
    bytes(s.value_commitment),
    bytes(s.audit_key),
    concat(...s.assets.map(bytes)),
  );
}
function committeeBinding(c: Committee) {
  return digest(
    "committee",
    u32(c.epoch),
    concat(...c.members.map(u32)),
    concat(...c.commitments.map(bytes)),
  );
}
function verificationKey(c: Committee, member: number) {
  requireThat(c.members.includes(member), "Unknown guardian");
  return c.commitments.reduce(
    (p, v, j) => p.add(multiply(point(v), pow(BigInt(member), BigInt(j)))),
    zero,
  );
}
function packetCiphertexts(packet: Uint8Array, assetCount: number) {
  requireThat(
    packet.length <= 80000 &&
      new TextDecoder().decode(packet.slice(0, 4)) === "TAC2",
    "Unsupported recovery packet",
  );
  const ciphertexts: { first: P; second: P }[] = [];
  let pos = 4;
  for (let i = 0; i < 36; i++) {
    requireThat(pos + 101 <= packet.length, "Truncated packet");
    const first = point(hex(packet.slice(pos, pos + 33))),
      second = point(hex(packet.slice(pos + 33, pos + 66)));
    requireThat(!first.equals(zero), "Invalid ciphertext");
    const length = packet[pos + 99] * 256 + packet[pos + 100];
    requireThat(length >= 1 && length <= 1536, "Invalid range proof");
    pos += 101 + length + 128;
    ciphertexts.push({ first, second });
  }
  requireThat(
    pos + 64 * (assetCount + 1) === packet.length,
    "Invalid packet length",
  );
  return ciphertexts;
}
function unseal(
  secret: Uint8Array,
  env: Sealed,
  identity: string,
  binding: string,
): Partial {
  requireThat(
    env.scheme === "secp256k1-hkdf-aesgcm-v1" &&
      env.request_binding === binding &&
      env.recipient_key === hex(secp256k1.getPublicKey(secret)),
    "Sealed package recipient mismatch",
  );
  const { signature, ...signed } = env;
  requireThat(
    schnorr.verify(
      bytes(signature),
      digest("sealed-partial-envelope", canonical(signed)),
      bytes(identity),
    ),
    "Invalid guardian envelope signature",
  );
  const aad = digest(
    "sealed-partial",
    bytes(binding),
    u32(env.member),
    bytes(env.recipient_key),
  );
  const shared = secp256k1
    .getSharedSecret(secret, bytes(env.ephemeral_key))
    .slice(1);
  const aes = hkdf(
    sha256,
    shared,
    aad,
    text("Elements/threshold-audit/sealed-partial/v1"),
    32,
  );
  try {
    return JSON.parse(
      new TextDecoder().decode(
        gcm(aes, bytes(env.nonce), aad).decrypt(bytes(env.ciphertext)),
      ),
    ) as Partial;
  } finally {
    shared.fill(0);
    aes.fill(0);
  }
}
function verifyPartial(
  output: Output,
  partial: Partial,
  ciphertexts: { first: P; second: P }[],
) {
  const committee = committeeBinding(output.committee),
    request = bytes(output.request_binding),
    member = partial.member;
  requireThat(
    partial.committee_binding === hex(committee) &&
      partial.request_binding === output.request_binding &&
      partial.points.length === 36 &&
      partial.proofs.length === 36,
    "Partial scope mismatch",
  );
  const key = verificationKey(output.committee, member);
  const ctx = digest(
    "TAC2/decryption",
    statementBinding(output.statement),
    digest("packet", bytes(output.packet)),
    committee,
    request,
    u32(member),
  );
  for (let j = 0; j < 36; j++) {
    const pair = partial.proofs[j];
    requireThat(
      pair.length === 2 &&
        pair.every((s) => /^[a-f0-9]{64}$/.test(s) && number(bytes(s)) < N),
      "Invalid partial proof",
    );
    const [c, z] = pair.map((s) => number(bytes(s))),
      R = ciphertexts[j].first,
      D = point(partial.points[j]);
    const a = multiply(G, z).subtract(multiply(key, c)),
      b = multiply(R, z).subtract(multiply(D, c));
    const expected =
      number(
        digest(
          "dleq",
          digest("TAC2/partial", ctx, u32(j)),
          encoded(G),
          encoded(R),
          encoded(key),
          encoded(D),
          encoded(a),
          encoded(b),
        ),
      ) % N;
    requireThat(c === expected, "Invalid guardian partial proof");
  }
  const checkpoint = partial.checkpoint,
    identity = output.identities.find(([id]) => id === member)?.[1];
  requireThat(
    identity &&
      checkpoint.member === member &&
      schnorr.verify(
        bytes(checkpoint.signature),
        digest(
          "guardian-checkpoint",
          u32(member),
          integer(checkpoint.sequence, 8),
          bytes(checkpoint.head),
        ),
        bytes(identity),
      ),
    "Invalid guardian audit checkpoint",
  );
}
function smallLog(base: P) {
  const babies = new Map<string, number>();
  let p = zero;
  for (let j = 0; j < 256; j++) {
    babies.set(hex(encoded(p)), j);
    p = p.add(base);
  }
  const giant = p.negate();
  return (target: P) => {
    let point = target;
    for (let i = 0; i < 256; i++) {
      const j = babies.get(hex(encoded(point)));
      if (j !== undefined) return i * 256 + j;
      point = point.add(giant);
    }
    throw new Error("Recovered limb is outside its range");
  };
}
export async function recoverBundle(
  bundle: DisclosureBundle,
  secret: Uint8Array,
  user: string,
): Promise<RecoveredOutput[]> {
  requireThat(
    bundle.format === "concord-sealed-disclosure-v1" &&
      bundle.manifest.recipient.id === user &&
      bundle.manifest.recipient.public_key ===
        hex(secp256k1.getPublicKey(secret)),
    "This package is not addressed to your key and account",
  );
  const manifestHash = digest(
    "settlement-disclosure-case",
    canonical(bundle.manifest),
  );
  requireThat(
    hex(manifestHash) === bundle.manifest_hash &&
      bundle.outputs.length === bundle.manifest.targets.length &&
      bundle.outputs.length >= 1 &&
      bundle.outputs.length <= 4,
    "Case manifest mismatch",
  );
  const results: RecoveredOutput[] = [];
  let unavailableReason = "Encrypted package does not yet contain a quorum";
  for (const output of bundle.outputs) {
    const s = output.statement,
      c = output.committee,
      r = output.request;
    requireThat(
      c.members.length <= 32 &&
        c.commitments.length >= 1 &&
        c.commitments.length <= c.members.length &&
        new Set(c.members).size === c.members.length &&
        c.members.every(
          (m, i) =>
            Number.isInteger(m) && m > 0 && (i === 0 || m > c.members[i - 1]),
        ),
      "Invalid recovery committee",
    );
    requireThat(
      c.commitments[0] === s.audit_key &&
        !point(c.commitments.at(-1)!).equals(zero),
      "Invalid recovery key",
    );
    const target = bundle.manifest.targets.find(
      (t) => t.txid === output.txid && t.output_index === output.output_index,
    );
    requireThat(
      target &&
        target.creation_block === output.creation_block &&
        same(canonical(target.statement), canonical(s)) &&
        s.output_index === output.output_index,
      "Output differs from approved case",
    );
    const stmt = statementBinding(s),
      packet = bytes(output.packet),
      packetHash = digest("packet", packet),
      committee = committeeBinding(c);
    requireThat(
      target.packet_hash === hex(packetHash) &&
        r.statement_binding === hex(stmt) &&
        r.packet_binding === hex(packetHash) &&
        r.case_reference === bundle.manifest_hash &&
        r.recipient_key === bundle.manifest.recipient.public_key &&
        r.expires_at === bundle.manifest.expires_at &&
        r.delivery === "sealed-v1",
      "Disclosure scope mismatch",
    );
    requireThat(
      output.identities.length === c.members.length &&
        output.identities.every(([id], i) => id === c.members[i]) &&
        new Set(output.identities.map(([, key]) => key)).size ===
          c.members.length,
      "Invalid guardian identity roster",
    );
    const policy = digest(
      "approval-policy",
      committee,
      u32(c.commitments.length),
      concat(
        ...output.identities.map(([id, key]) => concat(u32(id), bytes(key))),
      ),
    );
    requireThat(r.policy_binding === hex(policy), "Approval policy mismatch");
    const request = digest(
      "disclosure-request/sealed-v1",
      policy,
      stmt,
      packetHash,
      manifestHash,
      bytes(r.recipient_key),
      integer(r.expires_at, 8),
    );
    requireThat(
      hex(request) === output.request_binding,
      "Request binding mismatch",
    );
    const ciphertexts = packetCiphertexts(packet, s.assets.length),
      partials: Partial[] = [];
    requireThat(
      Object.keys(output.sealed_partials).length <= 32,
      "Too many guardian contributions",
    );
    let rejectedReason = "";
    for (const env of Object.values(output.sealed_partials)) {
      try {
        requireThat(
          Number.isInteger(env.released_at) &&
            env.released_at >= bundle.manifest.created_at &&
            env.released_at < r.expires_at,
          "Guardian release is outside the approved validity period",
        );
        requireThat(
          !partials.some((p) => p.member === env.member),
          "Duplicate guardian contribution",
        );
        const identity = output.identities.find(
            ([id]) => id === env.member,
          )?.[1],
          approval = output.approvals[String(env.member)];
        requireThat(
          identity &&
            approval &&
            schnorr.verify(bytes(approval.signature), request, bytes(identity)),
          "Missing signed guardian approval",
        );
        const partial = unseal(secret, env, identity, output.request_binding);
        requireThat(
          partial.member === env.member,
          "Guardian identity mismatch",
        );
        verifyPartial(output, partial, ciphertexts);
        partials.push(partial);
      } catch (error) {
        rejectedReason =
          error instanceof Error
            ? error.message
            : "Invalid guardian contribution";
      }
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
    if (partials.length < c.commitments.length) {
      unavailableReason =
        "Encrypted package does not contain a valid quorum" +
        (rejectedReason ? ": " + rejectedReason : "");
      continue;
    }
    const members = partials.map((p) => p.member),
      weights = members.map((member) =>
        members
          .filter((v) => v !== member)
          .reduce(
            (w, other) =>
              mod(w * BigInt(-other) * inverse(BigInt(member - other))),
            1n,
          ),
      );
    const plaintexts = ciphertexts.map((v, j) =>
      v.second.subtract(
        partials.reduce(
          (sum, p, i) => sum.add(multiply(point(p.points[j]), weights[i])),
          zero,
        ),
      ),
    );
    const A = confidential(s.asset_commitment, 10),
      decodeAmount = smallLog(A),
      decodeScalar = smallLog(G);
    const limbs = plaintexts.map((v, i) =>
      BigInt(i < 4 ? decodeAmount(v) : decodeScalar(v)),
    );
    const field = (start: number, count: number) =>
      limbs
        .slice(start, start + count)
        .reduce((sum, v, j) => sum + (v << BigInt(16 * j)), 0n);
    const amount = field(0, 4),
      abf = field(4, 16) % N,
      vbf = field(20, 16) % N;
    const generator = A.subtract(multiply(G, abf));
    const assets = s.assets.filter((asset) =>
      point(assetGenerator(asset)).equals(generator),
    );
    requireThat(
      assets.length === 1 &&
        multiply(A, amount)
          .add(multiply(G, vbf))
          .equals(confidential(s.value_commitment, 8)),
      "Recovered opening does not match the on-chain commitments",
    );
    results.push({
      txid: output.txid,
      output_index: output.output_index,
      asset_id: hex(bytes(assets[0]).reverse()),
      amount_base_units: amount.toString(),
      asset_blinder: hex(integer(abf, 32)),
      value_blinder: hex(integer(vbf, 32)),
      verified_guardians: partials.length,
    });
  }
  requireThat(results.length > 0, unavailableReason);
  return results;
}
