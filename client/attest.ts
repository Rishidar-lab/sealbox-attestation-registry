/**
 * SealBox Attestation Registry — minimal end-to-end client (Aptos testnet).
 *
 *   file -> SHA-256 (off-chain) -> create attestation -> read it back
 *        -> compare digests -> revoke -> confirm revoked state
 *
 * The account's private key is read from the Aptos CLI profile config
 * (project-local .aptos/config.yaml, then ~/.aptos/config.yaml) or from the
 * APTOS_PRIVATE_KEY environment variable. It is never printed.
 *
 * Usage:
 *   npm run attest -- ./artifact.txt
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import {
  Account,
  Aptos,
  AptosConfig,
  Ed25519PrivateKey,
  Network,
} from '@aptos-labs/ts-sdk';

const HERE = dirname(fileURLToPath(import.meta.url));
const PROFILE = process.env.APTOS_PROFILE ?? 'attestation';

/** Config lookup order: env key > APTOS_CONFIG > project .aptos > user .aptos. */
function loadPrivateKey(): string {
  if (process.env.APTOS_PRIVATE_KEY) return process.env.APTOS_PRIVATE_KEY;

  const candidates = [
    process.env.APTOS_CONFIG,
    join(HERE, '..', '.aptos', 'config.yaml'),
    join(process.cwd(), '.aptos', 'config.yaml'),
    join(homedir(), '.aptos', 'config.yaml'),
  ].filter((p): p is string => Boolean(p));

  for (const path of candidates) {
    if (!existsSync(path)) continue;
    const config = parseYaml(readFileSync(path, 'utf8')) as {
      profiles?: Record<string, { private_key?: string }>;
    };
    const key = config.profiles?.[PROFILE]?.private_key;
    if (key) return key;
  }
  throw new Error(
    `No private key found. Set APTOS_PRIVATE_KEY or add profile "${PROFILE}" to a .aptos/config.yaml.`,
  );
}

function moduleAddress(account: Account): string {
  return process.env.MODULE_ADDRESS ?? account.accountAddress.toString();
}

async function sha256(path: string): Promise<{ digest: Uint8Array; hex: string }> {
  const bytes = readFileSync(path);
  const hash = createHash('sha256').update(bytes).digest();
  return { digest: new Uint8Array(hash), hex: hash.toString('hex') };
}

function bytesToHex(value: unknown): string {
  if (value instanceof Uint8Array) return Buffer.from(value).toString('hex');
  if (typeof value === 'string') return Buffer.from(value.replace(/^0x/, ''), 'hex').toString('hex');
  if (Array.isArray(value)) return Buffer.from(value as number[]).toString('hex');
  return String(value);
}

const file = process.argv[2] ?? './artifact.txt';
if (!existsSync(file)) {
  console.error(`File not found: ${file}`);
  process.exit(2);
}

const account = Account.fromPrivateKey({
  privateKey: new Ed25519PrivateKey(loadPrivateKey()),
});
const module = moduleAddress(account);
const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));

const { digest, hex: localDigest } = await sha256(file);
const reference = `file:${file}@sha256:${localDigest}`;

const entry = (name: string): `${string}::${string}::${string}` =>
  `${module}::attestation::${name}`;
const objectAddress = (
  await aptos.view({
    payload: {
      function: entry('attestation_address'),
      functionArguments: [account.accountAddress.toString(), Array.from(digest)],
    },
  })
)[0] as string;

console.log(JSON.stringify({ step: 'derive', objectAddress, localDigest }));

// 1. create (skipped when the attestation already exists)
const existsBefore = (
  await aptos.view({
    payload: {
      function: entry('attestation_exists'),
      functionArguments: [account.accountAddress.toString(), Array.from(digest)],
    },
  })
)[0] as boolean;

if (!existsBefore) {
  const transaction = await aptos.transaction.build.simple({
    sender: account.accountAddress,
    data: {
      function: entry('create_attestation'),
      functionArguments: [Array.from(digest), reference],
    },
    // explicit, small fee ceiling: a testnet account holds ~1 APT
    options: { gasUnitPrice: 100, maxGasAmount: 50_000 },
  });
  const pending = await aptos.signAndSubmitTransaction({ signer: account, transaction });
  const committed = await aptos.waitForTransaction({ transactionHash: pending.hash });
  console.log(
    JSON.stringify({
      step: 'create',
      ok: committed.success,
      hash: pending.hash,
      explorer: `https://explorer.aptoslabs.com/txn/${pending.hash}?network=testnet`,
    }),
  );
} else {
  console.log(JSON.stringify({ step: 'create', skipped: true, reason: 'already attested' }));
}

// 2. read back and compare against the local digest
const readDigest = (
  await aptos.view({
    payload: {
      function: entry('attestation_digest'),
      functionArguments: [objectAddress],
    },
  })
)[0];
const onchainDigest = bytesToHex(readDigest);
const owner = (
  await aptos.view({
    payload: { function: entry('owner_of'), functionArguments: [objectAddress] },
  })
)[0] as string;
const createdAt = (
  await aptos.view({
    payload: { function: entry('created_at'), functionArguments: [objectAddress] },
  })
)[0] as string;

console.log(
  JSON.stringify({
    step: 'read',
    owner,
    createdAt,
    matchesLocalDigest: onchainDigest === localDigest,
    onchainDigest,
  }),
);

// 3. revoke (only the owner can) and confirm state
const alreadyRevoked = (
  await aptos.view({
    payload: { function: entry('is_revoked'), functionArguments: [objectAddress] },
  })
)[0] as boolean;

if (!alreadyRevoked) {
  const transaction = await aptos.transaction.build.simple({
    sender: account.accountAddress,
    data: { function: entry('revoke_attestation'), functionArguments: [objectAddress] },
    options: { gasUnitPrice: 100, maxGasAmount: 50_000 },
  });
  const pending = await aptos.signAndSubmitTransaction({ signer: account, transaction });
  const committed = await aptos.waitForTransaction({ transactionHash: pending.hash });
  console.log(
    JSON.stringify({
      step: 'revoke',
      ok: committed.success,
      hash: pending.hash,
      explorer: `https://explorer.aptoslabs.com/txn/${pending.hash}?network=testnet`,
    }),
  );
} else {
  console.log(JSON.stringify({ step: 'revoke', skipped: true, reason: 'already revoked' }));
}

const revoked = (
  await aptos.view({
    payload: { function: entry('is_revoked'), functionArguments: [objectAddress] },
  })
)[0] as boolean;
// digest must be unchanged by revocation
const digestAfter = bytesToHex(
  (
    await aptos.view({
      payload: { function: entry('attestation_digest'), functionArguments: [objectAddress] },
    })
  )[0],
);

console.log(
  JSON.stringify({
    step: 'verify',
    revoked,
    digestUnchanged: digestAfter === localDigest,
    ok: revoked && digestAfter === localDigest && onchainDigest === localDigest,
  }),
);
