# SealBox Attestation Registry

An Aptos Move registry that anchors an **off-chain artifact digest** as an on-chain,
object-owned attestation. Built as a small integration proof next to
[SealBox](https://github.com/Rishidar-lab/sealbox).

**Status: testnet-only, unaudited, demonstration project.** Everything below is tiered and
backed by the transactions listed under [Testnet deployment](#testnet-deployment).

---

## Purpose

SealBox proves artifact integrity **off-chain**: it hashes a file (SHA-256), signs a canonical
manifest with Ed25519, and verifies both later. This project demonstrates a second,
complementary primitive: the **digest** can be anchored on Aptos so a third party can check
"this digest was vouched for by this address at this time" without holding the manifest.

The chain does **not** store the artifact — only the 32-byte digest and small metadata.

## Architecture

```
artifact file
   │  SHA-256 (off-chain, e.g. SealBox)
   ▼
32-byte digest ──► Aptos Move: create_attestation(digest, reference)
   │                        │
   │                        ├─ named object per (creator, digest)
   │                        ├─ Attestation resource on that object
   │                        ├─ AttestationCreated event
   │                        └─ views: digest / owner / created_at / is_revoked
   ▼
SealBox manifest + Ed25519 signature (unchanged, off-chain)
```

## What is on-chain

- the 32-byte digest (immutable after creation)
- the object owner (the attester; transferable like any Aptos object)
- an optional free-form `reference` string (e.g. `file:artifact.txt@sha256:…`, a URL, an ipfs:// URI)
- `created_at` and revocation state (`revoked`, `revoked_at`)
- `AttestationCreated` / `AttestationRevoked` events

## What is NOT on-chain

- the artifact contents (no blobs, no chunks)
- the private key, any secret material
- SealBox's Ed25519 signature or manifest (they stay off-chain; see Limitations)
- any index or table — addressing is derived, not stored

## Module

Deployed module: `0x94f38b145c2790b5a4e42c2937a4b3f78c5463cb105ee20b4db4fa6a16a2e8f4::attestation`

| function | kind | note |
|---|---|---|
| `create_attestation(creator, digest, reference)` | entry | digest must be 32 bytes; duplicate `(creator, digest)` aborts |
| `revoke_attestation(account, attestation)` | entry | **owner only**; second revoke aborts |
| `attestation_digest(attestation)` | view | |
| `attestation_reference(attestation)` | view | |
| `owner_of(attestation)` | view | current owner (the address allowed to revoke) |
| `created_at(attestation)` / `revoked_at(attestation)` | view | seconds |
| `is_revoked(attestation)` | view | |
| `attestation_address(creator, digest)` | view | deterministic address: `object::create_object_address(creator, b"SEALBOX-ATTEST-V1" ‖ digest)` |
| `attestation_exists(creator, digest)` | view | |
| `seed_for(digest)` | public | seed helper so clients don't re-implement the derivation |

Design notes:

- **One named object per `(creator, digest)`.** Deterministic, duplicate-proof (collision
  aborts), and non-deletable — so revocation is a boolean flag rather than a delete.
- **No admin, no global table, no upgrade hook.** Ownership *is* the authorization: revocation
  is gated by `object::is_owner`, so a transferred object carries the revoke right with it.
- Abort codes: `E_DIGEST_LENGTH=1`, `E_ALREADY_ATTESTED=2`, `E_NOT_OWNER=3`,
  `E_ALREADY_REVOKED=4`.

## Tests

14 Move unit tests — `aptos move test` (all pass; `aptos move compile` is warning-free):

| test | asserts |
|---|---|
| `create_stores_digest_owner_reference_and_time` | stored fields, owner, clock |
| `empty_reference_is_allowed` | optional reference |
| `duplicate_create_aborts` | `E_ALREADY_ATTESTED` |
| `short_digest_aborts` / `long_digest_aborts` | `E_DIGEST_LENGTH` |
| `owner_can_revoke_and_state_is_visible` | revoke flips state; digest/owner unchanged; `revoked_at` set |
| `non_owner_cannot_revoke` | `E_NOT_OWNER` |
| `double_revoke_aborts` | `E_ALREADY_REVOKED` |
| `attestation_address_is_deterministic_and_matches_creation` | determinism + seed length |
| `attestation_exists_tracks_creation` | true/false, per-creator isolation |
| `two_creators_can_attest_the_same_digest` | independent objects |
| `transfer_moves_revoke_right_to_new_owner` | transfer semantics + old owner loses revoke |
| `create_and_revoke_each_emit_one_event` | events emitted |
| `revoke_with_non_object_address_aborts` | bogus object address fails safely |

## Client

`client/attest.ts` (TypeScript, `@aptos-labs/ts-sdk`) runs the full sequence:
hash → derive address → create → read back → compare digest → revoke → verify.

```bash
cd client && npm install
npm run attest -- ../artifact.txt
```

The private key comes from the Aptos CLI profile (project `.aptos/config.yaml`, then
`~/.aptos/config.yaml`) or `APTOS_PRIVATE_KEY`. See `client/.env.example` — names only, values
are never printed.

`npm test` = `tsc --noEmit`; the client is a single script validated by typecheck, build and a
live run, while the Move unit tests are the actual test suite.

## Testnet deployment

Network: `testnet` · Module: `0x94f38b145c2790b5a4e42c2937a4b3f78c5463cb105ee20b4db4fa6a16a2e8f4::attestation`

| step | transaction |
|---|---|
| faucet funding (1 APT) | [`0xa5de63e6…`](https://explorer.aptoslabs.com/txn/0xa5de63e6107026e299eecfb83d7f5b849af05263c928a84e3dae6f7b7dfff425?network=testnet) |
| publish package | [`0x9dfdfc58…`](https://explorer.aptoslabs.com/txn/0x9dfdfc5893feced5a6191f5061e8ea7181878c1f7956bc084bd34b636fc9ea7f?network=testnet) |
| create attestation | [`0x243e60e5…`](https://explorer.aptoslabs.com/txn/0x243e60e577af6e34381fac45d68ab1cee4c358e0d284a4f06cdce0e0bc5a3780?network=testnet) |
| revoke attestation | [`0x053129e2…`](https://explorer.aptoslabs.com/txn/0x053129e205c6c9c0d237f8c7e77d1bbabcf6d7e030e642c8348a682162b416ae?network=testnet) |

Attestation object created: `0x765ccbc7136a385c85e7a98f24f0af09470fea127b5cb76779d9c9b9b3c032b1`
for artifact digest `a322c65ecd0ae115937ff3134846e2271c66a7ac06cb1e6c176b863d8b72cec9`
(`artifact.txt` in this repo). The client output showed `matchesLocalDigest: true`,
then `revoked: true` with the digest unchanged.

## Reproduce

```bash
aptos move test                       # 14 tests
aptos init --network testnet --profile attestation
# fund the printed address at https://aptos.dev/network/faucet (Google sign-in), then:
aptos move publish --profile attestation \
  --named-addresses sealbox_attestation=<your-address>
cd client && npm install && npm run attest -- ../artifact.txt
```

## Limitations

- **Anchoring does not prove the file was honest.** It records that *an address* claimed *a
  digest*. Anyone can attest any digest.
- **Digest correctness depends on the submitted digest.** The module records 32 bytes; it does
  not (yet) verify a signature over them. On-chain Ed25519 verification via
  `aptos_std::ed25519` is a deliberate follow-up, not implemented here.
- **Signer trust stays external.** The registry does not say which addresses are "trusted".
- **Revocation means "withdrawn", not "false".** The flag is set by the object owner and is
  itself observable, but its meaning is social, not cryptographic.
- Named objects cannot be deleted, so revocations accumulate; `reference` is immutable in v1.
- Testnet-only, unaudited, no production claim; the test suite is unit-level (no property
  tests) and the client is a single script.

## License

MIT — see [LICENSE](LICENSE).
