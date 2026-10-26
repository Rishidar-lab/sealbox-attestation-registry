/// SealBox Attestation Registry
///
/// Anchors an off-chain artifact digest on Aptos as an object-owned attestation.
/// The file never goes on-chain: the creator hashes it off-chain (SealBox does
/// this with SHA-256) and records the 32-byte digest here.
///
/// Design:
///   - one named object per (creator, digest):
///       address = object::create_object_address(creator, DOMAIN_SEED || digest)
///     so a duplicate attempt is a cheap, deterministic check;
///   - the digest is fixed at creation; only the current object owner can revoke;
///   - revocation is a boolean because named objects cannot be deleted;
///   - no admin, no global tables, no upgrade hook.
module sealbox_attestation::attestation {
    use std::signer;
    use std::string::String;
    use std::vector;
    use aptos_framework::event;
    use aptos_framework::object::{Self, Object};
    use aptos_framework::timestamp;

    /// Digest must be a 32-byte SHA-256 output.
    public const E_DIGEST_LENGTH: u64 = 1;
    /// (creator, digest) has already been attested.
    public const E_ALREADY_ATTESTED: u64 = 2;
    /// Caller does not own the attestation object.
    public const E_NOT_OWNER: u64 = 3;
    /// The attestation has already been revoked.
    public const E_ALREADY_REVOKED: u64 = 4;

    /// Domain separation for the named-object seed. Bump alongside a new module
    /// version rather than mutating this one.
    const DOMAIN_SEED: vector<u8> = b"SEALBOX-ATTEST-V1";

    #[event]
    struct AttestationCreated has drop, store {
        owner: address,
        digest: vector<u8>,
        object_address: address,
        reference: String,
        created_at: u64,
    }

    #[event]
    struct AttestationRevoked has drop, store {
        owner: address,
        digest: vector<u8>,
        object_address: address,
        revoked_at: u64,
    }

    /// Stored on the named object; the object's owner is the attester.
    struct Attestation has key {
        digest: vector<u8>,
        reference: String,
        created_at: u64,
        revoked: bool,
        revoked_at: u64,
    }

    /// Named-object seed for a digest. Public so clients can recompute the
    /// object address without duplicating the derivation scheme by hand.
    public fun seed_for(digest: vector<u8>): vector<u8> {
        let seed = DOMAIN_SEED;
        seed.append(digest);
        seed
    }

    #[view]
    /// Deterministic object address for (creator, digest).
    public fun attestation_address(creator: address, digest: vector<u8>): address {
        object::create_object_address(&creator, seed_for(digest))
    }

    #[view]
    /// Whether (creator, digest) has an attestation object.
    public fun attestation_exists(creator: address, digest: vector<u8>): bool {
        object::object_exists<Attestation>(attestation_address(creator, digest))
    }

    /// Create an attestation for `digest`, owned by the caller.
    ///
    /// `reference` is an optional off-chain pointer (empty string allowed):
    /// e.g. an HTTPS URL, an ipfs:// URI, or a Shelby blob name.
    public entry fun create_attestation(creator: &signer, digest: vector<u8>, reference: String) {
        let creator_address = signer::address_of(creator);
        assert!(vector::length(&digest) == 32, E_DIGEST_LENGTH);

        let object_address = attestation_address(creator_address, digest);
        assert!(
            !object::object_exists<Attestation>(object_address),
            E_ALREADY_ATTESTED,
        );

        let constructor_ref = object::create_named_object(creator, seed_for(digest));
        let object_signer = object::generate_signer(&constructor_ref);
        let created_at = timestamp::now_seconds();

        move_to(
            &object_signer,
            Attestation { digest, reference, created_at, revoked: false, revoked_at: 0 },
        );

        event::emit(AttestationCreated {
            owner: creator_address,
            digest,
            object_address,
            reference,
            created_at,
        });
    }

    /// Revoke the attestation. Only the current owner of the object may call it.
    /// Because attestations are ordinary objects, they can be transferred and the
    /// new owner then holds the revoke right.
    public entry fun revoke_attestation(account: &signer, attestation: Object<Attestation>) {
        let account_address = signer::address_of(account);
        assert!(object::is_owner(attestation, account_address), E_NOT_OWNER);

        let object_address = object::object_address(&attestation);
        let attestation_ref = borrow_global_mut<Attestation>(object_address);
        assert!(!attestation_ref.revoked, E_ALREADY_REVOKED);

        attestation_ref.revoked = true;
        attestation_ref.revoked_at = timestamp::now_seconds();

        event::emit(AttestationRevoked {
            owner: account_address,
            digest: attestation_ref.digest,
            object_address,
            revoked_at: attestation_ref.revoked_at,
        });
    }

    // ── views ────────────────────────────────────────────────────────────────

    #[view]
    public fun attestation_digest(attestation: Object<Attestation>): vector<u8> acquires Attestation {
        borrow_global<Attestation>(object::object_address(&attestation)).digest
    }

    #[view]
    public fun attestation_reference(
        attestation: Object<Attestation>,
    ): String acquires Attestation {
        borrow_global<Attestation>(object::object_address(&attestation)).reference
    }

    #[view]
    public fun created_at(attestation: Object<Attestation>): u64 acquires Attestation {
        borrow_global<Attestation>(object::object_address(&attestation)).created_at
    }

    #[view]
    public fun is_revoked(attestation: Object<Attestation>): bool acquires Attestation {
        borrow_global<Attestation>(object::object_address(&attestation)).revoked
    }

    #[view]
    public fun revoked_at(attestation: Object<Attestation>): u64 acquires Attestation {
        borrow_global<Attestation>(object::object_address(&attestation)).revoked_at
    }

    #[view]
    /// Current owner of the attestation object (the address allowed to revoke).
    public fun owner_of(attestation: Object<Attestation>): address {
        object::owner(attestation)
    }
}
