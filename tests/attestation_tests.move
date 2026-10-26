#[test_only]
/// Unit tests for the attestation module.
///
/// Covers: creation, stored fields, owner derivation, duplicate and malformed
/// inputs, owner-only revocation, revoked-state visibility, object transfer
/// semantics, deterministic addressing, and event emission.
module sealbox_attestation::attestation_tests {
    use std::string;
    use std::vector;
    use aptos_framework::account;
    use aptos_framework::event;
    use aptos_framework::object;
    use aptos_framework::timestamp;
    use sealbox_attestation::attestation;

    const CREATOR: address = @0x1001;
    /// Deterministic clock for timestamp assertions.
    const START_TIME: u64 = 1_000_000;
    const REVOKE_TIME: u64 = 1_000_100;
    const OTHER: address = @0x1002;
    const THIRD: address = @0x1003;

    /// 32 identical bytes — cheap stand-in for a SHA-256 digest.
    fun digest_of(byte: u8): vector<u8> {
        let digest = vector::empty<u8>();
        let i = 0;
        while (i < 32) {
            vector::push_back(&mut digest, byte);
            i = i + 1;
        };
        digest
    }

    fun setup(): (signer, signer, signer) {
        account::create_account_for_test(CREATOR);
        account::create_account_for_test(OTHER);
        account::create_account_for_test(THIRD);
        timestamp::set_time_has_started_for_testing(&account::create_signer_for_test(@0x1));
        timestamp::update_global_time_for_test_secs(START_TIME);
        (
            account::create_signer_for_test(CREATOR),
            account::create_signer_for_test(OTHER),
            account::create_signer_for_test(THIRD),
        )
    }

    #[test]
    fun create_stores_digest_owner_reference_and_time() {
        let (creator, _, _) = setup();
        let digest = digest_of(7);
        let reference = string::utf8(b"https://example.invalid/artifact");

        attestation::create_attestation(&creator, digest, reference);

        let object_address = attestation::attestation_address(CREATOR, digest);
        let object = object::address_to_object<attestation::Attestation>(object_address);

        assert!(attestation::attestation_digest(object) == digest);
        assert!(attestation::attestation_reference(object) == reference);
        assert!(attestation::owner_of(object) == CREATOR);
        assert!(attestation::created_at(object) == START_TIME);
        assert!(!attestation::is_revoked(object));
        assert!(attestation::revoked_at(object) == 0);
    }

    #[test]
    fun empty_reference_is_allowed() {
        let (creator, _, _) = setup();
        let digest = digest_of(1);
        attestation::create_attestation(&creator, digest, string::utf8(b""));
        let object = object::address_to_object<attestation::Attestation>(
            attestation::attestation_address(CREATOR, digest),
        );
        assert!(attestation::attestation_reference(object) == string::utf8(b""));
    }

    #[test]
    #[expected_failure(abort_code = attestation::E_ALREADY_ATTESTED)]
    fun duplicate_create_aborts() {
        let (creator, _, _) = setup();
        let digest = digest_of(2);
        attestation::create_attestation(&creator, digest, string::utf8(b"first"));
        attestation::create_attestation(&creator, digest, string::utf8(b"second"));
    }

    #[test]
    #[expected_failure(abort_code = attestation::E_DIGEST_LENGTH)]
    fun short_digest_aborts() {
        let (creator, _, _) = setup();
        attestation::create_attestation(&creator, vector[1u8, 2, 3], string::utf8(b""));
    }

    #[test]
    #[expected_failure(abort_code = attestation::E_DIGEST_LENGTH)]
    fun long_digest_aborts() {
        let (creator, _, _) = setup();
        let digest = digest_of(9);
        vector::push_back(&mut digest, 0);
        attestation::create_attestation(&creator, digest, string::utf8(b""));
    }

    #[test]
    fun owner_can_revoke_and_state_is_visible() {
        let (creator, _, _) = setup();
        let digest = digest_of(3);
        attestation::create_attestation(&creator, digest, string::utf8(b""));
        let object = object::address_to_object<attestation::Attestation>(
            attestation::attestation_address(CREATOR, digest),
        );

        timestamp::update_global_time_for_test_secs(REVOKE_TIME);
        attestation::revoke_attestation(&creator, object);

        assert!(attestation::is_revoked(object));
        assert!(attestation::revoked_at(object) == REVOKE_TIME);
        assert!(attestation::revoked_at(object) > attestation::created_at(object));
        // digest and owner are unchanged by revocation
        assert!(attestation::attestation_digest(object) == digest);
        assert!(attestation::owner_of(object) == CREATOR);
    }

    #[test]
    #[expected_failure(abort_code = attestation::E_NOT_OWNER)]
    fun non_owner_cannot_revoke() {
        let (creator, other, _) = setup();
        let digest = digest_of(4);
        attestation::create_attestation(&creator, digest, string::utf8(b""));
        let object = object::address_to_object<attestation::Attestation>(
            attestation::attestation_address(CREATOR, digest),
        );
        attestation::revoke_attestation(&other, object);
    }

    #[test]
    #[expected_failure(abort_code = attestation::E_ALREADY_REVOKED)]
    fun double_revoke_aborts() {
        let (creator, _, _) = setup();
        let digest = digest_of(5);
        attestation::create_attestation(&creator, digest, string::utf8(b""));
        let object = object::address_to_object<attestation::Attestation>(
            attestation::attestation_address(CREATOR, digest),
        );
        attestation::revoke_attestation(&creator, object);
        attestation::revoke_attestation(&creator, object);
    }

    #[test]
    fun attestation_address_is_deterministic_and_matches_creation() {
        let (creator, _, _) = setup();
        let digest = digest_of(6);
        let expected = attestation::attestation_address(CREATOR, digest);
        assert!(expected == attestation::attestation_address(CREATOR, digest));

        attestation::create_attestation(&creator, digest, string::utf8(b""));
        let object = object::address_to_object<attestation::Attestation>(expected);
        assert!(object::object_address(&object) == expected);
        // seed is domain-separated: 17-byte tag + 32-byte digest
        assert!(vector::length(&attestation::seed_for(digest)) == 17 + 32);
    }

    #[test]
    fun attestation_exists_tracks_creation() {
        let (creator, _, _) = setup();
        let digest = digest_of(8);
        assert!(!attestation::attestation_exists(CREATOR, digest));
        // same digest, different creator: still absent
        attestation::create_attestation(&creator, digest, string::utf8(b""));
        assert!(attestation::attestation_exists(CREATOR, digest));
        assert!(!attestation::attestation_exists(OTHER, digest));
    }

    #[test]
    fun two_creators_can_attest_the_same_digest() {
        let (creator, other, _) = setup();
        let digest = digest_of(10);
        attestation::create_attestation(&creator, digest, string::utf8(b"a"));
        attestation::create_attestation(&other, digest, string::utf8(b"b"));

        let a = object::address_to_object<attestation::Attestation>(
            attestation::attestation_address(CREATOR, digest),
        );
        let b = object::address_to_object<attestation::Attestation>(
            attestation::attestation_address(OTHER, digest),
        );
        assert!(object::object_address(&a) != object::object_address(&b));
        assert!(attestation::owner_of(a) == CREATOR);
        assert!(attestation::owner_of(b) == OTHER);
    }

    #[test]
    fun transfer_moves_revoke_right_to_new_owner() {
        let (creator, other, _) = setup();
        let digest = digest_of(11);
        attestation::create_attestation(&creator, digest, string::utf8(b""));
        let object_address = attestation::attestation_address(CREATOR, digest);

        object::transfer_raw(&creator, object_address, OTHER);

        let object = object::address_to_object<attestation::Attestation>(object_address);
        assert!(attestation::owner_of(object) == OTHER);
        // creator can no longer revoke
        attestation::revoke_attestation(&other, object);
        assert!(attestation::is_revoked(object));
    }

    #[test]
    fun create_and_revoke_each_emit_one_event() {
        let (creator, _, _) = setup();
        let digest = digest_of(12);
        let created_before = vector::length(&event::emitted_events<attestation::AttestationCreated>());
        let revoked_before = vector::length(&event::emitted_events<attestation::AttestationRevoked>());

        attestation::create_attestation(&creator, digest, string::utf8(b"r"));
        let object = object::address_to_object<attestation::Attestation>(
            attestation::attestation_address(CREATOR, digest),
        );
        attestation::revoke_attestation(&creator, object);

        assert!(
            vector::length(&event::emitted_events<attestation::AttestationCreated>())
                == created_before + 1,
        );
        assert!(
            vector::length(&event::emitted_events<attestation::AttestationRevoked>())
                == revoked_before + 1,
        );
    }

    #[test]
    #[expected_failure]
    fun revoke_with_non_object_address_aborts() {
        let (creator, _, _) = setup();
        let digest = digest_of(13);
        attestation::create_attestation(&creator, digest, string::utf8(b""));
        // an address that is not an ObjectCore-carrying object
        let bogus = object::address_to_object<attestation::Attestation>(@0x9999);
        attestation::revoke_attestation(&creator, bogus);
    }
}
