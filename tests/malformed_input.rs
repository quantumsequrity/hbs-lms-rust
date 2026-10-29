//! Malformed signatures, public keys and aux data must be rejected or ignored, never cause a panic.
//!
//! All keys are test keys from a fixed seed, with LMS_SHA256_M32_H5 and LMOTS_SHA256_N32_W8.

use hbs_lms::signature::SignerMut;
use hbs_lms::{
    keygen, verify, HssParameter, LmotsAlgorithm, LmsAlgorithm, Seed, Sha256_256, SigningKey,
    VerifyingKey,
};

type H = Sha256_256;

const MESSAGE: &[u8] = b"message";

// Sizes in bytes for LMS_SHA256_M32_H5 with LMOTS_SHA256_N32_W8 (RFC 8554, sections 4 and 5).
const LMOTS_SIGNATURE_LEN: usize = 4 + 32 + 34 * 32; // type, C, y[0..34]
const LMS_SIGNATURE_LEN: usize = 4 + LMOTS_SIGNATURE_LEN + 4 + 5 * 32; // q, LM-OTS signature, type, path
const LMS_PUBLIC_KEY_LEN: usize = 4 + 4 + 16 + 32; // LMS type, LM-OTS type, I, T[1]
const SIGNED_PUBLIC_KEY_LEN: usize = LMS_SIGNATURE_LEN + LMS_PUBLIC_KEY_LEN;

fn key_pair(levels: usize, aux_data: Option<&mut &mut [u8]>) -> (SigningKey<H>, VerifyingKey<H>) {
    let parameters = vec![HssParameter::new(LmotsAlgorithm::LmotsW8, LmsAlgorithm::LmsH5); levels];
    keygen::<H>(&parameters, &Seed::from([0x5a; 32]), aux_data).expect("key generation")
}

fn sign(signing_key: &mut SigningKey<H>) -> Vec<u8> {
    signing_key
        .try_sign(MESSAGE)
        .expect("signing")
        .as_ref()
        .to_vec()
}

#[test]
fn truncated_signatures_are_rejected() {
    for levels in [1, 2] {
        let (mut signing_key, verifying_key) = key_pair(levels, None);
        let public_key = verifying_key.as_slice();
        let signature = sign(&mut signing_key);
        assert!(verify::<H>(MESSAGE, &signature, public_key).is_ok());

        for len in 0..signature.len() {
            assert!(
                verify::<H>(MESSAGE, &signature[..len], public_key).is_err(),
                "{} level(s), signature cut to {} bytes",
                levels,
                len
            );
        }
    }
}

#[test]
fn truncated_public_keys_are_rejected() {
    let (mut signing_key, verifying_key) = key_pair(1, None);
    let public_key = verifying_key.as_slice();
    let signature = sign(&mut signing_key);
    assert!(verify::<H>(MESSAGE, &signature, public_key).is_ok());

    for len in 0..public_key.len() {
        assert!(
            verify::<H>(MESSAGE, &signature, &public_key[..len]).is_err(),
            "public key cut to {} bytes",
            len
        );
    }
}

#[test]
fn unknown_type_codes_are_rejected() {
    let (mut signing_key, verifying_key) = key_pair(1, None);
    let public_key = verifying_key.as_slice().to_vec();
    let signature = sign(&mut signing_key);
    assert!(verify::<H>(MESSAGE, &signature, &public_key).is_ok());

    // Signature: Nspk (4), q (4), LM-OTS signature starting with its type, LMS type, path.
    let signature_type_offsets = [8, 8 + LMOTS_SIGNATURE_LEN];
    // Public key: L (4), LMS type (4), LM-OTS type (4), I, T[1].
    let public_key_type_offsets = [4, 8];

    for type_code in [0, 0x99, u32::MAX] {
        for offset in signature_type_offsets {
            let mut bad_signature = signature.clone();
            bad_signature[offset..offset + 4].copy_from_slice(&type_code.to_be_bytes());
            assert!(
                verify::<H>(MESSAGE, &bad_signature, &public_key).is_err(),
                "type code {:#x} at signature offset {}",
                type_code,
                offset
            );
        }
        for offset in public_key_type_offsets {
            let mut bad_public_key = public_key.clone();
            bad_public_key[offset..offset + 4].copy_from_slice(&type_code.to_be_bytes());
            assert!(
                verify::<H>(MESSAGE, &signature, &bad_public_key).is_err(),
                "type code {:#x} at public key offset {}",
                type_code,
                offset
            );
        }
    }
}

#[test]
fn too_many_hss_levels_are_rejected() {
    let (mut signing_key, verifying_key) = key_pair(2, None);
    let public_key = verifying_key.as_slice();
    let signature = sign(&mut signing_key);
    assert!(verify::<H>(MESSAGE, &signature, public_key).is_ok());
    assert_eq!(
        signature.len(),
        4 + SIGNED_PUBLIC_KEY_LEN + LMS_SIGNATURE_LEN
    );

    // Nspk (4), one signed public key, the last LMS signature.
    let signed_public_key = &signature[4..4 + SIGNED_PUBLIC_KEY_LEN];
    let last_signature = &signature[4 + SIGNED_PUBLIC_KEY_LEN..];

    for nspk in [8, u32::MAX] {
        let mut bad_signature = nspk.to_be_bytes().to_vec();
        for _ in 0..8 {
            bad_signature.extend_from_slice(signed_public_key);
        }
        bad_signature.extend_from_slice(last_signature);
        assert!(
            verify::<H>(MESSAGE, &bad_signature, public_key).is_err(),
            "Nspk {:#x} with 8 signed public keys",
            nspk
        );
    }
}
