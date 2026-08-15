use super::*;

#[test]
fn integrity_is_checked() {
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(b"safe")));
    assert_eq!(
        verify_integrity_digest(b"safe", Some(&digest), "fixture").unwrap(),
        digest
    );
    assert!(verify_integrity(b"changed", Some(&digest), "fixture").is_err());
}

#[test]
fn integrity_errors_redact_url_queries_and_fragments() {
    let source = "https://artifacts.example/package.tgz?token=secret#fragment";

    let error = verify_integrity(b"changed", Some(&"0".repeat(64)), source).unwrap_err();

    assert!(matches!(
        error,
        Error::Fetch { source_url, .. }
            if source_url == "https://artifacts.example/package.tgz"
                && !source_url.contains("secret")
    ));
}

#[test]
fn missing_integrity_errors_redact_url_queries_and_fragments() {
    let source = "https://artifacts.example/package.tgz?token=secret#fragment";

    let error = verify_integrity(b"safe", None, source).unwrap_err();

    assert!(matches!(
        error,
        Error::Policy { message, .. }
            if !message.contains("secret") && !message.contains("fragment")
    ));
}

#[test]
fn npm_integrity_requires_a_decodable_digest_of_the_declared_size() {
    let sha1 = format!("sha1-{}", STANDARD.encode([0_u8; 20]));
    let sha256 = format!("sha256-{}", STANDARD.encode([0_u8; 32]));
    let sha512 = format!("sha512-{}", STANDARD.encode([0_u8; 64]));

    assert!(!supported_npm_integrity(&sha1));
    assert!(supported_npm_integrity(&sha256));
    assert!(supported_npm_integrity(&sha512));
    assert!(supported_npm_integrity(&format!("{sha256} {sha512}")));
    assert!(!supported_npm_integrity("sha512-not-base64"));
    assert!(!supported_npm_integrity(&format!(
        "sha256-{}",
        STANDARD.encode([0_u8; 16])
    )));
}

#[test]
fn npm_integrity_matches_the_strongest_supported_algorithm() {
    let sha1 = format!("sha1-{}", STANDARD.encode([0_u8; 20]));
    let sha256 = format!("sha256-{}", STANDARD.encode(Sha256::digest(b"safe")));
    let sha512 = format!("sha512-{}", STANDARD.encode(Sha512::digest(b"safe")));
    assert!(verify_integrity(b"safe", Some(&sha1), "fixture").is_err());
    assert!(
        verify_integrity(
            b"safe",
            Some(&format!("{sha1} {sha256} {sha512}")),
            "fixture"
        )
        .is_ok()
    );

    let mismatched_sha512 = format!("sha512-{}", STANDARD.encode(Sha512::digest(b"changed")));
    assert!(
        verify_integrity(
            b"safe",
            Some(&format!("{sha256} {mismatched_sha512}")),
            "fixture"
        )
        .is_err()
    );
}

#[test]
fn python_integrity_accepts_any_lock_authorized_sha256_digest() {
    let wrong = format!("sha256:{}", hex::encode(Sha256::digest(b"changed")));
    let correct = format!("sha256:{}", hex::encode(Sha256::digest(b"safe")));

    assert!(verify_integrity(b"safe", Some(&format!("{wrong} {correct}")), "fixture").is_ok());
}

#[test]
fn npm_integrity_accepts_any_matching_digest_from_the_strongest_algorithm() {
    let wrong = format!("sha512-{}", STANDARD.encode(Sha512::digest(b"changed")));
    let correct = format!("sha512-{}", STANDARD.encode(Sha512::digest(b"safe")));

    assert_eq!(
        verify_integrity_digest(b"safe", Some(&format!("{wrong} {correct}")), "fixture").unwrap(),
        correct
    );
}

#[test]
fn digest_verification_distinguishes_sha256_sha512_and_mismatches() {
    let deadline = crate::fetcher::budget::AcquisitionBudget::new(
        std::time::Duration::from_secs(3_600),
        u64::MAX,
    )
    .deadline_guard();
    let raw = sha256_digest_raw_before(b"safe", &deadline).unwrap();
    let hex_sha256 = hex::encode(raw);
    let colon_sha256 = format!("sha256:{hex_sha256}");
    let sri_sha256 = format!("sha256-{}", STANDARD.encode(raw));
    let sri_sha512 = format!("sha512-{}", STANDARD.encode(Sha512::digest(b"safe")));

    // Verified sha256 forms:
    assert_eq!(
        verify_integrity_from_sha256_digest(&raw, Some(&colon_sha256), "fixture", &deadline)
            .unwrap(),
        Some(())
    );
    assert_eq!(
        verify_integrity_from_sha256_digest(&raw, Some(&hex_sha256), "fixture", &deadline).unwrap(),
        Some(())
    );
    assert_eq!(
        verify_integrity_from_sha256_digest(&raw, Some(&sri_sha256), "fixture", &deadline).unwrap(),
        Some(())
    );

    // sha512 needs bytes:
    assert_eq!(
        verify_integrity_from_sha256_digest(&raw, Some(&sri_sha512), "fixture", &deadline).unwrap(),
        None
    );

    // Mismatches fail:
    assert!(
        verify_integrity_from_sha256_digest(
            &raw,
            Some("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
            "fixture",
            &deadline
        )
        .is_err()
    );
    assert!(
        verify_integrity_from_sha256_digest(
            &raw,
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
            "fixture",
            &deadline
        )
        .is_err()
    );
    assert!(
        verify_integrity_from_sha256_digest(
            &raw,
            Some(&format!("sha256-{}", STANDARD.encode([0_u8; 32]))),
            "fixture",
            &deadline
        )
        .is_err()
    );

    // Missing expected fails with Policy error:
    let missing_error =
        verify_integrity_from_sha256_digest(&raw, None, "fixture", &deadline).unwrap_err();
    assert!(matches!(missing_error, Error::Policy { .. }));
}
