use acme::api::{Account, DirectoryMeta, Identifier, Problem, Revocation};

#[test]
fn account_status_matches_the_exact_server_value() {
    let account = Account {
        status: Some("valid".to_owned()),
        ..Default::default()
    };

    assert!(account.is_status_valid());
    assert!(!account.is_status_deactivated());
    assert!(!account.is_status_revoked());
}

#[test]
fn account_exposes_deactivated_and_revoked_states() {
    let deactivated = Account {
        status: Some("deactivated".to_owned()),
        ..Default::default()
    };
    let revoked = Account {
        status: Some("revoked".to_owned()),
        ..Default::default()
    };

    assert!(deactivated.is_status_deactivated());
    assert!(revoked.is_status_revoked());
}

#[test]
fn account_terms_default_to_not_agreed() {
    assert!(!Account::default().terms_of_service_agreed());
}

#[test]
fn account_terms_use_the_camel_case_json_field() {
    let account = serde_json::from_str::<Account>(r#"{"termsOfServiceAgreed":true}"#).unwrap();

    assert!(account.terms_of_service_agreed());
}

#[test]
fn directory_meta_defaults_to_no_external_account_requirement() {
    assert!(!DirectoryMeta::default().external_account_required());
}

#[test]
fn directory_meta_reads_external_account_requirement() {
    let meta =
        serde_json::from_str::<DirectoryMeta>(r#"{"externalAccountRequired":true}"#).unwrap();

    assert!(meta.external_account_required());
}

#[test]
fn problem_display_includes_detail_when_present() {
    let problem = Problem {
        _type: "badNonce".to_owned(),
        detail: Some("nonce expired".to_owned()),
        ..Default::default()
    };

    assert_eq!(problem.to_string(), "badNonce: nonce expired");
}

#[test]
fn problem_display_omits_missing_detail() {
    let problem = Problem {
        _type: "badNonce".to_owned(),
        ..Default::default()
    };

    assert_eq!(problem.to_string(), "badNonce");
}

#[test]
fn identifier_recognizes_only_dns_type() {
    let dns = Identifier {
        _type: "dns".to_owned(),
        value: "example.com".to_owned(),
    };
    let ip = Identifier {
        _type: "ip".to_owned(),
        value: "192.0.2.1".to_owned(),
    };

    assert!(dns.is_type_dns());
    assert!(!ip.is_type_dns());
}

#[test]
fn revocation_omits_unspecified_reason() {
    let revocation = Revocation::new("certificate-der".to_owned(), None);

    assert_eq!(
        serde_json::to_value(revocation).unwrap(),
        serde_json::json!({"certificate": "certificate-der"})
    );
}

#[test]
fn revocation_serializes_reason_code() {
    let revocation = Revocation::new("certificate-der".to_owned(), Some(1));

    assert_eq!(
        serde_json::to_value(revocation).unwrap(),
        serde_json::json!({"certificate": "certificate-der", "reason": 1})
    );
}

#[test]
fn problem_converts_to_displayable_error() {
    let problem = Problem {
        _type: "badNonce".to_owned(),
        detail: Some("nonce expired".to_owned()),
        ..Default::default()
    };

    let error = eyre::Error::from(problem);

    assert_eq!(error.to_string(), "badNonce: nonce expired");
}
