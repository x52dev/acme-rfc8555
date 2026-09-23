use acme::api::{Account, DirectoryMeta, Problem};

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
