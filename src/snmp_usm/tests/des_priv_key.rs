use snmp_usm::{
    self, DesPrivKey, LocalizedMd5Key, LocalizedSha1Key, PrivKey, SecurityError, SecurityParams,
    WithLocalizedKey,
};

const ENGINE_ID: [u8; 17] = [
    0x80, 0x00, 0x1f, 0x88, 0x80, 0xfa, 0xa8, 0x11, 0x60, 0x0f, 0xa2, 0xc5, 0x5e, 0x00, 0x00, 0x00,
    0x00,
];

#[test]
fn it_encrypts_scoped_pdu_using_localized_md5_key() {
    let priv_key = DesPrivKey::with_localized_key(LocalizedMd5Key::new(b"12345678", &ENGINE_ID));

    let scoped_pdu = vec![
        0x30, 0x30, 0x04, 0x11, 0x80, 0x00, 0x1F, 0x88, 0x80, 0xFA, 0xA8, 0x11, 0x60, 0x0F, 0xA2,
        0xC5, 0x5E, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xA0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01,
        0x00, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01,
        0x01, 0x03, 0x00, 0x05, 0x00,
    ];

    let mut security_params = SecurityParams::new();
    security_params
        .set_engine_id(&ENGINE_ID)
        .set_engine_boots(47);

    let (encrypted_scoped_pdu, salt) = priv_key.encrypt(scoped_pdu, &security_params, 0);

    let expected_scoped_pdu = vec![
        0xD7, 0xD8, 0xF9, 0x8F, 0xD7, 0xF0, 0x80, 0x76, 0x6D, 0xC9, 0xC8, 0x68, 0x41, 0xEE, 0x60,
        0x08, 0x31, 0xC6, 0x69, 0x97, 0x7D, 0xC3, 0x17, 0x7C, 0x9F, 0x30, 0x34, 0xAB, 0x8D, 0xAF,
        0x16, 0xA6, 0x64, 0x89, 0x2D, 0xFB, 0xA6, 0x97, 0x18, 0x84, 0x2B, 0xBA, 0xEC, 0x38, 0x9B,
        0x89, 0x0F, 0x90, 0x84, 0x78, 0xC2, 0x94, 0xFD, 0x4B, 0x97, 0x53,
    ];
    assert_eq!(encrypted_scoped_pdu, expected_scoped_pdu);

    let expected_salt = [0x00, 0x00, 0x00, 0x2F, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(salt, expected_salt);
}

#[test]
fn it_encrypts_scoped_pdu_using_localized_sha1_key() {
    let priv_key = DesPrivKey::with_localized_key(LocalizedSha1Key::new(b"87654321", &ENGINE_ID));

    let scoped_pdu = vec![
        0x30, 0x30, 0x04, 0x11, 0x80, 0x00, 0x1F, 0x88, 0x80, 0xFA, 0xA8, 0x11, 0x60, 0x0F, 0xA2,
        0xC5, 0x5E, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xA0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01,
        0x00, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01,
        0x01, 0x01, 0x00, 0x05, 0x00,
    ];

    let mut security_params = SecurityParams::new();
    security_params
        .set_engine_id(&ENGINE_ID)
        .set_engine_boots(48);

    let (encrypted_scoped_pdu, salt) = priv_key.encrypt(scoped_pdu, &security_params, 0);

    let expected_scoped_pdu = vec![
        0x8F, 0xE2, 0x4F, 0x12, 0x76, 0xA0, 0x13, 0x34, 0x7D, 0x86, 0x63, 0x02, 0xE4, 0x4F, 0x42,
        0x87, 0x4C, 0x94, 0x61, 0x8C, 0xA1, 0xD2, 0x98, 0xF8, 0x8D, 0x69, 0x7E, 0xB1, 0x9A, 0x55,
        0xE9, 0x83, 0xFA, 0xE9, 0xDF, 0x1F, 0x98, 0x61, 0x16, 0x97, 0x81, 0xF1, 0x4A, 0xBA, 0xFA,
        0x09, 0x79, 0x13, 0x77, 0x8C, 0xE6, 0xD6, 0x8C, 0x61, 0xA3, 0xEA,
    ];
    assert_eq!(encrypted_scoped_pdu, expected_scoped_pdu);

    let expected_salt = [0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(salt, expected_salt);
}

#[test]
fn it_decrypts_scoped_pdu_using_localized_md5_key() {
    let priv_key = DesPrivKey::with_localized_key(LocalizedMd5Key::new(b"12345678", &ENGINE_ID));

    let encrypted_scoped_pdu = vec![
        0xA8, 0xB6, 0x99, 0x8C, 0xE0, 0xE2, 0xF7, 0x88, 0x20, 0x6B, 0x55, 0x11, 0x00, 0x17, 0x4A,
        0x78, 0x4C, 0x8B, 0x9D, 0x3B, 0x13, 0xE1, 0xAD, 0x68, 0x0B, 0xBB, 0xFD, 0xDB, 0xE5, 0xCE,
        0x89, 0xF7, 0xB9, 0x57, 0x4B, 0x38, 0xDC, 0x46, 0x76, 0x3F, 0x29, 0xA8, 0x2C, 0x47, 0x00,
        0xF9, 0x37, 0x45, 0x88, 0x33, 0x49, 0x6D, 0x7E, 0x19, 0x50, 0xFF,
    ];
    let mut security_params = SecurityParams::new();
    security_params.set_priv_params(&[0x00, 0x00, 0x00, 0x30, 0x1F, 0xFF, 0x4A, 0x99]);

    let decrypted_scoped_pdu = priv_key
        .decrypt(encrypted_scoped_pdu, &security_params)
        .unwrap();

    let expected = vec![
        0x30, 0x33, 0x04, 0x11, 0x80, 0x00, 0x1F, 0x88, 0x80, 0xFA, 0xA8, 0x11, 0x60, 0x0F, 0xA2,
        0xC5, 0x5E, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xA2, 0x1C, 0x02, 0x01, 0x01, 0x02, 0x01,
        0x00, 0x02, 0x01, 0x00, 0x30, 0x11, 0x30, 0x0F, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01,
        0x01, 0x03, 0x00, 0x43, 0x03, 0x02, 0x20, 0x3B, 0x03, 0x03, 0x03,
    ];
    assert_eq!(decrypted_scoped_pdu, expected);
}

#[test]
fn it_decrypts_scoped_pdu_using_localized_sha1_key() {
    let priv_key = DesPrivKey::with_localized_key(LocalizedSha1Key::new(b"87654321", &ENGINE_ID));

    let encrypted_scoped_pdu = vec![
        0x1F, 0xD0, 0x02, 0xD1, 0x7E, 0xAF, 0xDC, 0x6C, 0x00, 0xFC, 0x32, 0x44, 0x28, 0xAA, 0xFB,
        0x76, 0x99, 0x3D, 0x94, 0xFD, 0x57, 0xB5, 0x5F, 0xC6, 0x87, 0xA2, 0x81, 0x73, 0xB8, 0xAB,
        0x77, 0x29, 0x7E, 0xE5, 0x9F, 0xCE, 0x13, 0xDA, 0xF7, 0xDF, 0xD7, 0xD6, 0xC3, 0xD6, 0x7A,
        0x7E, 0xDA, 0x4A, 0xC8, 0xBF, 0x43, 0x5E, 0xD2, 0xE5, 0xE6, 0xAE, 0x45, 0x5D, 0xA8, 0x64,
        0x42, 0x94, 0x17, 0x44, 0x7B, 0x61, 0xEC, 0xBE, 0xC3, 0xF6, 0xFF, 0x64, 0x4B, 0x55, 0x51,
        0x79, 0x67, 0x90, 0x8E, 0x14, 0x3B, 0xF6, 0xA3, 0xCA, 0x85, 0xC7, 0xC5, 0xA7, 0xC9, 0x29,
        0x3E, 0x43, 0xC6, 0x3F, 0xE0, 0x9F, 0x23, 0x50, 0x8D, 0x97, 0x14, 0xC5, 0x8C, 0xC4, 0x51,
        0x32, 0xFE, 0xF6, 0x4D, 0x22, 0x65, 0xC4, 0x5E, 0x99, 0xA9, 0xD2, 0x80, 0xB8, 0x57, 0x5C,
        0x4D, 0xA0, 0xBC, 0xAE, 0x10, 0x54, 0x1D, 0x5E, 0xE4, 0x7F, 0xAF, 0xE1, 0x70, 0x69, 0x4F,
        0x15, 0xC6, 0x75, 0xAB, 0x69, 0x35, 0xAE, 0x1D, 0x29, 0xE9, 0x2F, 0x7C, 0x9F, 0xF3, 0x70,
        0x92, 0xDF, 0xF0, 0x30, 0x73, 0x98, 0xE3, 0x80, 0xEE, 0x86, 0xA3, 0x2D, 0xCC, 0xE5, 0x7F,
        0xC2, 0x6D, 0xCE, 0xE8, 0xD2, 0xA4, 0x56, 0x14, 0x86, 0x0E, 0x76, 0x87, 0xC4, 0xB3, 0x00,
        0x0B, 0x0E, 0xD9, 0xCD, 0x2C, 0x8A, 0xAD, 0xBE, 0xEF, 0xE7, 0x86, 0x4C,
    ];
    let mut security_params = SecurityParams::new();
    security_params.set_priv_params(&[0x00, 0x00, 0x00, 0x30, 0x1F, 0xFF, 0x4A, 0x9A]);

    let decrypted_scoped_pdu = priv_key
        .decrypt(encrypted_scoped_pdu, &security_params)
        .unwrap();

    let expected = vec![
        0x30, 0x81, 0xB8, 0x04, 0x11, 0x80, 0x00, 0x1F, 0x88, 0x80, 0xFA, 0xA8, 0x11, 0x60, 0x0F,
        0xA2, 0xC5, 0x5E, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xA2, 0x81, 0xA0, 0x02, 0x01, 0x01,
        0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x81, 0x94, 0x30, 0x81, 0x91, 0x06, 0x08, 0x2B,
        0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x04, 0x81, 0x84, 0x44, 0x61, 0x72, 0x77, 0x69,
        0x6E, 0x20, 0x64, 0x61, 0x76, 0x69, 0x64, 0x73, 0x2D, 0x6D, 0x62, 0x70, 0x2E, 0x6C, 0x61,
        0x6E, 0x20, 0x31, 0x39, 0x2E, 0x35, 0x2E, 0x30, 0x20, 0x44, 0x61, 0x72, 0x77, 0x69, 0x6E,
        0x20, 0x4B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E,
        0x20, 0x31, 0x39, 0x2E, 0x35, 0x2E, 0x30, 0x3A, 0x20, 0x54, 0x75, 0x65, 0x20, 0x4D, 0x61,
        0x79, 0x20, 0x32, 0x36, 0x20, 0x32, 0x30, 0x3A, 0x34, 0x31, 0x3A, 0x34, 0x34, 0x20, 0x50,
        0x44, 0x54, 0x20, 0x32, 0x30, 0x32, 0x30, 0x3B, 0x20, 0x72, 0x6F, 0x6F, 0x74, 0x3A, 0x78,
        0x6E, 0x75, 0x2D, 0x36, 0x31, 0x35, 0x33, 0x2E, 0x31, 0x32, 0x31, 0x2E, 0x32, 0x7E, 0x32,
        0x2F, 0x52, 0x45, 0x4C, 0x45, 0x41, 0x53, 0x45, 0x5F, 0x58, 0x38, 0x36, 0x5F, 0x36, 0x34,
        0x20, 0x78, 0x38, 0x36, 0x5F, 0x36, 0x34, 0x05, 0x05, 0x05, 0x05, 0x05,
    ];
    assert_eq!(decrypted_scoped_pdu, expected);
}

#[test]
fn it_returns_error_for_priv_params_with_wrong_len() {
    let priv_key = DesPrivKey::with_localized_key(LocalizedSha1Key::new(b"87654321", &ENGINE_ID));

    let encrypted_scoped_pdu = vec![
        0x49, 0xDB, 0x95, 0xBC, 0xBF, 0xC3, 0x78, 0x60, 0xE0, 0x4B, 0x67, 0xDE, 0xD1, 0xBF, 0xED,
        0x3B, 0x46, 0x7F, 0x6A, 0x23, 0x7B, 0x61, 0x80, 0x6E, 0x49, 0x89, 0xC, 0x21, 0x59, 0x77,
        0xF0, 0x2F, 0x14, 0x6E, 0xE3, 0xF9, 0x76, 0xBD, 0x86, 0x64, 0x22, 0x8A, 0x1D, 0x31, 0x17,
        0x7B, 0x40, 0x5C, 0x9C, 0x40, 0xB7, 0xFC, 0x68, 0x79, 0x5A, 0xC4,
    ];
    let mut security_params = SecurityParams::new();
    security_params
        // Missing last byte 0x9B.
        .set_priv_params(&[0x00, 0x00, 0x00, 0x30, 0x1F, 0xFF, 0x4A]);

    let result = priv_key.decrypt(encrypted_scoped_pdu, &security_params);
    assert_eq!(result, Err(SecurityError::DecryptError));
}

#[test]
fn it_returns_empty_vec_when_encrypting_empty_scoped_pdu() {
    let priv_key = DesPrivKey::with_localized_key(LocalizedMd5Key::new(b"12345678", &ENGINE_ID));

    let scoped_pdu = vec![];

    let mut security_params = SecurityParams::new();
    security_params
        .set_engine_id(&ENGINE_ID)
        .set_engine_boots(47);

    let (encrypted_scoped_pdu, salt) = priv_key.encrypt(scoped_pdu, &security_params, 0);
    assert_eq!(encrypted_scoped_pdu, vec![]);

    let expected_salt = [0x00, 0x00, 0x00, 0x2F, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(salt, expected_salt);
}

#[test]
fn it_returns_empty_vec_when_decrypting_empty_scoped_pdu() {
    let priv_key = DesPrivKey::with_localized_key(LocalizedMd5Key::new(b"12345678", &ENGINE_ID));

    let encrypted_scoped_pdu = vec![];
    let mut security_params = SecurityParams::new();
    security_params.set_priv_params(&[0x00, 0x00, 0x00, 0x30, 0x1F, 0xFF, 0x4A, 0x99]);

    let decrypted_scoped_pdu = priv_key
        .decrypt(encrypted_scoped_pdu, &security_params)
        .unwrap();

    assert_eq!(decrypted_scoped_pdu, vec![]);
}
