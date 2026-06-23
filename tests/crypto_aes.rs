use pretty_assertions::assert_eq;
use rskrb5::crypto::{
    AesSha1Etype, AesSha2Etype, Error, KerberosEtype, Rc4HmacEtype, iterations_to_s2kparams, nfold,
    s2kparams_to_iterations,
};

#[test]
fn reports_aes_sha1_metadata() {
    assert_eq!(AesSha1Etype::from_etype_id(17), Some(AesSha1Etype::Aes128));
    assert_eq!(AesSha1Etype::from_etype_id(18), Some(AesSha1Etype::Aes256));
    assert_eq!(AesSha1Etype::from_etype_id(23), None);

    assert_eq!(AesSha1Etype::Aes128.etype_id(), 17);
    assert_eq!(AesSha1Etype::Aes128.checksum_type_id(), 15);
    assert_eq!(AesSha1Etype::Aes128.key_len(), 16);
    assert_eq!(AesSha1Etype::Aes128.confounder_len(), 16);
    assert_eq!(AesSha1Etype::Aes128.hmac_len(), 12);
    assert_eq!(AesSha1Etype::Aes128.default_s2kparams(), "00001000");

    assert_eq!(AesSha1Etype::Aes256.etype_id(), 18);
    assert_eq!(AesSha1Etype::Aes256.checksum_type_id(), 16);
    assert_eq!(AesSha1Etype::Aes256.key_len(), 32);
    assert_eq!(AesSha1Etype::Aes256.default_s2kparams(), "00001000");
}

#[test]
fn reports_aes_sha2_metadata_and_dispatch() {
    assert_eq!(AesSha2Etype::from_etype_id(19), Some(AesSha2Etype::Aes128));
    assert_eq!(AesSha2Etype::from_etype_id(20), Some(AesSha2Etype::Aes256));
    assert_eq!(AesSha2Etype::from_etype_id(18), None);

    assert_eq!(AesSha2Etype::Aes128.etype_id(), 19);
    assert_eq!(AesSha2Etype::Aes128.checksum_type_id(), 19);
    assert_eq!(AesSha2Etype::Aes128.ename(), "aes128-cts-hmac-sha256-128");
    assert_eq!(AesSha2Etype::Aes128.key_len(), 16);
    assert_eq!(AesSha2Etype::Aes128.confounder_len(), 16);
    assert_eq!(AesSha2Etype::Aes128.hmac_len(), 16);
    assert_eq!(AesSha2Etype::Aes128.default_s2kparams(), "00008000");

    assert_eq!(AesSha2Etype::Aes256.etype_id(), 20);
    assert_eq!(AesSha2Etype::Aes256.checksum_type_id(), 20);
    assert_eq!(AesSha2Etype::Aes256.ename(), "aes256-cts-hmac-sha384-192");
    assert_eq!(AesSha2Etype::Aes256.key_len(), 32);
    assert_eq!(AesSha2Etype::Aes256.hmac_len(), 24);
    assert_eq!(AesSha2Etype::Aes256.default_s2kparams(), "00008000");

    assert_eq!(
        KerberosEtype::from_etype_id(17),
        Some(KerberosEtype::Sha1(AesSha1Etype::Aes128))
    );
    assert_eq!(
        KerberosEtype::from_etype_id(20),
        Some(KerberosEtype::Sha2(AesSha2Etype::Aes256))
    );
    assert_eq!(
        KerberosEtype::from_checksum_type_id(19),
        Some(KerberosEtype::Sha2(AesSha2Etype::Aes128))
    );
    assert_eq!(
        KerberosEtype::from_etype_id(23),
        Some(KerberosEtype::Rc4Hmac(Rc4HmacEtype))
    );

    let dispatcher = KerberosEtype::Sha1(AesSha1Etype::Aes256);
    assert_eq!(dispatcher.etype_id(), 18);
}

#[test]
fn converts_s2kparams_iteration_counts() {
    assert_eq!(iterations_to_s2kparams(1), "00000001");
    assert_eq!(iterations_to_s2kparams(4096), "00001000");
    assert_eq!(s2kparams_to_iterations("00001000"), Ok(4096));

    assert!(matches!(
        s2kparams_to_iterations("001000"),
        Err(Error::InvalidS2kParamsLength(6))
    ));
    assert!(matches!(
        s2kparams_to_iterations("0000000z"),
        Err(Error::InvalidS2kParamsHex('z'))
    ));
    assert!(matches!(
        s2kparams_to_iterations("00000000"),
        Err(Error::UnsupportedIterationCountZero)
    ));
}

#[test]
fn nfold_matches_gokrb5_vectors() {
    let tests = [
        (64, b"012345".as_slice(), "be072631276b1955"),
        (56, b"password".as_slice(), "78a07b6caf85fa"),
        (
            64,
            b"Rough Consensus, and Running Code".as_slice(),
            "bb6ed30870b7f0e0",
        ),
        (
            168,
            b"password".as_slice(),
            "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e",
        ),
        (
            192,
            b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY".as_slice(),
            "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
        ),
        (
            168,
            b"Q".as_slice(),
            "518a54a215a8452a518a54a215a8452a518a54a215",
        ),
        (
            168,
            b"ba".as_slice(),
            "fb25d531ae8974499f52fd92ea9857c4ba24cf297e",
        ),
    ];

    for (bits, input, expected) in tests {
        assert_eq!(
            hex_encode(&nfold(input, bits).expect("n-fold succeeds")),
            expected
        );
    }
}

#[test]
fn aes128_string_to_key_matches_gokrb5_vectors() {
    let binary_salt = decode_hex("1234567878563412");
    let musical_symbol = decode_hex("f09d849e");
    let tests = [
        StringToKeyVector {
            iterations: 1,
            phrase: b"password".as_slice(),
            salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
            pbkdf2: "cdedb5281bb2f801565a1122b2563515",
            key: "42263c6e89f4fc28b8df68ee09799f15",
        },
        StringToKeyVector {
            iterations: 2,
            phrase: b"password".as_slice(),
            salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
            pbkdf2: "01dbee7f4a9e243e988b62c73cda935d",
            key: "c651bf29e2300ac27fa469d693bdda13",
        },
        StringToKeyVector {
            iterations: 1200,
            phrase: b"password".as_slice(),
            salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
            pbkdf2: "5c08eb61fdf71e4e4ec3cf6ba1f5512b",
            key: "4c01cd46d632d01e6dbe230a01ed642a",
        },
        StringToKeyVector {
            iterations: 5,
            phrase: b"password".as_slice(),
            salt: binary_salt.as_slice(),
            pbkdf2: "d1daa78615f287e6a1c8b120d7062a49",
            key: "e9b23d52273747dd5c35cb55be619d8e",
        },
        StringToKeyVector {
            iterations: 1200,
            phrase: b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".as_slice(),
            salt: b"pass phrase equals block size".as_slice(),
            pbkdf2: "139c30c0966bc32ba55fdbf212530ac9",
            key: "59d1bb789a828b1aa54ef9c2883f69ed",
        },
        StringToKeyVector {
            iterations: 1200,
            phrase: b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".as_slice(),
            salt: b"pass phrase exceeds block size".as_slice(),
            pbkdf2: "9ccad6d468770cd51b10e6a68721be61",
            key: "cb8005dc5f90179a7f02104c0018751d",
        },
        StringToKeyVector {
            iterations: 50,
            phrase: musical_symbol.as_slice(),
            salt: b"EXAMPLE.COMpianist".as_slice(),
            pbkdf2: "6b9cf26d45455a43a5b8bb276a403b39",
            key: "f149c1f2e154a73452d43e7fe62a56e5",
        },
    ];

    assert_string_to_key_vectors(AesSha1Etype::Aes128, &tests);
}

#[test]
fn aes256_string_to_key_matches_gokrb5_vectors() {
    let binary_salt = decode_hex("1234567878563412");
    let musical_symbol = decode_hex("f09d849e");
    let tests = [
        StringToKeyVector {
            iterations: 1,
            phrase: b"password".as_slice(),
            salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
            pbkdf2: "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837",
            key: "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
        },
        StringToKeyVector {
            iterations: 2,
            phrase: b"password".as_slice(),
            salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
            pbkdf2: "01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86",
            key: "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff",
        },
        StringToKeyVector {
            iterations: 1200,
            phrase: b"password".as_slice(),
            salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
            pbkdf2: "5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13",
            key: "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a",
        },
        StringToKeyVector {
            iterations: 5,
            phrase: b"password".as_slice(),
            salt: binary_salt.as_slice(),
            pbkdf2: "d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee",
            key: "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31",
        },
        StringToKeyVector {
            iterations: 1200,
            phrase: b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".as_slice(),
            salt: b"pass phrase equals block size".as_slice(),
            pbkdf2: "139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1",
            key: "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34",
        },
        StringToKeyVector {
            iterations: 1200,
            phrase: b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".as_slice(),
            salt: b"pass phrase exceeds block size".as_slice(),
            pbkdf2: "9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a",
            key: "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b",
        },
        StringToKeyVector {
            iterations: 50,
            phrase: musical_symbol.as_slice(),
            salt: b"EXAMPLE.COMpianist".as_slice(),
            pbkdf2: "6b9cf26d45455a43a5b8bb276a403b39e7fe37a0c41e02c281ff3069e1e94f52",
            key: "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e",
        },
    ];

    assert_string_to_key_vectors(AesSha1Etype::Aes256, &tests);
}

#[test]
fn aes_sha2_string_to_key_matches_gokrb5_vectors() {
    let random = decode_hex("10df9dd783e5bc8acea1730e74355f61");
    let mut salt = random;
    salt.extend_from_slice(b"ATHENA.MIT.EDUraeburn");

    let tests = [
        Sha2StringToKeyVector {
            etype: AesSha2Etype::Aes128,
            iterations: 32768,
            phrase: b"password".as_slice(),
            salt: salt.as_slice(),
            saltp: "6165733132382d6374732d686d61632d7368613235362d3132380010df9dd783e5bc8acea1730e74355f61415448454e412e4d49542e4544557261656275726e",
            key: "089bca48b105ea6ea77ca5d2f39dc5e7",
        },
        Sha2StringToKeyVector {
            etype: AesSha2Etype::Aes256,
            iterations: 32768,
            phrase: b"password".as_slice(),
            salt: salt.as_slice(),
            saltp: "6165733235362d6374732d686d61632d7368613338342d3139320010df9dd783e5bc8acea1730e74355f61415448454e412e4d49542e4544557261656275726e",
            key: "45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467",
        },
    ];

    for test in tests {
        assert_eq!(hex_encode(&test.etype.saltp(test.salt)), test.saltp);
        let key = test
            .etype
            .string_to_key(
                test.phrase,
                test.salt,
                &iterations_to_s2kparams(test.iterations),
            )
            .expect("AES-SHA2 string-to-key succeeds");
        assert_eq!(hex_encode(&key), test.key);
    }
}

#[test]
fn aes128_sha2_derive_checksum_integrity_and_crypto_match_gokrb5_vectors() {
    assert_sha2_derive_vectors(
        AesSha2Etype::Aes128,
        "3705d96080c17728a0e800eab6e0d23c",
        "b31a018a48f54776f403e9a396325dc3",
        "9b197dd1e8c5609d6e67c3e37c62c72e",
        "9fda0e56ab2d85e1569a688696c26a6c",
    );
    assert_sha2_checksum_vector(
        AesSha2Etype::Aes128,
        "3705d96080c17728a0e800eab6e0d23c",
        "000102030405060708090a0b0c0d0e0f1011121314",
        "d78367186643d67b411cba9139fc1dee",
    );
    assert_sha2_crypto_vectors(
        AesSha2Etype::Aes128,
        "3705d96080c17728a0e800eab6e0d23c",
        &[
            Sha2CryptoVector {
                plain: "",
                confounder: "7e5895eaf2672435bad817f545a37148",
                ke: "9b197dd1e8c5609d6e67c3e37c62c72e",
                encrypted: "ef85fb890bb8472f4dab20394dca781d",
                cipher: "ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718",
            },
            Sha2CryptoVector {
                plain: "000102030405",
                confounder: "7bca285e2fd4130fb55b1a5c83bc5b24",
                ke: "9b197dd1e8c5609d6e67c3e37c62c72e",
                encrypted: "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6",
                cipher: "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6877ce99e247e52d16ed4421dfdf8976c",
            },
            Sha2CryptoVector {
                plain: "000102030405060708090a0b0c0d0e0f",
                confounder: "56ab21713ff62c0a1457200f6fa9948f",
                ke: "9b197dd1e8c5609d6e67c3e37c62c72e",
                encrypted: "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc2",
                cipher: "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc295fb4852e7d83e1e7c48c37eebe6b0d3",
            },
            Sha2CryptoVector {
                plain: "000102030405060708090a0b0c0d0e0f1011121314",
                confounder: "a7a4e29a4728ce10664fb64e49ad3fac",
                ke: "9b197dd1e8c5609d6e67c3e37c62c72e",
                encrypted: "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c1",
                cipher: "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c186b39a413c2f92ca9b8334a287ffcbfc",
            },
        ],
    );
}

#[test]
fn aes256_sha2_derive_checksum_integrity_and_crypto_match_gokrb5_vectors() {
    assert_sha2_derive_vectors(
        AesSha2Etype::Aes256,
        "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
        "ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d",
        "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
        "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f",
    );
    assert_sha2_checksum_vector(
        AesSha2Etype::Aes256,
        "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
        "000102030405060708090a0b0c0d0e0f1011121314",
        "45ee791567eefca37f4ac1e0222de80d43c3bfa06699672a",
    );
    assert_sha2_crypto_vectors(
        AesSha2Etype::Aes256,
        "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
        &[
            Sha2CryptoVector {
                plain: "",
                confounder: "f764e9fa15c276478b2c7d0c4e5f58e4",
                ke: "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
                encrypted: "41f53fa5bfe7026d91faf9be959195a0",
                cipher: "41f53fa5bfe7026d91faf9be959195a058707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c",
            },
            Sha2CryptoVector {
                plain: "000102030405",
                confounder: "b80d3251c1f6471494256ffe712d0b9a",
                ke: "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
                encrypted: "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9",
                cipher: "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2",
            },
            Sha2CryptoVector {
                plain: "000102030405060708090a0b0c0d0e0f",
                confounder: "53bf8a0d105265d4e276428624ce5e63",
                ke: "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
                encrypted: "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f6",
                cipher: "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f68cf51f14d798c2273f35df574d1f932e40c4ff255b36a266",
            },
            Sha2CryptoVector {
                plain: "000102030405060708090a0b0c0d0e0f1011121314",
                confounder: "763e65367e864f02f55153c7e3b58af1",
                ke: "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
                encrypted: "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86",
                cipher: "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62",
            },
        ],
    );
}

#[test]
fn aes_cts_encrypts_and_decrypts_rfc3962_vectors() {
    let key = decode_hex("636869636b656e207465726979616b69");
    let tests = [
        AesCtsVector {
            plain: "4920776f756c64206c696b652074686520",
            cipher: "c6353568f2bf8cb4d8a580362da7ff7f97",
            next_iv: "c6353568f2bf8cb4d8a580362da7ff7f",
        },
        AesCtsVector {
            plain: "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
            cipher: "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
            next_iv: "fc00783e0efdb2c1d445d4c8eff7ed22",
        },
        AesCtsVector {
            plain: "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
            cipher: "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
            next_iv: "39312523a78662d5be7fcbcc98ebf5a8",
        },
        AesCtsVector {
            plain: "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c",
            cipher: "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5",
            next_iv: "b3fffd940c16a18c1b5549d2f838029e",
        },
        AesCtsVector {
            plain: "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20",
            cipher: "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8",
            next_iv: "9dad8bbb96c4cdc03bc103e1a194bbd8",
        },
        AesCtsVector {
            plain: "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
            cipher: "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
            next_iv: "4807efe836ee89a526730dbc2f7bc840",
        },
    ];

    for test in tests {
        let plain = decode_hex(test.plain);
        let (next_iv, cipher) = AesSha1Etype::Aes128
            .encrypt_data(&key, &plain)
            .expect("AES-CTS encrypts");
        assert_eq!(hex_encode(&cipher), test.cipher);
        assert_eq!(hex_encode(&next_iv), test.next_iv);

        let decrypted = AesSha1Etype::Aes128
            .decrypt_data(&key, &cipher)
            .expect("AES-CTS decrypts");
        assert_eq!(decrypted, plain);
    }
}

#[test]
fn checksums_and_messages_match_gokrb5_aes128() {
    assert_checksum_and_message_vector(
        AesSha1Etype::Aes128,
        "42263c6e89f4fc28b8df68ee09799f15",
        "2b8e69736fe39ecdf288436e",
        "57269a6fb1a2e5d4fc8d9749767e7d75f4d31ac8b66531ebf1f81ad3f7fb1cc7fd0311164f604577ae6aa6b22c79ac59ca7e",
    );
}

#[test]
fn checksums_and_messages_match_gokrb5_aes256() {
    assert_checksum_and_message_vector(
        AesSha1Etype::Aes256,
        "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
        "eff61bf5eb38bc0ea3c18200",
        "c4408e3c7e212d5f11805303ebd1f356d64a289ce228bfd159e34294fb4448204512c3757ae2bd207cd0adbcc44ed0e6ef47",
    );
}

#[test]
fn rejects_invalid_crypto_inputs() {
    assert!(matches!(
        AesSha1Etype::Aes128.encrypt_data(&[0; 15], b"x"),
        Err(Error::InvalidKeyLength {
            expected: 16,
            actual: 15
        })
    ));
    assert!(matches!(
        AesSha1Etype::Aes128.encrypt_data(&[0; 16], b""),
        Err(Error::EmptyPlaintext)
    ));
    assert!(matches!(
        AesSha1Etype::Aes128.decrypt_data(&[0; 16], &[0; 15]),
        Err(Error::CiphertextTooShort {
            minimum: 16,
            actual: 15
        })
    ));
    assert!(matches!(
        AesSha1Etype::Aes128.encrypt_message_with_confounder(&[0; 16], b"x", 1, &[0; 15]),
        Err(Error::InvalidConfounderLength {
            expected: 16,
            actual: 15
        })
    ));
}

struct StringToKeyVector<'a> {
    iterations: u32,
    phrase: &'a [u8],
    salt: &'a [u8],
    pbkdf2: &'a str,
    key: &'a str,
}

struct Sha2StringToKeyVector<'a> {
    etype: AesSha2Etype,
    iterations: u32,
    phrase: &'a [u8],
    salt: &'a [u8],
    saltp: &'a str,
    key: &'a str,
}

fn assert_string_to_key_vectors(etype: AesSha1Etype, tests: &[StringToKeyVector<'_>]) {
    for test in tests {
        let pbkdf2 = etype.string_to_pbkdf2(test.phrase, test.salt, test.iterations);
        assert_eq!(hex_encode(&pbkdf2), test.pbkdf2);

        let s2kparams = iterations_to_s2kparams(test.iterations);
        let key = etype
            .string_to_key(test.phrase, test.salt, &s2kparams)
            .expect("string-to-key succeeds");
        assert_eq!(hex_encode(&key), test.key);
    }
}

struct Sha2CryptoVector<'a> {
    plain: &'a str,
    confounder: &'a str,
    ke: &'a str,
    encrypted: &'a str,
    cipher: &'a str,
}

fn assert_sha2_derive_vectors(
    etype: AesSha2Etype,
    key_hex: &str,
    kc_hex: &str,
    ke_hex: &str,
    ki_hex: &str,
) {
    let key = decode_hex(key_hex);
    assert_eq!(
        hex_encode(
            &etype
                .derive_key(&key, &usage_constant(2, 0x99))
                .expect("Kc derives")
        ),
        kc_hex
    );
    assert_eq!(
        hex_encode(
            &etype
                .derive_key(&key, &usage_constant(2, 0xaa))
                .expect("Ke derives")
        ),
        ke_hex
    );
    assert_eq!(
        hex_encode(
            &etype
                .derive_key(&key, &usage_constant(2, 0x55))
                .expect("Ki derives")
        ),
        ki_hex
    );
}

fn assert_sha2_checksum_vector(
    etype: AesSha2Etype,
    key_hex: &str,
    data_hex: &str,
    checksum_hex: &str,
) {
    let key = decode_hex(key_hex);
    let data = decode_hex(data_hex);
    let checksum = etype
        .checksum(&key, &data, 2)
        .expect("AES-SHA2 checksum succeeds");
    assert_eq!(hex_encode(&checksum), checksum_hex);
    assert!(etype.verify_checksum(&key, &data, &checksum, 2));
    assert!(!etype.verify_checksum(&key, b"tampered", &checksum, 2));
}

fn assert_sha2_crypto_vectors(etype: AesSha2Etype, key_hex: &str, tests: &[Sha2CryptoVector<'_>]) {
    let key = decode_hex(key_hex);

    for test in tests {
        let plain = decode_hex(test.plain);
        let confounder = decode_hex(test.confounder);
        let ke = decode_hex(test.ke);

        let mut confounded = confounder.clone();
        confounded.extend_from_slice(&plain);
        let (_, encrypted) = etype
            .encrypt_data(&ke, &confounded)
            .expect("AES-SHA2 raw data encrypts");
        assert_eq!(hex_encode(&encrypted), test.encrypted);
        assert_eq!(
            etype
                .decrypt_data(&ke, &encrypted)
                .expect("AES-SHA2 raw data decrypts"),
            confounded
        );

        let cipher = etype
            .encrypt_message_with_confounder(&key, &plain, 2, &confounder)
            .expect("AES-SHA2 message encrypts");
        assert_eq!(hex_encode(&cipher), test.cipher);
        assert_eq!(
            etype
                .decrypt_message(&key, &cipher, 2)
                .expect("AES-SHA2 message decrypts"),
            plain
        );

        let mut tampered = cipher;
        tampered[0] ^= 0x01;
        assert!(matches!(
            etype.decrypt_message(&key, &tampered, 2),
            Err(Error::IntegrityCheckFailed)
        ));
    }
}

struct AesCtsVector<'a> {
    plain: &'a str,
    cipher: &'a str,
    next_iv: &'a str,
}

fn usage_constant(usage: u32, suffix: u8) -> [u8; 5] {
    let usage = usage.to_be_bytes();
    [usage[0], usage[1], usage[2], usage[3], suffix]
}

fn assert_checksum_and_message_vector(
    etype: AesSha1Etype,
    key_hex: &str,
    checksum_hex: &str,
    encrypted_hex: &str,
) {
    let usage = 1027;
    let key = decode_hex(key_hex);
    let confounder = decode_hex("000102030405060708090a0b0c0d0e0f");
    let checksum_data = b"gokrb5 checksum fixture";
    let message = b"gokrb5 message fixture";

    let checksum = etype
        .checksum(&key, checksum_data, usage)
        .expect("checksum succeeds");
    assert_eq!(hex_encode(&checksum), checksum_hex);
    assert!(etype.verify_checksum(&key, checksum_data, &checksum, usage));
    assert!(!etype.verify_checksum(&key, b"tampered", &checksum, usage));

    let encrypted = etype
        .encrypt_message_with_confounder(&key, message, usage, &confounder)
        .expect("message encrypts");
    assert_eq!(hex_encode(&encrypted), encrypted_hex);

    let decrypted = etype
        .decrypt_message(&key, &encrypted, usage)
        .expect("message decrypts");
    assert_eq!(decrypted, message);

    let mut tampered = encrypted;
    tampered[0] ^= 0x01;
    assert!(matches!(
        etype.decrypt_message(&key, &tampered, usage),
        Err(Error::IntegrityCheckFailed)
    ));
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_value(pair[0]) << 4) | hex_value(pair[1]))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}
