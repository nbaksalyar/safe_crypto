use id::*;
use rand;

#[test]
fn anonymous_bytes_cipher() {
    let mut csprng = rand::OsRng::new().expect("can't create random generator");

    let data = b"Humpty Dumpty sat on a wall";
    let sk = SecretId::new(&mut csprng);
    let sk2 = SecretId::new(&mut csprng);
    let pk = sk.public_id();

    let ciphertext = pk.encrypt_anonymous_bytes(&mut csprng, data);
    assert!(&ciphertext != data);

    let error_res: Result<_, _> = sk.decrypt_anonymous_bytes(data);
    match error_res {
        Err(_e) => (),
        Ok(_) => panic!("Unexpected result: we're using wrong data, it should have returned error"),
    }

    let error_res: Result<_, _> = sk2.decrypt_anonymous_bytes(&ciphertext);
    match error_res {
        Err(_e) => (),
        Ok(_) => {
            panic!("Unexpected result: we're using a wrong key, it should have returned error")
        }
    }

    let plaintext: Vec<u8> = sk
        .decrypt_anonymous_bytes(&ciphertext)
        .expect("couldn't decrypt ciphertext");
    assert!(&plaintext == data);
}

#[test]
fn anonymous_cipher() {
    let mut csprng = rand::OsRng::new().expect("can't create random generator");

    let data: Vec<u64> = vec![4, 5, 6];

    let sk = SecretId::new(&mut csprng);
    let pk = sk.public_id();

    let ciphertext = pk
        .encrypt_anonymous(&mut csprng, &data)
        .expect("couldn't encrypt base data");
    assert!(!ciphertext.is_empty());

    let plaintext: Vec<u64> = sk
        .decrypt_anonymous(&ciphertext)
        .expect("couldn't decrypt ciphertext");
    assert!(plaintext == data);
}

#[test]
fn authenticated_cipher() {
    let mut csprng = rand::OsRng::new().expect("can't create random generator");

    let data = b"Humpty Dumpty had a great fall.";

    let sk1 = SecretId::new(&mut csprng);
    let pk1 = sk1.public_id();

    let sk2 = SecretId::new(&mut csprng);
    let pk2 = sk2.public_id();

    let shared_key1 = sk1.shared_key(&pk2);
    let shared_key2 = sk2.shared_key(&pk1);

    let ciphertext = shared_key1.encrypt_bytes(data);
    assert!(&ciphertext != data);

    let plaintext = shared_key2
        .decrypt_bytes(&ciphertext)
        .expect("couldn't decrypt data");
    assert!(&plaintext == data);

    // Trying with wrong data
    let error_res: Result<_, _> = shared_key2.decrypt_bytes(&plaintext);
    match error_res {
        Err(_e) => (),
        Ok(_) => panic!("Unexpected result: we're using wrong data, it should have returned error"),
    }

    // Trying with a wrong key
    let sk3 = SecretId::new(&mut csprng);
    let shared_key3 = sk3.shared_key(&pk2);

    let error_res: Result<_, _> = shared_key3.decrypt_bytes(&ciphertext);
    match error_res {
        Err(_e) => (),
        Ok(_) => {
            panic!("Unexpected result: we're using a wrong key, it should have returned error")
        }
    }
}

#[test]
fn signing() {
    let mut csprng = rand::OsRng::new().expect("can't create random generator");

    let data1 = b"All the king's horses and all the king's men";
    let data2 = b"Couldn't put Humpty together again";

    let sk1 = SecretId::new(&mut csprng);
    let pk1 = sk1.public_id();

    let sk2 = SecretId::new(&mut csprng);
    let pk2 = sk2.public_id();

    let sig1 = sk1.sign_detached(data1).expect("can't sign");
    let sig2 = sk2.sign_detached(data2).expect("can't sign");

    assert_eq!(
        pk1.verify_detached(&sig1, data1)
            .expect("can't verify signature"),
        true
    );
    assert_eq!(
        pk1.verify_detached(&sig1, data2)
            .expect("can't verify signature"),
        false
    );
    assert_eq!(
        pk1.verify_detached(&sig2, data1)
            .expect("can't verify signature"),
        false
    );
    assert_eq!(
        pk1.verify_detached(&sig2, data2)
            .expect("can't verify signature"),
        false
    );

    assert_eq!(
        pk2.verify_detached(&sig1, data1)
            .expect("can't verify signature"),
        false
    );
    assert_eq!(
        pk2.verify_detached(&sig1, data2)
            .expect("can't verify signature"),
        false
    );
    assert_eq!(
        pk2.verify_detached(&sig2, data1)
            .expect("can't verify signature"),
        false
    );
    assert_eq!(
        pk2.verify_detached(&sig2, data2)
            .expect("can't verify signature"),
        true
    );
}
