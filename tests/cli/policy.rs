use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

use Fixture;

#[test]
fn policy_nist_pbkdf() {
    let ept = Fixture::copy("sample/simple.ept");

    // legacy not allowed
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg("nist")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("--cipher")
        .arg("aes-256-gcm")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "PBKDF algorithm is not permitted by policy",
        ));

    // argon2 not allowed
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg("nist")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("argon2")
        .arg("--cipher")
        .arg("aes-256-gcm")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "PBKDF algorithm is not permitted by policy",
        ));

    // pbkdf2 is allowed
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg("nist")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--cipher")
        .arg("aes-256-gcm")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .success();

    // pbkdf2 requires a minimum iteration count
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg("nist")
        .arg("--pbkdf-params")
        .arg("i=999")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--cipher")
        .arg("aes-256-gcm")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .failure()
        .stderr(predicates::str::contains("Iteration count violates policy"));

    // pbkdf2 requires a minimum iteration count
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg("nist")
        .arg("--pbkdf-params")
        .arg("i=1000")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--cipher")
        .arg("aes-256-gcm")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .success();
}

#[test]
fn policy_nist_cipher() {
    let ept = Fixture::copy("sample/simple.ept");

    // aes-256-gcm is allowed
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg("nist")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--cipher")
        .arg("aes-256-gcm")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .success();

    // aes-256-gcm requires an IV of 12 bytes
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg("nist")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--cipher")
        .arg("aes-256-gcm")
        .arg("--cipher-iv")
        .arg("01020304050607080910111213141516")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "IV length does not match NIST recommendations for this cipher",
        ));
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg("nist")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--cipher")
        .arg("aes-256-gcm")
        .arg("--cipher-iv")
        .arg("010203040506070809101112")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .success();

    // aes-256-siv is not allowed
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg("nist")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Cipher algorithm is not permitted by policy",
        ));

    // aes-256-gcm-siv is not allowed
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg("nist")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--cipher")
        .arg("aes-256-gcm-siv")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Cipher algorithm is not permitted by policy",
        ));
}

#[test]
fn fips_flag() {
    let ept = Fixture::copy("sample/simple.ept");

    // ensure we select some sane defaults
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--fips")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .success()
        .stdout(
            predicates::str::contains("pbkdf:$pbkdf2-sha512$")
                .and(predicates::str::contains("cipher:aes-256-gcm$iv=")),
        );

    // should not be able to set a conflicting policy
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--fips")
        .arg("--policy")
        .arg("none")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Policy setting of 'none' conflicts with --fips",
        ));
}
