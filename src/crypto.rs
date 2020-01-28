// Copyright (c) 2019-2020 [Ribose Inc](https://www.ribose.com).
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use phf::phf_map;
use std::collections::BTreeMap;

use consts;

pub static BOTAN_HASH_ALG_MAP: phf::Map<&'static str, &'static str> = phf_map! {
    "sha256" => "SHA-256",
    "sha512" => "SHA-512",
    "sha3-256" => "SHA-3(256)",
    "sha3-512" => "SHA-3(512)",
};

pub fn to_botan_hash(alg: &str) -> Result<&'static str, &'static str> {
    Ok(BOTAN_HASH_ALG_MAP
        .get::<str>(alg)
        .ok_or("Unrecognized hash algorithm")?)
}

pub trait CryptoPolicy {
    fn check_hash(&self, _alg: &str) -> Result<(), &'static str> {
        Ok(())
    }

    fn check_pbkdf(
        &self,
        _alg: &str,
        _key_len: usize,
        _password: &str,
        _salt: &[u8],
        _params: &BTreeMap<String, usize>,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    fn check_cipher(
        &self,
        _alg: &str,
        _key: &[u8],
        _iv: &[u8],
        _ad: &[u8],
    ) -> Result<(), &'static str> {
        Ok(())
    }
}

pub struct CryptoPolicyDefault {}

impl CryptoPolicyDefault {
    pub fn new() -> CryptoPolicyDefault {
        CryptoPolicyDefault {
            ciphers: &consts::NIST_APPROVED_CIPHERS,
            hashes: &consts::NIST_APPROVED_HASHES,
            pbkdfs: &consts::NIST_APPROVED_PBKDFS,
        }
    }

    fn check_alg(&self, kind: &str, alg: &str) -> Result<(), &'static str> {
        let lst = match kind {
            "Cipher" => &self.ciphers,
            "Hash" => &self.hashes,
            "PBKDF" => &self.pbkdfs,
            _ => return Err("Invalid algorithm kind"),
        };
        if lst.contains(alg) {
            Ok(())
        } else {
            eprintln!("{} algorithm is not permitted by policy: {}", kind, alg);
            Err("Algorithm not permitted by policy")
        }
    }
}

impl CryptoPolicy for CryptoPolicyDefault {}

pub struct CryptoPolicyNIST {
    pub ciphers: &'static phf::Set<&'static str>,
    pub hashes: &'static phf::Set<&'static str>,
    pub pbkdfs: &'static phf::Set<&'static str>,
}

impl CryptoPolicyNIST {
    pub fn new() -> CryptoPolicyNIST {
        CryptoPolicyNIST {
            ciphers: &consts::NIST_APPROVED_CIPHERS,
            hashes: &consts::NIST_APPROVED_HASHES,
            pbkdfs: &consts::NIST_APPROVED_PBKDFS,
        }
    }

    fn check_alg(&self, kind: &str, alg: &str) -> Result<(), &'static str> {
        let lst = match kind {
            "Cipher" => &self.ciphers,
            "Hash" => &self.hashes,
            "PBKDF" => &self.pbkdfs,
            _ => return Err("Invalid algorithm kind"),
        };
        if lst.contains(alg) {
            Ok(())
        } else {
            eprintln!("{} algorithm is not permitted by policy: {}", kind, alg);
            Err("Algorithm not permitted by policy")
        }
    }
}

impl CryptoPolicy for CryptoPolicyNIST {
    fn check_hash(&self, alg: &str) -> Result<(), &'static str> {
        self.check_alg("Hash", alg)
    }

    fn check_pbkdf(
        &self,
        alg: &str,
        key_len: usize,
        _password: &str,
        salt: &[u8],
        params: &BTreeMap<String, usize>,
    ) -> Result<(), &'static str> {
        self.check_alg("PBKDF", alg)?;
        if salt.len() < consts::NIST_PBKDF_MIN_SALT_LEN {
            return Err("Salt length violates policy");
        }
        if key_len < 14 {
            return Err("Key length violates policy");
        }
        if let Some(iters) = params.get("i") {
            if *iters < 1000 {
                return Err("Iteration count violates policy");
            }
        }
        Ok(())
    }

    fn check_cipher(
        &self,
        alg: &str,
        _key: &[u8],
        iv: &[u8],
        _ad: &[u8],
    ) -> Result<(), &'static str> {
        self.check_alg("Cipher", alg)?;
        if alg == "aes-256-gcm" && iv.len() != 96 / 8 {
            return Err("IV length does not match NIST recommendations for this cipher.");
        }
        Ok(())
    }
}

pub fn digest(
    alg: &str,
    data: &[u8],
    policy: &Box<dyn CryptoPolicy>,
) -> Result<Vec<u8>, &'static str> {
    policy.check_hash(alg)?;
    let hash =
        botan::HashFunction::new(to_botan_hash(alg)?).map_err(|_| "Botan error creating hash")?;
    hash.update(data).map_err(|_| "Botan error updating hash")?;
    hash.finish().map_err(|_| "Botan error finishing hash")
}

pub fn hexdigest(
    alg: &str,
    data: &[u8],
    policy: &Box<dyn CryptoPolicy>,
) -> Result<String, &'static str> {
    Ok(hex::encode(digest(alg, data, policy)?))
}

fn to_botan_pbkdf(alg: &str) -> Result<String, &'static str> {
    if alg.starts_with("pbkdf2-") {
        let hash = alg.splitn(2, "-").skip(1).collect::<String>();
        return Ok(format!("PBKDF2({})", to_botan_hash(&hash)?));
    }
    match alg {
        "argon2" => Ok("Argon2id".to_string()),
        "scrypt" => Ok("Scrypt".to_string()),
        _ => {
            eprintln!("Invalid KDF: '{}'", alg);
            Err("Invalid KDF")
        }
    }
}

pub fn derive_key_from_password(
    alg: &str,
    param_order: &[&[&str; 3]; 2],
    key_len: usize,
    password: &str,
    salt: &[u8],
    mut params_map: BTreeMap<String, usize>,
    policy: &Box<dyn CryptoPolicy>,
) -> Result<Vec<u8>, &'static str> {
    policy.check_pbkdf(alg, key_len, password, salt, &params_map)?;
    let mut params: [usize; 3] = [0, 0, 0];
    for (i, param) in param_order[1].iter().enumerate() {
        if param.is_empty() {
            continue;
        }
        params[i] = params_map.remove(*param).ok_or("Missing PBKDF parameter")?;
    }
    if !params_map.is_empty() {
        return Err("Extraneous PBKDF parameters");
    }
    let key = botan::derive_key_from_password(
        &to_botan_pbkdf(alg)?,
        key_len,
        password,
        salt,
        params[0],
        params[1],
        params[2],
    )
    .map_err(|_| "Botan error deriving key")?;
    Ok(key)
}

pub fn derive_key_from_password_timed(
    alg: &str,
    param_order: &[&[&str; 3]; 2],
    key_len: usize,
    password: &str,
    salt: &[u8],
    msec: u32,
    policy: &Box<dyn CryptoPolicy>,
) -> Result<(Vec<u8>, BTreeMap<String, usize>), &'static str> {
    let (key, param1, param2, param3) = botan::derive_key_from_password_timed(
        &to_botan_pbkdf(alg)?,
        key_len,
        password,
        &salt,
        msec,
    )
    .map_err(|_| "Botan error deriving key (timed)")?;
    let params = [param1, param2, param3];
    let mut params_map = BTreeMap::new();
    for (i, param) in param_order[0].iter().filter(|v| !v.is_empty()).enumerate() {
        params_map.insert(param.to_string(), params[i]);
    }
    policy.check_pbkdf(alg, key_len, password, salt, &params_map)?;
    Ok((key, params_map))
}
