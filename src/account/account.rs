struct ECDSAAccount {
    pub entripy: Vec<u8>,
    mnemonic: String,
}

pub fn generate_account_by_mnemonic(mnemonic: &String, lang: u32) -> Result<ECDSAAccount> {}

pub fn get_crypto_byte_from_mnemonic(mnemonic: &String, lang: u32) -> Result<u8> {}
