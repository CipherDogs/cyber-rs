use bip39::{Language, Mnemonic, MnemonicType};

/// Seed phrase generation function
/// # Usage
/// ```
/// use cyber::mnemonic::*;
/// let phrase = generate_phrase();
/// ```
pub fn generate_phrase() -> String {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let phrase: &str = mnemonic.phrase();
    format!("{}", phrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_phrase() {
        let phrase = generate_phrase();

        assert_eq!(phrase.split_ascii_whitespace().count(), 12);
    }
}
