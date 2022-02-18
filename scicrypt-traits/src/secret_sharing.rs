

trait NOfNSecretSharing {
    type Plaintext;
    type Share;

    fn share(plaintext: &Self::Plaintext, share_count: usize) -> Vec<Self::Share>;

    fn combine(shares: &[Self::Share]) -> Self::Plaintext;
}

trait TOfNSecretSharing {
    type Plaintext;
    type Share;

    fn share(plaintext: &Self::Plaintext, threshold: usize, share_count: usize) -> Vec<Self::Share>;

    fn combine(shares: &[Self::Share]) -> Self::Plaintext;
}
