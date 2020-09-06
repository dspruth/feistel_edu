extern crate feistel_ed;

#[test]
fn test_general_encryption() {
    assert!(feistel_ed::feistel("MyData".as_bytes(), "key".as_bytes(), 16, feistel_ed::FeistelMode::Encrypt).is_ok());
}