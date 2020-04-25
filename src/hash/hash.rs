use ring::digest;

pub fn double_sha256(data: &[u8]) -> Vec<u8> {
    let res = digest::digest(&digest::SHA256, data);
    digest::digest(&digest::SHA256, res.as_ref())
        .as_ref()
        .to_vec()
}
