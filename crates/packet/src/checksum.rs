#![allow(clippy::cast_possible_truncation)]

pub fn sum_words(mut sum: u32, mut bytes: &[u8]) -> u32 {
    while bytes.len() >= 2 {
        sum += u32::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        bytes = &bytes[2..];
    }
    if let Some(&last) = bytes.first() {
        sum += u32::from(last) << 8;
    }
    sum
}

pub fn fold(sum: u32) -> u16 {
    !fold_sum(sum)
}

fn fold_sum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

pub fn checksum(bytes: &[u8]) -> u16 {
    fold(sum_words(0, bytes))
}

pub fn ipv4_transport(src: [u8; 4], dst: [u8; 4], protocol: u8, bytes: &[u8]) -> u16 {
    let mut sum = sum_words(0, &src);
    sum = sum_words(sum, &dst);
    sum += u32::from(protocol);
    sum += bytes.len() as u32;
    fold(sum_words(sum, bytes))
}

pub fn ipv6_transport(src: [u8; 16], dst: [u8; 16], protocol: u8, bytes: &[u8]) -> u16 {
    let mut sum = sum_words(0, &src);
    sum = sum_words(sum, &dst);
    let len = (bytes.len() as u32).to_be_bytes();
    sum = sum_words(sum, &len);
    sum += u32::from(protocol);
    fold(sum_words(sum, bytes))
}

/// Folded but NOT complemented one's-complement sum of the IPv4 pseudo
/// header: the seed value a `VIRTIO_NET_HDR_F_NEEDS_CSUM` frame carries in
/// its transport checksum field for the kernel to complete.
pub fn ipv4_pseudo_header(src: [u8; 4], dst: [u8; 4], protocol: u8, length: usize) -> u16 {
    let mut sum = sum_words(0, &src);
    sum = sum_words(sum, &dst);
    sum += u32::from(protocol);
    sum += length as u32;
    fold_sum(sum)
}

/// IPv6 counterpart of [`ipv4_pseudo_header`].
pub fn ipv6_pseudo_header(src: [u8; 16], dst: [u8; 16], protocol: u8, length: usize) -> u16 {
    let mut sum = sum_words(0, &src);
    sum = sum_words(sum, &dst);
    let length = (length as u32).to_be_bytes();
    sum = sum_words(sum, &length);
    sum += u32::from(protocol);
    fold_sum(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ipv4_header() {
        let header = [
            0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0, 0, 0xc0, 0xa8, 0x00,
            0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(checksum(&header), 0xb890);
    }
}
