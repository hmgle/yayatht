#[must_use]
pub const fn before(left: u32, right: u32) -> bool {
    (left.wrapping_sub(right) as i32) < 0
}

#[must_use]
pub const fn after(left: u32, right: u32) -> bool {
    before(right, left)
}

#[must_use]
pub const fn before_or_equal(left: u32, right: u32) -> bool {
    left == right || before(left, right)
}

#[must_use]
pub const fn distance(start: u32, end: u32) -> u32 {
    end.wrapping_sub(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_safe_ordering() {
        assert!(before(u32::MAX - 2, 2));
        assert!(after(2, u32::MAX - 2));
        assert_eq!(distance(u32::MAX - 2, 2), 5);
    }
}
