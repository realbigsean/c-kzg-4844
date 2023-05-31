pub use c_kzg::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_field_elements_per_blob() {
        assert_eq!(FIELD_ELEMENTS_PER_BLOB, 4);
    }
}
