use rand_core::{Error, RngCore};

use crate::vault;

#[derive(Debug, Clone)]
pub struct OckamRng;

impl RngCore for OckamRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes[..]);
        u32::from_ne_bytes(bytes)
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes[..]);
        u64::from_ne_bytes(bytes)
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        vault::random(dest).unwrap();
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}
