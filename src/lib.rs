#[macro_use]
extern crate lazy_static;

extern crate base58;
extern crate num_bigint;
extern crate num_traits;
extern crate ring;

pub mod account;
pub mod hash;
pub mod hdwallet;
pub mod keys;
pub mod sign;

pub mod errors;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
