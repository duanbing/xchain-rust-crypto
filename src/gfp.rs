type Limb = u32;
pub enum LimbMask {
    True = 0xffff_ffff,
    False = 0,
}

extern "C" {
    fn GFp_nistz256_select_w7(val: *const u64, int: *const u64, index: i32);
    fn LIMBS_are_zero(a: *const Limb, num_limbs: usize) -> LimbMask;
}

#[test]
pub fn call_test() {
    let val: u64 = 0;
    let int: u64 = 0;
    let index: i32 = 0;

    let limbs = [64; 3];
    unsafe {
        //        GFp_nistz256_select_w7(&val as *const u64, &int as *const u64, index);
        println!("begin");
        LIMBS_are_zero(limbs.as_ptr(), 3);
    }
}
