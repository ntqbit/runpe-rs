#[no_mangle]
#[inline]
unsafe fn strlen(p: *const u8) -> usize {
    let mut t = p;

    while *t != 0 {
        t = t.add(1);
    }

    t.offset_from(p) as usize
}

#[no_mangle]
#[inline]
unsafe fn memcmp(mut a: *const u8, mut b: *const u8, size: u32) -> i32 {
    for _ in 0..size {
        let d = (*a as i32) - (*b as i32);
        if d != 0 {
            return d;
        }

        a = a.add(1);
        b = b.add(1);
    }

    0
}
