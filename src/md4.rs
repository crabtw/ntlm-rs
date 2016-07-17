use std::num::Wrapping;

pub fn hash(data: &[u8]) -> Vec<u8> {
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    fn r(v: u32, s: u32) -> u32 {
        (v << s) | (v >> (32 - s))
    }

    fn wrap_add2(a: u32, b: u32) -> u32 {
        (Wrapping(a) + Wrapping(b)).0
    }

    fn wrap_add3(a: u32, b: u32, c: u32) -> u32 {
        (Wrapping(a) + Wrapping(b) + Wrapping(c)).0
    }

    fn wrap_add4(a: u32, b: u32, c: u32, d: u32) -> u32 {
        (Wrapping(a) + Wrapping(b) + Wrapping(c) + Wrapping(d)).0
    }

    let bit_len = data.len() << 3;
    let mut data = Vec::from(data);
    data.push(0x80);

    while data.len() % 64 != 56 {
        data.push(0x00);
    }
    
    {
        let low = bit_len as u32;
        let high = (bit_len >> 32) as u32;

        data.push((low & 0xff) as u8);
        data.push(((low >> 8) & 0xff) as u8);
        data.push(((low >> 16) & 0xff) as u8);
        data.push(((low >> 24) & 0xff) as u8);

        data.push((high & 0xff) as u8);
        data.push(((high >> 8) & 0xff) as u8);
        data.push(((high >> 16) & 0xff) as u8);
        data.push(((high >> 24) & 0xff) as u8);
    }

    let mut a = 0x67452301;
    let mut b = 0xefcdab89;
    let mut c = 0x98badcfe;
    let mut d = 0x10325476;

    let data: Vec<_> = data.chunks(4).map(|x| {
            x[0] as u32
        | ((x[1] as u32) << 8)
        | ((x[2] as u32) << 16)
        | ((x[3] as u32) << 24)
    }).collect();

    for x in data.chunks(16) {
        let a2 = a;
        let b2 = b;
        let c2 = c;
        let d2 = d;

        let i0: &[usize; 4] = &[0, 4, 8, 12];
        let i1: &[usize; 4] = &[0, 1, 2, 3];
        let i2: &[usize; 4] = &[0, 2, 1, 3];

        for i in i0 {
            a = r(wrap_add3(a, f(b, c, d), x[i + 0]), 3);
            d = r(wrap_add3(d, f(a, b, c), x[i + 1]), 7);
            c = r(wrap_add3(c, f(d, a, b), x[i + 2]), 11);
            b = r(wrap_add3(b, f(c, d, a), x[i + 3]), 19);
        }

        for i in i1 {
            a = r(wrap_add4(a, g(b, c, d), x[i + 0] , 0x5a827999), 3);
            d = r(wrap_add4(d, g(a, b, c), x[i + 4] , 0x5a827999), 5);
            c = r(wrap_add4(c, g(d, a, b), x[i + 8] , 0x5a827999), 9);
            b = r(wrap_add4(b, g(c, d, a), x[i + 12], 0x5a827999), 13);
        }

        for i in i2 {
            a = r(wrap_add4(a, h(b, c, d), x[i + 0] , 0x6ed9eba1), 3);
            d = r(wrap_add4(d, h(a, b, c), x[i + 8] , 0x6ed9eba1), 9);
            c = r(wrap_add4(c, h(d, a, b), x[i + 4] , 0x6ed9eba1), 11);
            b = r(wrap_add4(b, h(c, d, a), x[i + 12], 0x6ed9eba1), 15);
        }

        a = wrap_add2(a, a2);
        b = wrap_add2(b, b2);
        c = wrap_add2(c, c2);
        d = wrap_add2(d, d2);
    }

    let result: Vec<_> = (&[a, b, c, d]).iter().flat_map(|x| {
        vec!(*x as u8,
             (x >> 8)  as u8,
             (x >> 16) as u8,
             (x >> 24) as u8)
    }).collect();

    result
}

#[test]
fn test() {
    assert_eq!(hash(b""),
               vec!(0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0));
    assert_eq!(hash(b"a"),
               vec!(0xbd, 0xe5, 0x2c, 0xb3, 0x1d, 0xe3, 0x3e, 0x46, 0x24, 0x5e, 0x05, 0xfb, 0xdb, 0xd6, 0xfb, 0x24));
    assert_eq!(hash(b"abc"),
               vec!(0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d));
    assert_eq!(hash(b"message digest"),
               vec!(0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8, 0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7, 0x01, 0x4b));
    assert_eq!(hash(b"abcdefghijklmnopqrstuvwxyz"),
               vec!(0xd7, 0x9e, 0x1c, 0x30, 0x8a, 0xa5, 0xbb, 0xcd, 0xee, 0xa8, 0xed, 0x63, 0xdf, 0x41, 0x2d, 0xa9));
    assert_eq!(hash(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
               vec!(0x04, 0x3f, 0x85, 0x82, 0xf2, 0x41, 0xdb, 0x35, 0x1c, 0xe6, 0x27, 0xe1, 0x53, 0xe7, 0xf0, 0xe4));
    assert_eq!(hash(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
               vec!(0xe3, 0x3b, 0x4d, 0xdc, 0x9c, 0x38, 0xf2, 0x19, 0x9c, 0x3e, 0x7b, 0x16, 0x4f, 0xcc, 0x05, 0x36));
}
