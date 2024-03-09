use aiken/fuzz.{bool, int, label, list, list_between}
use aiken/list
use aiken/math
use aiken/string

const max_u64: Int = 18_446_744_073_709_551_615

const max_u32: Int = 4_294_967_295

const max_u16: Int = 65_535

const max_u8: Int = 256

const max_u4: Int = 16

test prop_int_distribution(n via int()) {
  label(
    if n < -max_u64 - 1 {
      @"]-∞, -2^64["
    } else if n < -max_u32 - 1 {
      @"[-2^64; -2^32["
    } else if n < -max_u16 - 1 {
      @"[-2^32; -2^16["
    } else if n < 0 {
      @"[-2^16; 0["
    } else if n == 0 {
      @"0"
    } else if n <= max_u4 {
      @"]0; 2^4["
    } else if n <= max_u8 {
      @"[2^4; 2^8["
    } else if n <= max_u16 {
      @"[2^8; 2^16["
    } else if n <= max_u32 {
      @"[2^16; 2^32["
    } else if n <= max_u64 {
      @"[2^32; 2^64["
    } else {
      @"[2^64; +∞["
    },
  )

  True
}

const m0 = 8

const m1 = 256

const m2 = 16777216

const m3 = 4294967296

const m4 = 18446744073709551616

test test_uint(n via fuzz.uint(2)) {
  label(
    if n < m0 {
      @"m0"
    } else if n < m1 {
      @"m1"
    } else if n < m2 {
      @"m2"
    } else if n < m3 {
      @"m3"
    } else if n < m4 {
      @"m4"
    } else {
      @"m5"
    },
  )
  True
}

test test_uint_8(n via fuzz.uint(8)) {
  label(
    if n < 32 {
      @"0"
    } else if n < 64 {
      @"1"
    } else if n < 96 {
      @"2"
    } else if n < 128 {
      @"3"
    } else if n < 160 {
      @"4"
    } else if n < 192 {
      @"5"
    } else if n < 224 {
      @"6"
    } else if n < 256 {
      @"7"
    } else {
      @"impossible"
    },
  )
  True
}

test test_uint_16(n via fuzz.uint(24)) {
  label(
    if n < 2097152 { 
      @"0"
    } else if n < 4194304 {
      @"1"
    } else if n < 6291456 {
      @"2"
    } else if n < 8388608 {
      @"3"
    } else if n < 10485760 {
      @"4"
    } else if n < 12582912 {
      @"5"
    } else if n < 14680064 {
      @"6"
    } else if n < 16777216 { // max_u16 + 1
      @"7"
    } else {
      @"impossible"
    },
  )
  True
}

fn int_range() -> Fuzzer<(Int, Int, Int)> {
  fuzz.int()
    |> fuzz.and_then(
         fn(lo) {
           fuzz.int()
             |> fuzz.and_then(
                  fn(hi) {
                    fuzz.int_between(lo, hi)
                      |> fuzz.map(fn(in) { (lo, hi, in) })
                  },
                )
         },
       )
}

test prop_int_between(triple via int_range()) {
  let (lo, hi, in) = triple
  if lo < hi {
    and {
      lo <= in,
      in <= hi,
    }
  } else {
    and {
      hi <= in,
      in <= lo,
    }
  }
}

const max_u64_minus: Int = -18_446_744_073_709_551_616

test prop_int_between_large(n via fuzz.int_between(max_u64_minus, max_u64)) fail {
  label(string.from_int(n))
  n < max_u32
}

test prop_int_sometimes_near_u8(n via fuzz.int()) fail {
  n < 192 || n > 255
}

test prop_bool_distribution(b via bool()) {
  label(
    if b {
      @"True"
    } else {
      @"False"
    },
  )

  True
}

test prop_list_distribution(xs via list(int())) {
  label(
    if list.is_empty(xs) {
      @"Empty"
    } else {
      @"Non-empty"
    },
  )

  True
}

test prop_list_int_shrink(xs via list_between(int(), 32, 32)) fail {
  let below_255 = xs |> list.filter(fn(n) { math.abs(n) <= 255 }) |> list.length
  below_255 >= 32
}
