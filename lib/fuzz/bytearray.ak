use aiken/bytearray as ba
use aiken/hash.{blake2b_256}
use aiken/math.{pow2}
use fuzz/builtin as fbi
use fuzz/types.{Seed, Fuzz}
use fuzz/base.{step_seed}
use fuzz/int.{int_range}


pub fn bytearray32() -> Fuzz<ByteArray> {
  fn(s: Seed) { (blake2b_256(fbi.int_to_bytearray(s.seed)), step_seed(s)) }
}

pub fn bytearray_fixed(length: Int) -> Fuzz<ByteArray> {
  fn(s : Seed) {
    if length <= 0 {
      ("", s)
    } else {
      let (head, s1) = bytearray32()(s)
      if length <= 32 {
        (ba.take(head, length), s1)
      } else {
        let (tail, s_end) = bytearray_fixed(length - 32)(s1)
        (ba.concat(head, tail), s_end)
      }
    }
  }
}

pub fn bytearray28() -> Fuzz<ByteArray> {
  bytearray_fixed(28)
}

pub fn bytearray64() -> Fuzz<ByteArray> {
  bytearray_fixed(64)
}

pub fn bytearray_range(lo: Int, hi: Int) -> Fuzz<ByteArray> {
  fn(s : Seed) {
    let (length, s1) = int_range(lo, hi)(s)
    bytearray_fixed(length)(s1)
  }
}

pub fn bytearray() -> Fuzz<ByteArray> {
  fn(s : Seed) {
    bytearray_range(0, pow2(s.size))(s)
  }
}

