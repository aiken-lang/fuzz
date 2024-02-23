use aiken/builtin
use aiken/bytearray
use aiken/math.{pow2}

// Primitives

pub type Seed {
  seed: Int,
  size: Int,
}

type Fuzzer<a> =
  fn(Seed) -> (Seed, a)

///
pub fn constant(a: a) -> Fuzzer<a> {
  fn(seed) { (seed, a) }
}

///
pub fn map(f: fn(a) -> b, fuzz_a: Fuzzer<a>) -> Fuzzer<b> {
  fn(s0) {
    let (s1, a) = fuzz_a(s0)
    (s1, f(a))
  }
}

pub fn and_map(fuzz_f: Fuzzer<fn(a) -> b>, fuzz_a: Fuzzer<a>) -> Fuzzer<b> {
  fn(s0) {
    let (s1, f) = fuzz_f(s0)
    let (s2, a) = fuzz_a(s1)
    (s2, f(a))
  }
}

pub fn and_then(f: fn(a) -> Fuzzer<b>, fuzz_a: Fuzzer<a>) -> Fuzzer<b> {
  fn(s0) {
    let (s1, a) = fuzz_a(s0)
    f(a)(s1)
  }
}

/// Generate int values within [-2^32; 2^32 - 1]
pub fn int() -> Fuzzer<Int> {
  fn(s: Seed) {
    let sign = s.seed % 2 == 0
    let val = bytearray_to_int(builtin.blake2b_256(int_to_bytearray(s.seed)))
    (
      step_seed(s),
      if sign {
        val
      } else {
        -val - 1
      },
    )
  }
}

/// Generate bytearrays of 32 bytes
pub fn bytearray() -> Fuzzer<ByteArray> {
  fn(s: Seed) { (step_seed(s), builtin.blake2b_256(int_to_bytearray(s.seed))) }
}

pub fn bytearray_fixed(len: Int) -> Fuzzer<ByteArray> {
  if len <= 0 {
    constant("")
  } else {
    do_bytearray(len, constant(""))
  }
}

fn do_bytearray(len: Int, tail: Fuzzer<ByteArray>) -> Fuzzer<ByteArray> {
  if len <= 32 {
    let head = map(bytearray.take(_, len), bytearray())
    map2(bytearray.concat, head, tail)
  } else {
    let head = bytearray()
    do_bytearray(len - 32, map2(bytearray.concat, head, tail))
  }
}

pub fn map2(f: fn(a, b) -> c, fuzz_a: Fuzzer<a>, fuzz_b: Fuzzer<b>) -> Fuzzer<c> {
  fn(x) { f(x, _) }
    |> map(fuzz_a)
    |> and_map(fuzz_b)
}

// Internal

fn step_seed(s: Seed) -> Seed {
  let Seed { size, seed } = s
  Seed { size, seed: step_pos_int(seed) }
}

fn step_pos_int(x: Int) -> Int {
  bytearray_to_int(builtin.blake2b_256(int_to_bytearray(x)))
}

fn int_to_bytearray(x: Int) -> ByteArray {
  if x == 0 {
    ""
  } else {
    bytearray.push(int_to_bytearray(x / 256), x % 256)
  }
}

fn bytearray_to_int(x: ByteArray) -> Int {
  if bytearray.length(x) == 0 {
    0
  } else {
    powsum(x, bytearray.length(x) - 1)
  }
}

fn powsum(x: ByteArray, ix: Int) {
  // UNSAFE : For empty bytearray
  if ix <= 0 {
    builtin.index_bytearray(x, ix)
  } else {
    pow2(8 * ix) * builtin.index_bytearray(x, ix) + powsum(x, ix - 1)
  }
}
