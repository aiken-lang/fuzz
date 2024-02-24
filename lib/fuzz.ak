use aiken/builtin
use aiken/bytearray
use aiken/list
use aiken/math.{pow2}

// Primitives

/// Seed is public to apease the type checker.
/// It should not be directly handled.
pub type Seed {
  seed: Int,
  size: Int,
}

/// For testing purposes only
pub fn def_seed() {
  Seed { size : 1, seed: 42 } 
}

pub type Fuzzer<a> =
  fn(Seed) -> (Seed, a)

/// Create a size sensitive fuzzer
pub fn sized(callback: fn(Int) -> Fuzzer<a>) -> Fuzzer<a> {
  fn(seed: Seed) { callback(seed.size)(seed) }
}

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

/// A convenient composition of map and and_map
pub fn map2(f: fn(a, b) -> c, fuzz_a: Fuzzer<a>, fuzz_b: Fuzzer<b>) -> Fuzzer<c> {
  fn(x) { f(x, _) }
    |> map(fuzz_a)
    |> and_map(fuzz_b)
}

/// A convenient composition of map and and_map
pub fn map3(
  f: fn(a0, a1, a2) -> b,
  fuzz_a0: Fuzzer<a0>,
  fuzz_a1: Fuzzer<a1>,
  fuzz_a2: Fuzzer<a2>,
) -> Fuzzer<b> {
  fn(x0) { fn(x1) { fn(x2) { f(x0, x1, x2) } } }
    |> map(fuzz_a0)
    |> and_map(fuzz_a1)
    |> and_map(fuzz_a2)
}

/// Generate int values within [ 0 ; 2^256 - 1]
pub fn u256() -> Fuzzer<Int> {
  fn(s: Seed) { (step(s), s.seed) }
}

const u256_max = 115792089237316195423570985008687907853269984665640564039457584007913129639935

/// Bounds inclusive
/// Cannot handle ranges > u256_max
/// There is a slight bias from using modulo. 
pub fn int_range(lo: Int, hi: Int) -> Fuzzer<Int> {
  let range = hi - lo
  expect range >= 0
  expect range <=  u256_max
  map(fn(x) { x % ( 1 + hi - lo ) + lo }, u256())
}

/// TODO use more sensible sizes
pub fn any_int() -> Fuzzer<Int> {
  sized(fn(size: Int) {
    int_range(-pow2(size), pow2(size))
  })
}

/// Generate bytearrays of 32 bytes
pub fn bytearray() -> Fuzzer<ByteArray> {
  fn(s: Seed) { (step(s), builtin.blake2b_256(int_to_bytearray(s.seed))) }
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

/// Generate string 
pub fn string() -> Fuzzer<string> {
  // How to generate valid strings?
  todo
}

pub fn choose(opt_0: Fuzzer<a>, opt_1: Fuzzer<a>) -> Fuzzer<a> {
  and_then(
    fn(x) {
      if x == 0 {
        opt_0
      } else {
        opt_1
      }
    },
    int_range(0,1),
  )
}

// Internal

fn step(s: Seed) -> Seed {
  let Seed { size, seed } = s
  Seed { size, seed: step_pos_int(seed) }
}

fn step_pos_int(x: Int) -> Int {
  bytearray_to_int(builtin.blake2b_256(int_to_bytearray(x)))
}

/// TODO : Replace with builtins when available
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
