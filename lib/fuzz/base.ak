use aiken/hash.{blake2b_256}
use fuzz/builtin as fbi
use fuzz/types.{Fuzz, Seed}

// const max_u64 = 18446744073709551615
// const min_i64 = -9223372036854775808
// const max_i64 = 9223372036854775807

pub fn step_pos_int(x: Int) -> Int {
  fbi.bytearray_to_int(blake2b_256(fbi.int_to_bytearray(x)))
}

pub fn step_seed(s: Seed) -> Seed {
  let Seed { size, seed } = s
  Seed { size, seed: step_pos_int(seed) }
}

pub fn step(fuzz: Fuzz<a>, s0: Seed) -> (a, Seed) {
  let (x, s1) = fuzz(s0)
  (x, Seed { size: s1.size, seed: step_pos_int(s1.seed) })
}

pub fn constant(x: a) -> Fuzz<a> {
  fn(s: Seed) { (x, s) }
}

pub fn bool() -> Fuzz<Bool> {
  fn(s: Seed) { (0 == s.seed % 2, step_seed(s)) }
}

// test test_bool() {
//   let fuzz_bool = bool()
//   let s0 = Seed { size: 1, seed: 42 }
//   let (b0, s1) = fuzz_bool(s0)
//   let (b1, s2) = fuzz_bool(s1)
//   let (b2, s3) = fuzz_bool(s2)
//   let (b3, s4) = fuzz_bool(s3)
//   let (b4, s5) = fuzz_bool(s4)
//   let (b5, s6) = fuzz_bool(s5)
//   let (b6, s7) = fuzz_bool(s6)
//   let (b7, s8) = fuzz_bool(s7)
//   let (b8, s9) = fuzz_bool(s8)
//   let (b9, _) = fuzz_bool(s9)
//   [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9] == [
//     True,
//     False,
//     True,
//     True,
//     False,
//     True,
//     True,
//     False,
//     True,
//     True,
//   ]
// }
