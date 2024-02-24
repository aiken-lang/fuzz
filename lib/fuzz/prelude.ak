use aiken/list
use aiken/math.{pow2}
use fuzz

/// Fuzzing types from aiken prelude 
pub fn bool() -> fuzz.Fuzzer<Bool> {
  fuzz.one_of(True, [False])
}

pub fn ordering() -> fuzz.Fuzzer<Ordering> {
  fuzz.one_of(Less, [Equal, Greater])
}

pub fn option(fuzz_a: fuzz.Fuzzer<a>) -> fuzz.Fuzzer<Option<a>> {
  fuzz.map2(
    fn(pred: Bool, a: a) {
      if pred {
        Some(a)
      } else {
        None
      }
    },
    bool(),
    fuzz_a,
  )
}

pub fn list_fixed(len: Int, fuzz_a: fuzz.Fuzzer<a>) -> fuzz.Fuzzer<List<a>> {
  if len <= 0 {
    fuzz.constant([])
  } else {
    fuzz.map2(list.push, list_fixed(len - 1, fuzz_a), fuzz_a)
  }
}

pub fn list_range(
  lo: Int,
  hi: Int,
  fuzz_a: fuzz.Fuzzer<a>,
) -> fuzz.Fuzzer<List<a>> {
  fuzz.and_then(list_fixed(_, fuzz_a), fuzz.int_range(lo, hi))
}

pub fn list(fuzz_a: fuzz.Fuzzer<a>) -> fuzz.Fuzzer<List<a>> {
  list_range(0, 100, fuzz_a)
}
