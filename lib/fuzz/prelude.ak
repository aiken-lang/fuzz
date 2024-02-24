use aiken/list
use aiken/math.{pow2}
use fuzz

// Will error on an empty list
/// Fuzzing types from aiken prelude 
/// Fuzzer that chooses an item from a list.
pub fn one_of(l: List<a>) -> fuzz.Fuzzer<a> {
  let len = list.length(l)
  expect len > 0
  fuzz.map(
    fn(n: Int) {
      expect Some(item) = list.at(l, n )
      item
    },
    fuzz.int_range(0, len - 1),
  )
}

pub fn bool() -> fuzz.Fuzzer<Bool> {
  one_of([True, False])
}

test test_bool() {
  let f = bool()
  let s = fuzz.def_seed()
  let (_, sample) = f(s)
  sample == True
}


pub fn ordering() -> fuzz.Fuzzer<Ordering> {
  one_of([Less, Equal, Greater])
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

test test_option() {
  let f = option(bool())
  let s = fuzz.def_seed()
  let (_, sample) = f(s)
  sample == Some(True)
}


pub fn list_fixed(len: Int, fuzz_a: fuzz.Fuzzer<a>) -> fuzz.Fuzzer<List<a>> {
  if len <= 0 {
    fuzz.constant([])
  } else {
    fuzz.map2(list.push, list_fixed(len - 1, fuzz_a), fuzz_a)
  }
}

// test test_list_fixed() {
//   let f = list_fixed(3, fuzz.constant(""))
//   let s = fuzz.def_seed()
//   let (_, sample) = f(s)
//   sample == ["", "", ""] 
// }

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
