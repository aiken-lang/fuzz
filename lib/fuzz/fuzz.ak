use aiken/list
use fuzz/int.{int_range}
use fuzz/types.{Fuzz, Seed}

pub fn map(f: fn(a) -> b, fuzz_a: Fuzz<a>) -> Fuzz<b> {
  fn(s: Seed) {
    let (x, s1) = fuzz_a(s)
    (f(x), s1)
  }
}

pub fn map2(
  f: fn(a, b) -> result,
  fuzz_a: Fuzz<a>,
  fuzz_b: Fuzz<b>,
) -> Fuzz<result> {
  fn(s: Seed) {
    let (x, s1) = fuzz_a(s)
    let (y, s2) = fuzz_b(s1)
    (f(x, y), s2)
  }
}

pub fn and_then(f: fn(a) -> Fuzz<b>, fuzz_a: Fuzz<a>) -> Fuzz<b> {
  fn(s: Seed) {
    let (x, s1) = fuzz_a(s)
    let (y, s2) = f(x)(s1)
    (y, s2)
  }
}

pub fn one_of(fuzz_0: Fuzz<a>, fuzzs: List<Fuzz<a>>) -> Fuzz<a> {
  fn(s: Seed) {
    let (n, s1) = int_range(0, list.length(fuzzs))(s)
    if n == 0 {
      fuzz_0(s1)
    } else {
      expect Some(fz) = list.at(fuzzs, n - 1)
      fz(s1)
    }
  }
}
