use aiken/list
use aiken/math.{pow2}
use fuzz/int.{int_range}
use fuzz/types.{Fuzz, Seed}

pub fn list_fixed(length: Int, fuzz: Fuzz<a>) -> Fuzz<List<a>> {
  fn(s: Seed) {
    if length < 1 {
      ([], s)
    } else {
      let (x, s1) = fuzz(s)
      let (tail, s_end) = list_fixed(length - 1, fuzz)(s1)
      (list.push(tail, x), s_end)
    }
  }
}

pub fn list_range(lo: Int, hi: Int, fuzz: Fuzz<a>) -> Fuzz<List<a>> {
  fn(s: Seed) {
    let (length, s1) = int_range(lo, hi)(s)
    list_fixed(length, fuzz)(s1)
  }
}

pub fn list(fuzz: Fuzz<a>) -> Fuzz<List<a>> {
  fn(s: Seed) { list_range(0, pow2(s.size), fuzz)(s) }
}
