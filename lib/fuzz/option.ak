use fuzz/base.{bool}
use fuzz/fuzz.{map}
use fuzz/types.{Fuzz, Seed}

pub fn option(fuzz_a: Fuzz<a>) -> Fuzz<Option<a>> {
  fn(s: Seed) {
    let (cond, s1) = bool()(s)
    if cond {
      map(fn(x) { Some(x) }, fuzz_a)(s1)
    } else {
      (None, s1)
    }
  }
}
