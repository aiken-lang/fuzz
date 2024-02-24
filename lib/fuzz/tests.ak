use fuzz
use fuzz/prelude

test test_int_range() {
  let f = fuzz.int_range(0, 10)
  let s = fuzz.Seed { size : 0, seed : 42 }
  let (_, sample) = prelude.list_fixed(0, f)(s)
  sample == []
}
