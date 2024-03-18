use aiken/dict.{Dict}
use aiken/fuzz
use aiken/list
use aiken/int

// WARNING: this will not handle key clashes. 
// Thus, if `fuzz_key` generates duplicates, the dict will be shorter.
/// Dict of length 'between' values.
pub fn dict_between(
  fuzz_key: Fuzzer<k>,
  fuzz_value: Fuzzer<v>,
  compare: fn(k, k) -> Ordering,
  min: Int,
  max: Int,
) -> Fuzzer<Dict<k, v>> {
  fuzz.list_between(
    fuzz.map2(fuzz_key, fuzz_value, fn(k, v) { (k, v) }),
    min,
    max,
  )
    |> fuzz.map(dict.from_list(_, compare))
}

test prop_dict_between(
  d via dict_between(fuzz.int(), fuzz.bytearray(), int.compare, 20, 40),
) {
  ( d |> dict.keys() |> list.length() ) > 10
}
