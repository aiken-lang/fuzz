use aiken/fuzz
use aiken/list
use aiken/math

test prop_int_positive(n via fuzz.int()) {
  n >= 0 || math.abs(n) < 128
}

test prop_list_int_spread(xs via fuzz.list(fuzz.int())) {
  xs |> list.all(fn(x) { math.abs(x) <= 255 })
}

test prop_bool_always_true(predicate via fuzz.bool()) {
  predicate
}

fn fixed_list() -> Fuzzer<List<Int>> {
  fuzz.list_between(fuzz.int(), 32, 32)
}

test prop_list_hard_shrink(xs via fixed_list()) {
  let below_255 = xs |> list.filter(fn(n) { math.abs(n) <= 255 }) |> list.length
  below_255 >= 30
}
