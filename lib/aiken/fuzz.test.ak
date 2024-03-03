use aiken/fuzz
use aiken/list
use aiken/math

fn many_int() -> Fuzzer<List<Int>> {
  fuzz.list_between(fuzz.int(), 100, 100)
}

test prop_int_generator(xs via many_int()) {
  let below_255 =
    xs |> list.filter(fn(x) { math.abs(x) <= 255 }) |> list.length()

  below_255 >= 75
}
