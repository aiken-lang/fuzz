use aiken/fuzz.{bool, int, label, list, list_between, lexographical, sorted, positive_int, nonnegative_int, negative_int, uniform}
use aiken/list
use aiken/math
use aiken/int
use aiken/string

test prop_int_distribution(n via int()) {
  label(
    if n < -255 {
      @"]-∞; -255["
    } else if n < 0 {
      @"[-255; 0["
    } else if n < 16 {
      @"[0; 16["
    } else if n < 255 {
      @"[16; 255["
    } else {
      @"[255; +∞["
    },
  )

  True
}

test prop_bool_distribution(b via bool()) {
  label(
    if b {
      @"True"
    } else {
      @"False"
    },
  )

  True
}

test prop_list_distribution(xs via list(int())) {
  label(
    if list.is_empty(xs) {
      @"Empty"
    } else {
      @"Non-empty"
    },
  )

  True
}

test prop_list_int_shrink(xs via list_between(int(), 32, 32)) fail {
  let below_255 = xs |> list.filter(fn(n) { math.abs(n) <= 255 }) |> list.length
  below_255 >= 32
}

test prop_test_lexographical(pair via lexographical(int(), int(), int.compare)) {
  let (a, b) = pair
  a <= b
}

test prop_test_sorted(ls via sorted(list(int()), int.compare)) {
  let sorted = list.sort(ls, int.compare)
  ls == sorted
}

test prop_positive(n via positive_int()) {
  n > 0
}

test prop_nonnegative(n via nonnegative_int()) {
  n >= 0
}

test prop_negative(n via negative_int()) {
  n < 0
}

test prop_uniform(u via uniform(8)) {
  // TODO: this reveals that uniform isn't so uniform, investigate why
  label(string.from_int(u % 8))
  True
}