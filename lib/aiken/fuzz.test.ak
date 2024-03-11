use aiken/fuzz.{
  bool, distinct, filter, int, int_between, label, lexographical, list,
  list_between, list_with_elem, list_with_subset, negative_int, nonempty_list,
  nonnegative_int, positive_int, sorted, uniform,
}
use aiken/int
use aiken/list
use aiken/math
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

fn is_even(x: Int) -> Bool {
  x % 2 == 0
}

test prop_filter(x via filter(int(), is_even)) {
  is_even(x)
}

test prop_nonempty_list(xs via nonempty_list(int())) {
  list.length(xs) > 0
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

test prop_list_with_elem(xs via list_with_elem(int())) {
  let (xs, x) = xs
  list.has(xs, x)
}

test prop_list_with_subset(xs via list_with_subset(int())) {
  let (xs, ys) = xs
  list.all(ys, fn(y) { list.has(xs, y) })
}

test prop_distinct_list(xs via distinct(list(bool()))) {
  list.length(xs) <= 2
}

test prop_distinct_list_2(
  xs via distinct(list_between(int_between(0, 9), 0, 100)),
) {
  list.length(xs) <= 10
}
