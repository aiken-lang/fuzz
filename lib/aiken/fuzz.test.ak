use aiken/bytearray
use aiken/fuzz.{
  and_then, bool, int, int_between, label, list, list_between, list_with_elem,
  map, one_of, sublist, such_that,
}
use aiken/list
use aiken/string

test prop_int_distribution(n via int()) {
  label(
    if n < -255 {
      fail @"n < -max_u8"
    } else if n < 0 {
      @"[-255; 0["
    } else if n == 0 {
      @"0"
    } else if n < 256 {
      @"]0; 255]"
    } else if n < 16383 {
      @"[256; 16383]"
    } else {
      fail @"n > 16383"
    },
  )

  True
}

test prop_int_between_distribution(n via int_between(-100, 100)) {
  buckets(n, -100, 100, fn(n) { n + 25 })
  n >= -100 && n <= 100
}

test prop_int_between_large(
  n via int_between(0, 340_282_366_920_938_463_463_374_607_431_768_211_455),
) fail {
  n <= 18_446_744_073_709_551_615
}

test prop_bool_distribution(is_true via bool()) {
  label(
    if is_true {
      @"True"
    } else {
      @"False"
    },
  )

  True
}

test prop_list_distribution_small(xs via list_between(int(), 0, 10)) {
  let len = list.length(xs)
  buckets(len, 0, 11, fn(n) { n + 1 })
  len >= 0 && len <= 10
}

fn is_even(x: Int) -> Bool {
  x % 2 == 0
}

test prop_such_that(x via such_that(int(), is_even)) {
  is_even(x)
}

fn list_at_least() -> Fuzzer<(Int, List<Int>)> {
  let min <- and_then(int_between(0, 10))
  let xs <- map(fuzz.list_at_least(int(), min))
  (min, xs)
}

test prop_list_at_least(params via list_at_least()) {
  let (min, xs) = params
  list.length(xs) >= min
}

fn list_at_most() -> Fuzzer<(Int, List<Int>)> {
  let max <- and_then(int_between(0, 10))
  let xs <- map(fuzz.list_at_most(int(), max))
  (max, xs)
}

test prop_list_at_most(params via list_at_most()) {
  let (max, xs) = params
  list.length(xs) <= max
}

fn int_at_least() -> Fuzzer<(Int, Int)> {
  let min <- and_then(int())
  let n <- map(fuzz.int_at_least(min))
  (min, n)
}

test prop_int_at_least(params via int_at_least()) {
  let (min, n) = params
  n >= min
}

fn int_at_most() -> Fuzzer<(Int, Int)> {
  let max <- and_then(int())
  let n <- map(fuzz.int_at_most(max))
  (max, n)
}

test prop_int_at_most(params via int_at_most()) {
  let (max, n) = params
  n <= max
}

test prop_list_with_elem(xs via list_with_elem(int())) {
  let (xs, x) = xs
  list.has(xs, x)
}

fn list_with_sublist() -> Fuzzer<(List<Int>, List<Int>)> {
  let xs <- and_then(list(int()))
  let sub <- map(sublist(xs))
  (xs, sub)
}

test prop_list_with_subset(params via list_with_sublist()) {
  let (xs, sub) = params
  list.all(sub, fn(x) { list.has(xs, x) })
}

fn bytearray_between() -> Fuzzer<(Int, Int, ByteArray)> {
  let min <- and_then(int_between(0, 32))
  let max <- and_then(int_between(min, min + 32))
  let bytes <- map(fuzz.bytearray_between(min, max))
  (min, max, bytes)
}

test prop_bytearray_between(params via bytearray_between()) {
  let (min, max, bytes) = params
  let len = bytearray.length(bytes)
  len >= min && len <= max
}

test prop_int_between_boundary_up(n via int_between(0, 2)) fail {
  n < 2
}

test prop_int_between_smallest_range(n via int_between(0, 1)) {
  label(
    if n == 0 {
      @"= 0"
    } else {
      @"= 1"
    },
  )
  n == 0 || n == 1
}

test prop_int_between_boundary_down(n via int_between(0, 10)) fail {
  n > 0
}

test prop_one_of_upper(i via one_of([1, 3, 5, 7])) fail {
  i != 7
}

/// A small function for automatically labelling a range of ints.
fn buckets(n, start, end, increment) -> Void {
  expect n >= start
  let next = increment(start)
  if next >= end {
    label(
      [string.from_int(start), @"->", string.from_int(end)]
        |> string.join(@" "),
    )
  } else if n < next {
    label(
      [string.from_int(start), @"->", string.from_int(next)]
        |> string.join(@" "),
    )
  } else {
    buckets(n, next, end, increment)
  }
}
