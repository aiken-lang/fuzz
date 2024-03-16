use aiken/builtin
use aiken/list
use aiken/math
use aiken/option

// Primitives

/// Create a constant [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer) from an arbitrary value.
pub fn constant(a: a) -> Fuzzer<a> {
  fn(s0) { Some((s0, a)) }
}

/// Generate a random [`Bool`](https://aiken-lang.github.io/prelude/aiken.html#Bool) value from a
/// uniform distribution.
///
/// ```aiken
/// test prop_bool(is_true via fuzz.bool()) {
///   is_true || !is_true
/// }
/// ```
pub fn bool() -> Fuzzer<Bool> {
  rand |> map(fn(n) { n % 2 == 0 })
}

/// Generate a random [`ByteArray`](https://aiken-lang.github.io/prelude/aiken.html#ByteArray) of 32 bytes.
pub fn bytearray() -> Fuzzer<ByteArray> {
  let lsb <- and_then(rand)
  let msb <- map(rand)
  ""
    |> builtin.cons_bytearray(lsb, _)
    |> builtin.cons_bytearray(msb, _)
    |> builtin.blake2b_256
}

/// Generate a random [`ByteArray`](https://aiken-lang.github.io/prelude/aiken.html#ByteArray) of
/// size within a lower and upper bounds.
pub fn bytearray_between(min: Int, max: Int) -> Fuzzer<ByteArray> {
  if max < min {
    bytearray_between(max, min)
  } else if max <= 0 {
    constant("")
  } else {
    expect min >= 0
    let size <- and_then(int_between(min, max))
    if size <= 32 {
      map(bytearray(), builtin.slice_bytearray(0, size, _))
    } else {
      let head <- and_then(bytearray())
      let tail <- map(bytearray_between(0, size - 32))
      builtin.append_bytearray(head, tail)
    }
  }
}

const int_bucket_small: Int = 128

const int_bucket_zero: Int = 132

const int_bucket_negative: Int = 192

/// Generate a random integer value. It favors small values near zero, but
/// generate across the range `[-255; 16383]` with the following distribution:
///
/// ```
/// 25.0%  [-255; 0[      ████████████
///  2.5%  0              █
/// 50.0%  ]0; 255]       █████████████████████████
/// 22.5%  [256; 16383]   ██████████
/// ```
///
/// The distribution is uniform within those buckets. If you need larger values, use [`int_between`](#int_between).
pub fn int() -> Fuzzer<Int> {
  fn(prng) {
    when prng is {
      Seeded { seed, choices } -> {
        let fst_choice = builtin.index_bytearray(seed, 0)

        fn(choice, choices) {
          Some((Seeded { seed: builtin.blake2b_256(seed), choices }, choice))
        }
          |> fn(return) {
              if fst_choice < int_bucket_small {
                return(fst_choice, builtin.cons_bytearray(fst_choice, choices))
              } else if fst_choice < int_bucket_zero {
                return(0, builtin.cons_bytearray(fst_choice, choices))
              } else if fst_choice < int_bucket_negative {
                let snd_choice = builtin.index_bytearray(seed, 1)
                return(
                  -snd_choice,
                  builtin.cons_bytearray(
                    snd_choice,
                    builtin.cons_bytearray(fst_choice, choices),
                  ),
                )
              } else {
                let snd_choice = builtin.index_bytearray(seed, 1)
                return(
                  u16(fst_choice - int_bucket_negative, snd_choice),
                  builtin.cons_bytearray(
                    snd_choice,
                    builtin.cons_bytearray(fst_choice, choices),
                  ),
                )
              }
            }
      }

      Replayed { cursor, choices } ->
        if cursor >= 1 {
          let cursor = cursor - 1

          let fst_choice = builtin.index_bytearray(choices, cursor)

          if fst_choice < int_bucket_small {
            Some((Replayed { choices, cursor }, fst_choice))
          } else if fst_choice < int_bucket_zero {
            Some((Replayed { choices, cursor }, 0))
          } else if cursor >= 1 {
            let cursor = cursor - 1

            let snd_choice = builtin.index_bytearray(choices, cursor)

            if fst_choice < int_bucket_negative {
              Some((Replayed { choices, cursor }, -snd_choice))
            } else {
              Some(
                (
                  Replayed { choices, cursor },
                  u16(fst_choice - int_bucket_negative, snd_choice),
                ),
              )
            }
          } else {
            None
          }
        } else {
          None
        }
    }
  }
}

/// Generate a random integer which is at least `min`.
pub fn int_at_least(min: Int) -> Fuzzer<Int> {
  let abs = math.abs(min)
  if abs <= max_rand {
    int_between(min, max_rand)
  } else {
    int_between(min, min + 5 * abs)
  }
}

/// Generate a random integer which is at most `max`.
pub fn int_at_most(max: Int) -> Fuzzer<Int> {
  let abs = math.abs(max)
  if abs <= max_rand {
    int_between(-max_rand, max)
  } else {
    int_between(max - 5 * abs, max)
  }
}

/// Generate integers values uniformly between a lower and upper bounds (both inclusive).
pub fn int_between(min: Int, max: Int) -> Fuzzer<Int> {
  if min > max {
    int_between(max, min)
  } else if min == max {
    constant(min)
  } else {
    let range = max - min + 1
    let log2_floor = log2(range)
    let threshold = math.pow2(log2_floor)
    let n <- and_then(rand)
    if n * range <= max_rand * threshold {
      let offset <- map(rand_n(log2_floor, _))
      offset + min
    } else {
      let offset <- map(int_between(0, range - threshold - 1))
      threshold + offset + min
    }
  }
}

/// Generate a byte uniformly across the range `[0; 255]`.
pub fn byte() -> Fuzzer<Int> {
  rand
}

/// Generate a random list of elements from a given element. The list contains
/// *at most `20`* elements, and has a higher probability of generating smaller lists.
///
/// For lists of a specific length, use [`list_between`](#list_between).
pub fn list(fuzzer: Fuzzer<a>) -> Fuzzer<List<a>> {
  list_between(fuzzer, 0, 20)
}

/// Generate a random list of elements from a given fuzzer, with at least `min` elements.
pub fn list_at_least(fuzzer: Fuzzer<a>, min: Int) -> Fuzzer<List<a>> {
  list_between(fuzzer, min, 20)
}

/// Generate a random list of elements from a given fuzzer, with at most `max` elements.
pub fn list_at_most(fuzzer: Fuzzer<a>, max: Int) -> Fuzzer<List<a>> {
  list_between(fuzzer, 0, max)
}

/// Generate a random list and pick an element from that list. Return both.
pub fn list_with_elem(fuzzer: Fuzzer<a>) -> Fuzzer<(List<a>, a)> {
  let xs <- and_then(list_at_least(fuzzer, 1))
  let x <- map(one_of(xs))
  (xs, x)
}

/// Take a random sublist from an existing list.
pub fn sublist(xs: List<a>) -> Fuzzer<List<a>> {
  let threshold <- and_then(rand)
  when xs is {
    [] -> constant([])
    [head, ..tail] -> {
      let n <- and_then(rand)
      let rest <- map(sublist(tail))
      if n < threshold {
        [head, ..rest]
      } else {
        rest
      }
    }
  }
}

/// Generate a random list of elements with length within specified bounds. The
/// resulting list contains *at least `min`* elements and *at most `max`*
/// elements, with a higher probability of generating smaller lists.
///
/// More specifically, there's approximately 1/n chance of generating n
/// elements within the range. For example, the distribution when generating a
/// list between 0 and 10 elements resemble the following:
///
/// ```
/// 22.7%   0 elements  ████████
/// 19.7%   1 element   ███████
/// 13.5%   2 elements  █████
///  9.5%   3 elements  ███
///  6.3%   4 elements  ██
///  5.6%   5 elements  ██
///  5.6%   6 elements  ██
///  4.0%   7 elements  █
///  3.1%   8 elements  █
///  2.0%   9 elements  █
///  8.0%  10 elements  ███
/// ```
pub fn list_between(fuzzer: Fuzzer<a>, min: Int, max: Int) -> Fuzzer<List<a>> {
  if min > max {
    list_between(fuzzer, max, min)
  } else if max <= 0 {
    constant([])
  } else {
    do_list_between(max - min, log2(max - min), fuzzer, min, max, 0, [])
  }
}

// We generate a list by "flipping a coin" and generating the next element if we
// got 'heads'.
//
// NOTE (2):
//   More mathematically, we consider the probability exp(log(1/(n + 1))/n)
//   of generating another element, where `n` is the maximum length of the list.
//
//   This gives a probability of generating a list of `n` elements of ~ 1/(n+1).
//   So for example, for a list of maximum 2 elements, we have 33% chance of
//   generating a list with 2 elements, 24% of 1 element, and 42% chances of
//   generating an empty list.
//
//   We approximate this probability as: n/(n+3) which for values of n >= 0
//   gives us a good enough approximation less expensive to compute.
//
// NOTE (1):
//   There are the special cases of 'min' and 'max' which may force us to add an element
//   or stop. For those, we still _fake making a choice_ so that even after shrinking the
//   choice sequence, we still generate lists that respect the given invariant.
fn do_list_between(p, q, fuzzer, min, max, length, xs) -> Fuzzer<List<a>> {
  if length < min {
    let x <- and_then(with_choice(min_rand) |> and_then(always(fuzzer, _)))
    do_list_between(p, q, fuzzer, min, max, length + 1, [x, ..xs])
  } else if length == max {
    with_choice(max_rand) |> map(fn(_) { xs })
  } else {
    rand
      |> and_then(
          fn(n) {
            // This is the probability above but rewritten to use only
            // multiplications since division on-chain is expensive.
            if n * ( p + q ) < max_rand * p {
              fuzzer
                |> and_then(
                    fn(x) {
                      do_list_between(
                        p,
                        q,
                        fuzzer,
                        min,
                        max,
                        length + 1,
                        [x, ..xs],
                      )
                    },
                  )
            } else {
              constant(xs)
            }
          },
        )
  }
}

/// Pick a value from a (non-empty!) list with equal probability.
///
/// ```aiken
/// let any_bool = fuzz.one_of([True, False])
/// ```
pub fn one_of(xs: List<a>) -> Fuzzer<a> {
  let len = list.length(xs)
  expect len > 0
  int_between(0, len - 1)
    |> map(
        fn(ix: Int) {
          expect Some(item) = list.at(xs, ix)
          item
        },
      )
}

// Combining Fuzzers

/// Choose either of two fuzzers with an equal probability.
pub fn either(left: Fuzzer<a>, right: Fuzzer<a>) -> Fuzzer<a> {
  let pick_left <- and_then(bool())
  if pick_left {
    left
  } else {
    right
  }
}

/// Combine two fuzzers into a 2-tuple.
pub fn both(left: Fuzzer<a>, right: Fuzzer<b>) -> Fuzzer<(a, b)> {
  map2(left, right, fn(l, r) { (l, r) })
}

/// Choose between `None` or `Some` value with an equal probability.
pub fn option(fuzz_a: Fuzzer<a>) -> Fuzzer<Option<a>> {
  bool()
    |> and_then(
        fn(predicate) {
          if predicate {
            fuzz_a |> map(Some)
          } else {
            constant(None)
          }
        },
      )
}

/// Generate a value that satisfies a given predicate. Beware that this
/// function may heavily impact the performances of your fuzzers. In general, you
/// should prefer constraining the fuzzers beforehand than trying to discard
/// values after the fact!
///
/// Use with caution.
pub fn such_that(fuzzer: Fuzzer<a>, predicate: fn(a) -> Bool) -> Fuzzer<a> {
  do_such_that(fuzzer, predicate, 100)
}

fn do_such_that(
  fuzzer: Fuzzer<a>,
  predicate: fn(a) -> Bool,
  max_tries: Int,
) -> Fuzzer<a> {
  if max_tries <= 0 {
    fail @"such_that: couldn't satisfy the predicate after 100 attempts."
  } else {
    let x <- and_then(fuzzer)
    if predicate(x) {
      constant(x)
    } else {
      do_such_that(fuzzer, predicate, max_tries - 1)
    }
  }
}

/// Combine a [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer) with the result of a another one.
/// This function works great with [backpassing](https://aiken-lang.org/language-tour/functions#backpassing-).
///
/// ```aiken
/// pub fn either(left: Fuzzer<a>, right: Fuzzer<a>) -> Fuzzer<a> {
///   let pick_left <- fuzz.and_then(fuzz.bool())
///   if pick_left {
///     left
///   } else {
///     right
///   }
/// }
/// ```
pub fn and_then(fuzz_a: Fuzzer<a>, f: fn(a) -> Fuzzer<b>) -> Fuzzer<b> {
  fn(s0) {
    when fuzz_a(s0) is {
      Some((s1, a)) -> f(a)(s1)
      None -> None
    }
  }
}

/// Transform the result of a [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer) using a function.
/// This function works great with [backpassing](https://aiken-lang.org/language-tour/functions#backpassing-).
///
/// ```aiken
/// fn bool() -> Fuzzer<Bool> {
///   let n <- map(int_between(1, 100))
///   n % 2
/// }
/// ```
pub fn map(fuzz_a: Fuzzer<a>, f: fn(a) -> b) -> Fuzzer<b> {
  fn(s0) {
    when fuzz_a(s0) is {
      Some((s1, a)) -> Some((s1, f(a)))
      None -> None
    }
  }
}

/// Combine the results of two [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s.
pub fn map2(
  fuzz_0: Fuzzer<t0>,
  fuzz_1: Fuzzer<t1>,
  f: fn(t0, t1) -> result,
) -> Fuzzer<result> {
  fn(s0) {
    when fuzz_0(s0) is {
      Some((s1, t0)) ->
        when fuzz_1(s1) is {
          Some((s2, t1)) -> Some((s2, f(t0, t1)))
          None -> None
        }
      None -> None
    }
  }
}

/// Combine the results of three [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s.
pub fn map3(
  fuzz_0: Fuzzer<t0>,
  fuzz_1: Fuzzer<t1>,
  fuzz_2: Fuzzer<t2>,
  f: fn(t0, t1, t2) -> result,
) -> Fuzzer<result> {
  fn(s0) {
    when fuzz_0(s0) is {
      Some((s1, t0)) ->
        when fuzz_1(s1) is {
          Some((s2, t1)) ->
            when fuzz_2(s2) is {
              Some((s3, t2)) -> Some((s3, f(t0, t1, t2)))
              None -> None
            }
          None -> None
        }
      None -> None
    }
  }
}

/// Combine the results of four [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s.
pub fn map4(
  fuzz_0: Fuzzer<t0>,
  fuzz_1: Fuzzer<t1>,
  fuzz_2: Fuzzer<t2>,
  fuzz_3: Fuzzer<t3>,
  f: fn(t0, t1, t2, t3) -> result,
) -> Fuzzer<result> {
  fn(s0) {
    when fuzz_0(s0) is {
      Some((s1, t0)) ->
        when fuzz_1(s1) is {
          Some((s2, t1)) ->
            when fuzz_2(s2) is {
              Some((s3, t2)) ->
                when fuzz_3(s3) is {
                  Some((s4, t3)) -> Some((s4, f(t0, t1, t2, t3)))
                  None -> None
                }
              None -> None
            }
          None -> None
        }
      None -> None
    }
  }
}

/// Combine the results of five [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s.
pub fn map5(
  fuzz_0: Fuzzer<t0>,
  fuzz_1: Fuzzer<t1>,
  fuzz_2: Fuzzer<t2>,
  fuzz_3: Fuzzer<t3>,
  fuzz_4: Fuzzer<t4>,
  f: fn(t0, t1, t2, t3, t4) -> result,
) -> Fuzzer<result> {
  fn(s0) {
    when fuzz_0(s0) is {
      Some((s1, t0)) ->
        when fuzz_1(s1) is {
          Some((s2, t1)) ->
            when fuzz_2(s2) is {
              Some((s3, t2)) ->
                when fuzz_3(s3) is {
                  Some((s4, t3)) ->
                    when fuzz_4(s4) is {
                      Some((s5, t4)) -> Some((s5, f(t0, t1, t2, t3, t4)))
                      None -> None
                    }
                  None -> None
                }
              None -> None
            }
          None -> None
        }
      None -> None
    }
  }
}

/// Combine the results of six [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s.
pub fn map6(
  fuzz_0: Fuzzer<t0>,
  fuzz_1: Fuzzer<t1>,
  fuzz_2: Fuzzer<t2>,
  fuzz_3: Fuzzer<t3>,
  fuzz_4: Fuzzer<t4>,
  fuzz_5: Fuzzer<t5>,
  f: fn(t0, t1, t2, t3, t4, t5) -> result,
) -> Fuzzer<result> {
  fn(s0) {
    when fuzz_0(s0) is {
      Some((s1, t0)) ->
        when fuzz_1(s1) is {
          Some((s2, t1)) ->
            when fuzz_2(s2) is {
              Some((s3, t2)) ->
                when fuzz_3(s3) is {
                  Some((s4, t3)) ->
                    when fuzz_4(s4) is {
                      Some((s5, t4)) ->
                        when fuzz_5(s5) is {
                          Some((s6, t5)) ->
                            Some((s6, f(t0, t1, t2, t3, t4, t5)))
                          None -> None
                        }
                      None -> None
                    }
                  None -> None
                }
              None -> None
            }
          None -> None
        }
      None -> None
    }
  }
}

/// Combine the results of seven [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s.
pub fn map7(
  fuzz_0: Fuzzer<t0>,
  fuzz_1: Fuzzer<t1>,
  fuzz_2: Fuzzer<t2>,
  fuzz_3: Fuzzer<t3>,
  fuzz_4: Fuzzer<t4>,
  fuzz_5: Fuzzer<t5>,
  fuzz_6: Fuzzer<t6>,
  f: fn(t0, t1, t2, t3, t4, t5, t6) -> result,
) -> Fuzzer<result> {
  fn(s0) {
    when fuzz_0(s0) is {
      Some((s1, t0)) ->
        when fuzz_1(s1) is {
          Some((s2, t1)) ->
            when fuzz_2(s2) is {
              Some((s3, t2)) ->
                when fuzz_3(s3) is {
                  Some((s4, t3)) ->
                    when fuzz_4(s4) is {
                      Some((s5, t4)) ->
                        when fuzz_5(s5) is {
                          Some((s6, t5)) ->
                            when fuzz_6(s6) is {
                              Some((s7, t6)) ->
                                Some((s7, f(t0, t1, t2, t3, t4, t5, t6)))
                              None -> None
                            }
                          None -> None
                        }
                      None -> None
                    }
                  None -> None
                }
              None -> None
            }
          None -> None
        }
      None -> None
    }
  }
}

/// Combine the results of eight [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s.
pub fn map8(
  fuzz_0: Fuzzer<t0>,
  fuzz_1: Fuzzer<t1>,
  fuzz_2: Fuzzer<t2>,
  fuzz_3: Fuzzer<t3>,
  fuzz_4: Fuzzer<t4>,
  fuzz_5: Fuzzer<t5>,
  fuzz_6: Fuzzer<t6>,
  fuzz_7: Fuzzer<t7>,
  f: fn(t0, t1, t2, t3, t4, t5, t6, t7) -> result,
) -> Fuzzer<result> {
  fn(s0) {
    when fuzz_0(s0) is {
      Some((s1, t0)) ->
        when fuzz_1(s1) is {
          Some((s2, t1)) ->
            when fuzz_2(s2) is {
              Some((s3, t2)) ->
                when fuzz_3(s3) is {
                  Some((s4, t3)) ->
                    when fuzz_4(s4) is {
                      Some((s5, t4)) ->
                        when fuzz_5(s5) is {
                          Some((s6, t5)) ->
                            when fuzz_6(s6) is {
                              Some((s7, t6)) ->
                                when fuzz_7(s7) is {
                                  Some((s8, t7)) ->
                                    Some(
                                      (s8, f(t0, t1, t2, t3, t4, t5, t6, t7)),
                                    )
                                  None -> None
                                }
                              None -> None
                            }
                          None -> None
                        }
                      None -> None
                    }
                  None -> None
                }
              None -> None
            }
          None -> None
        }
      None -> None
    }
  }
}

/// Combine the results of nine [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s.
pub fn map9(
  fuzz_0: Fuzzer<t0>,
  fuzz_1: Fuzzer<t1>,
  fuzz_2: Fuzzer<t2>,
  fuzz_3: Fuzzer<t3>,
  fuzz_4: Fuzzer<t4>,
  fuzz_5: Fuzzer<t5>,
  fuzz_6: Fuzzer<t6>,
  fuzz_7: Fuzzer<t7>,
  fuzz_8: Fuzzer<t8>,
  f: fn(t0, t1, t2, t3, t4, t5, t6, t7, t8) -> result,
) -> Fuzzer<result> {
  fn(s0) {
    when fuzz_0(s0) is {
      Some((s1, t0)) ->
        when fuzz_1(s1) is {
          Some((s2, t1)) ->
            when fuzz_2(s2) is {
              Some((s3, t2)) ->
                when fuzz_3(s3) is {
                  Some((s4, t3)) ->
                    when fuzz_4(s4) is {
                      Some((s5, t4)) ->
                        when fuzz_5(s5) is {
                          Some((s6, t5)) ->
                            when fuzz_6(s6) is {
                              Some((s7, t6)) ->
                                when fuzz_7(s7) is {
                                  Some((s8, t7)) ->
                                    when fuzz_8(s8) is {
                                      Some((s9, t8)) ->
                                        Some(
                                          (
                                            s9,
                                            f(
                                              t0,
                                              t1,
                                              t2,
                                              t3,
                                              t4,
                                              t5,
                                              t6,
                                              t7,
                                              t8,
                                            ),
                                          ),
                                        )
                                      None -> None
                                    }
                                  None -> None
                                }
                              None -> None
                            }
                          None -> None
                        }
                      None -> None
                    }
                  None -> None
                }
              None -> None
            }
          None -> None
        }
      None -> None
    }
  }
}

/// Label a test case. Labels are collected at the end of a property run and a
/// distribution amongst all labels is computed and shown. This is particularly
/// useful to assert that specific scenarios are met or to test your fuzzers.
///
/// ```aiken
/// test prop_bool_distribution(is_true via bool()) {
///   label(
///     if is_true {
///       @"True"
///     } else {
///       @"False"
///     },
///   )
///
///   True
/// }
/// ```
pub fn label(str: String) -> Void {
  str
    |> builtin.append_string(@"\0", _)
    |> builtin.debug(Void)
}

/// Apply a label when a predicate is true, or fallback to a default label.
/// Useful for labelling specific scenarios based on a predicate.
///
/// ```aiken
/// test prop_u16(operands via fuzz.both(byte(), byte())) {
///   let (msb, lsb) = operands
///   fuzz.label_when(msb == 0, @"msb = 0", @"default")
///   fuzz.label_when(lsb == 0, @"lsb = 0", @"default")
///   builtin.bytearray_to_integer(
///     False,
///     ""
///       |> builtin.cons_bytearray(msb, _)
///       |> builtin.cons_bytearray(lsb, _),
///   ) == msb * 256 + lsb
/// }
/// ```
pub fn label_when(predicate: Bool, str: String, default: String) -> Void {
  if predicate {
    label(str)
  } else {
    label(default)
  }
}

// Internal

const max_rand = 255

const min_rand = 0

//. A choice made from a Pseudo-random number generator. The generator can come in two shapes:
///
/// - Either it is `Seeded`, in which case leverage the pseudo-randomness of hashing algorithms to generate a value and a new seed.
///
/// - Or it is `Replayed` in case where we're trying to shrink a known counter-example. Because a `Replayed` generator has usually been altered, it isn't guaranteed to be a valid sequence. It is possible, for example, that we run out of values to draw from.
///
/// Either ways, the PRNG's choices are *always* non-negative integers.
fn rand(prng: PRNG) -> Option<(PRNG, Int)> {
  when prng is {
    Seeded { seed, choices } -> {
      let choice =
        seed
          |> builtin.index_bytearray(0)

      Some(
        (
          Seeded {
            seed: builtin.blake2b_256(seed),
            choices: builtin.cons_bytearray(choice, choices),
          },
          choice,
        ),
      )
    }

    Replayed { cursor, choices } ->
      if cursor >= 1 {
        let cursor = cursor - 1
        Some(
          (
            Replayed { choices, cursor },
            builtin.index_bytearray(choices, cursor),
          ),
        )
      } else {
        None
      }
  }
}

fn rand_n(bits: Int, prng: PRNG) -> Option<(PRNG, Int)> {
  let (prng, buffer) <- option.map(do_rand_n("", bits, prng))
  (prng, builtin.bytearray_to_integer(True, buffer))
}

fn do_rand_n(
  buffer: ByteArray,
  bits: Int,
  prng: PRNG,
) -> Option<(PRNG, ByteArray)> {
  let (prng, n) <- option.and_then(rand(prng))
  if bits <= 8 {
    Some((prng, builtin.cons_bytearray(n % math.pow2(bits), buffer)))
  } else {
    do_rand_n(builtin.cons_bytearray(n, buffer), bits - 8, prng)
  }
}

fn rand_n_fixture() -> Fuzzer<(Int, Int)> {
  let bits <-
    and_then(
      either(
        constant(1),
        either(constant(5), either(constant(8), constant(25))),
      ),
    )
  let n <- map(rand_n(bits, _))
  (bits, n)
}

test prop_rand_n(fixture via rand_n_fixture()) {
  let (bits, n) = fixture
  n >= 0 && n < math.pow2(bits)
}

test rand_n_distribution_20(n via rand_n(20, _)) {
  label(
    if n < 256 {
      // 256 / 2^20
      @"~ 0.025%"
    } else if n < 65536 {
      // (2^16 - 2^8) / 2^20
      @"~ 6.225%"
    } else {
      // (2^20 - 2^16) / 2^20
      @"~ 93.75%"
    },
  )

  True
}

fn with_choice(choice: Int) -> Fuzzer<Int> {
  fn(prng) {
    when prng is {
      Seeded { seed, choices } ->
        Some(
          (
            Seeded { seed, choices: builtin.cons_bytearray(choice, choices) },
            choice,
          ),
        )
      Replayed { cursor, choices } ->
        if cursor >= 1 {
          let cursor = cursor - 1
          let drawn = builtin.index_bytearray(choices, cursor)
          if choice == drawn {
            Some((Replayed { choices, cursor }, choice))
          } else {
            None
          }
        } else {
          None
        }
    }
  }
}

fn log2(x: Int) -> Int {
  expect x > 0
  let s = builtin.integer_to_bytearray(True, 0, x)
  let len = builtin.length_of_bytearray(s)
  let b = builtin.index_bytearray(s, 0)
  len * 8 - if b < 2 {
    8
  } else if b < 4 {
    7
  } else if b < 8 {
    6
  } else if b < 16 {
    5
  } else if b < 32 {
    4
  } else if b < 64 {
    3
  } else if b < 128 {
    2
  } else {
    1
  }
}

test unit_log2_1() {
  and {
    log2(1) == 0,
    log2(2) == 1,
    log2(3) == 1,
    log2(4) == 2,
    log2(256) == 8,
    log2(257) == 8,
    log2(511) == 8,
    log2(1025) == 10,
  }
}

/// Construct a larger int from two u8 operands.
/// The most significant part is given first.
fn u16(msb: Int, lsb: Int) -> Int {
  builtin.bytearray_to_integer(
    False,
    ""
      |> builtin.cons_bytearray(msb, _)
      |> builtin.cons_bytearray(lsb, _),
  )
}

test prop_u16(operands via both(rand, rand)) {
  let (msb, lsb) = operands
  label_when(msb == 0, @"msb = 0", @"default")
  label_when(lsb == 0, @"lsb = 0", @"default")
  u16(msb, lsb) == msb * 256 + lsb
}
