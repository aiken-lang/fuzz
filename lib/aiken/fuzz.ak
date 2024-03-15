use aiken/builtin
use aiken/list
use aiken/math

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

fn rand_n(n_bits: Int, prng: PRNG) -> Option<(PRNG, Int)> {
  let n_bytes = n_bits - 1 / 8 + 1
  let ub = math.pow2(n_bits)
  when prng is {
    Seeded { seed, choices } -> {
      let segment =
        seed
          |> builtin.slice_bytearray(0, n_bytes, _)
      let choice =
        segment
          |> builtin.bytearray_to_integer(True, _)
          |> builtin.mod_integer(ub)

      Some(
        (
          Seeded {
            seed: builtin.blake2b_256(seed),
            choices: builtin.append_bytearray(segment, choices),
          },
          choice,
        ),
      )
    }

    Replayed { cursor, choices } ->
      if cursor >= 1 {
        // FIXME :: WHICH WAY DOES THE CURSOR READ?!
        let cursor = cursor - n_bytes
        Some(
          (
            Replayed { choices, cursor },
            builtin.slice_bytearray(cursor - n_bytes, n_bytes, choices)
              |> builtin.bytearray_to_integer(True, _)
              |> builtin.mod_integer(ub),
          ),
        )
      } else {
        None
      }
  }
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

// Primitives

/// Create a constant [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer) from an arbitrary value.
pub fn constant(a: a) -> Fuzzer<a> {
  fn(s0) { Some((s0, a)) }
}

/// Generate a random `Bool` value.
pub fn bool() -> Fuzzer<Bool> {
  rand |> map(fn(n) { n % 2 == 0 })
}

pub fn bytearray() -> Fuzzer<ByteArray> {
  fail
}

pub fn bytearray_between(_min: Int, _max: Int) -> Fuzzer<ByteArray> {
  fail
}

const int_bucket_small: Int = 128

const int_bucket_zero: Int = 132

const int_bucket_negative: Int = 192

/// Generate a random integer value. It favors small values near zero, but
/// generate across the range `[-255; 16383]` with the following distribution:
///
/// ```
/// (25.0%) [-255; 0[      ████████████
/// ( 2.5%) 0              █
/// (50.0%) ]0; 255]       █████████████████████████
/// (22.5%) [256; 16383]   ██████████
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

pub fn int_between(lo: Int, hi: Int) -> Fuzzer<Int> {
  if lo < hi {
    int_between(lo, hi)
  } else if lo == hi {
    constant(lo)
  } else {
    let max = hi - lo
    let max_pow2 = math.pow2(log2(max))
    {
      let n <- and_then(rand)
      if n * max <= max_rand * max_pow2 {
        todo @"uniform randomness in power-of-two bucket"
      } else {
        let offset <- map(int_between(0, max - max_pow2))
        max_pow2 + offset
      }
    }
      |> map(fn(n) { n + lo })
  }
}

const p: Int = 50452517

const q: Int = 36183557

pub fn int_between_primes(min: Int, max: Int) -> Fuzzer<Int> {
  if max < min {
    int_between_primes(max, min)
  } else if max == min {
    constant(max)
  } else {
    let delta = max - min
    if delta <= max_rand {
      let n <- map(rand)
      min + n % ( delta + 1 )
    } else {
      let msb, lsb <- map2(rand, rand)
      min + ( u16(msb, lsb) * p + q ) % ( delta + 1 )
    }
  }
}

/// Generate a random list of elements from a given element.
pub fn list(fuzzer: Fuzzer<a>) -> Fuzzer<List<a>> {
  list_between(fuzzer, 0, 32)
}

/// Generate a random list of elements with length within specified bounds.
pub fn list_between(fuzzer: Fuzzer<a>, min: Int, max: Int) -> Fuzzer<List<a>> {
  if min > max {
    list_between(fuzzer, max, min)
  } else if max <= 0 {
    constant([])
  } else {
    do_list_between(min + max / 2, fuzzer, min, max, 0, [])
  }
}

// We generate a list by "flipping a coin" and generating the next element if we
// got 'heads'. More mathematically, we consider the probability 1 - 1 / (1 + avg)
// of generating another element.
//
// There are the special cases of 'min' and 'max' which may force us to add an element
// or stop. For those, we still _fake making a choice_ so that even after shrinking the
// choice sequence, we still generate lists that respect the given invariant.
fn do_list_between(avg, fuzzer, min, max, length, xs) -> Fuzzer<List<a>> {
  if length < min {
    with_choice(min_rand)
      |> and_then(always(fuzzer, _))
      |> and_then(
          fn(x) {
            do_list_between(avg, fuzzer, min, max, length + 1, [x, ..xs])
          },
        )
  } else if length >= max {
    with_choice(max_rand)
      |> map(fn(_) { xs })
  } else {
    rand
      |> and_then(
          fn(n) {
            // This is the probability above but simplified to use only
            // multiplications since division on-chain is expensive.
            if n + n * avg <= max_rand * avg {
              fuzzer
                |> and_then(
                    fn(x) {
                      do_list_between(
                        avg,
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

// Will error on an empty list
/// Fuzzing types from aiken prelude
/// Fuzzer that chooses an item from a list.
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

pub fn either(_fuzz_a: Fuzzer<a>, _fuzz_b: Fuzzer<a>) -> Fuzzer<a> {
  fail
}

pub fn both(left: Fuzzer<a>, right: Fuzzer<b>) -> Fuzzer<(a, b)> {
  map2(left, right, fn(l, r) { (l, r) })
}

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

/// Combine a [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer) with the result of a another one.
pub fn and_then(fuzz_a: Fuzzer<a>, f: fn(a) -> Fuzzer<b>) -> Fuzzer<b> {
  fn(s0) {
    when fuzz_a(s0) is {
      Some((s1, a)) -> f(a)(s1)
      None -> None
    }
  }
}

/// Transform the result of a [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer) using a function.
pub fn map(fuzz_a: Fuzzer<a>, f: fn(a) -> b) -> Fuzzer<b> {
  fn(s0) {
    when fuzz_a(s0) is {
      Some((s1, a)) -> Some((s1, f(a)))
      None -> None
    }
  }
}

/// Combine the results of two [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s
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

/// Combine the results of three [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s
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

/// Combine the results of four [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s
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

/// Combine the results of five [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s
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

/// Combine the results of six [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s
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

/// Combine the results of seven [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s
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

/// Combine the results of eight [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s
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

/// Combine the results of nine [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s
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

pub fn label(str: String) -> Void {
  str
    |> builtin.append_string(@"\0", _)
    |> builtin.debug(Void)
}

pub fn label_when(predicate: Bool, str: String, default: String) -> Void {
  if predicate {
    label(str)
  } else {
    label(default)
  }
}

// Internal

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

fn uint(bits: Int) -> Fuzzer<Int> {
  expect bits > 0
  expect bits <= 256
  rand_n(bits, _)
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
