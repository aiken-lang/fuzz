use aiken/builtin
use aiken/bytearray
use aiken/hash.{blake2b_256}
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

fn u16(msb: Int, lsb: Int) -> Int {
  builtin.bytearray_to_integer(
    True,
    ""
      |> builtin.cons_bytearray(msb, _)
      |> builtin.cons_bytearray(lsb, _),
  )
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
  bytearray_between(0, 1024)
}

pub fn bytearray_between(min: Int, max: Int) -> Fuzzer<ByteArray> {
  let bytes <- and_then(list_between(byte(), min, max))
  constant(list.foldl(bytes, #"", bytearray.concat))
}

/// Generate a random integer value. It favors small values near zero, but generate across the whole range [-2^64; 2^64 - 1]
pub fn int() -> Fuzzer<Int> {
  fn(prng) {
    when prng is {
      Seeded { seed, choices } -> {
        let fst_choice = builtin.index_bytearray(seed, 0)

        fn(choice, choices) {
          Some((Seeded { seed: builtin.blake2b_256(seed), choices }, choice))
        }
          |> fn(return) {
              if fst_choice < 128 {
                return(fst_choice, builtin.cons_bytearray(fst_choice, choices))
              } else if fst_choice < 224 {
                return(
                  fst_choice % 16,
                  builtin.cons_bytearray(fst_choice % 16, choices),
                )
              } else if fst_choice < 236 {
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
                  u16(fst_choice, snd_choice),
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
          if fst_choice < 224 {
            Some((Replayed { choices, cursor }, fst_choice))
          } else if fst_choice < 236 && cursor >= 1 {
            let cursor = cursor - 1
            let snd_choice = builtin.index_bytearray(choices, cursor)
            Some((Replayed { choices, cursor }, -snd_choice))
          } else if cursor >= 1 {
            let cursor = cursor - 1
            let snd_choice = builtin.index_bytearray(choices, cursor)
            Some((Replayed { choices, cursor }, u16(fst_choice, snd_choice)))
          } else {
            None
          }
        } else {
          None
        }
    }
  }
}

pub fn positive_int() -> Fuzzer<Int> {
  int() |> map(math.abs) |> map(fn(x) { x + 1 })
}

pub fn nonnegative_int() -> Fuzzer<Int> {
  int() |> map(math.abs)
}

pub fn negative_int() -> Fuzzer<Int> {
  int() |> map(fn(x) { -math.abs(x + 1) })
}

pub fn int_between(min: Int, max: Int) -> Fuzzer<Int> {
  if max < min {
    int_between(max, min)
  } else if max == min {
    constant(max)
  } else {
    let mid = ( max + min ) / 2
    let delta = ( max - min ) / 2
    int()
      |> and_then(
          fn(lo) {
            int()
              |> map(fn(hi) { mid - lo % ( delta + 1 ) + hi % ( delta + 1 ) })
          },
        )
  }
}

pub fn uniform(bits: Int) -> Fuzzer<Int> {
  // TODO: switch to Han-Hoshi for better uniform, and support min/max?
  if bits == 0 {
    constant(0)
  } else {
    let bit <- and_then(bool())
    let rest <- and_then(uniform(bits - 1))
    if bit {
      constant(rest * 2 + 1)
    } else {
      constant(rest * 2)
    }
  }
}

pub fn byte() -> Fuzzer<ByteArray> {
  let byte <- and_then(int_between(0, 255))
  constant(bytearray.push(#"", byte))
}

pub fn hash() -> Fuzzer<ByteArray> {
  let b <- and_then(byte())
  let hash = blake2b_256(b)
  constant(bytearray.take(hash, 28))
}

/// Generate a random list of elements from a given element.
pub fn list(fuzzer: Fuzzer<a>) -> Fuzzer<List<a>> {
  list_between(fuzzer, 0, 32)
}

pub fn nonempty_list(fuzzer: Fuzzer<a>) -> Fuzzer<List<a>> {
  list_between(fuzzer, 1, 32)
}

pub fn sorted(
  fuzzer: Fuzzer<List<a>>,
  compare: fn(a, a) -> Ordering,
) -> Fuzzer<List<a>> {
  let ls <- and_then(fuzzer)
  constant(list.sort(ls, compare))
}

pub fn list_with_elem(fuzzer: Fuzzer<a>) -> Fuzzer<(List<a>, a)> {
  let xs <- and_then(nonempty_list(fuzzer))
  let x <- and_then(one_of(xs))
  constant((xs, x))
}

pub fn list_with_subset(fuzzer: Fuzzer<a>) -> Fuzzer<(List<a>, List<a>)> {
  let xs <- and_then(list(fuzzer))
  let bits <- and_then(list_between(bool(), 0, list.length(xs)))
  let ys =
    list.filter(
      list.zip(xs, bits),
      fn(pair) {
        let (_, b) = pair
        b
      },
    )
  let (ys, _) = list.unzip(ys)
  constant((xs, ys))
}

pub fn filter(fuzzer: Fuzzer<a>, predicate: fn(a) -> Bool) -> Fuzzer<a> {
  do_filter(fuzzer, predicate, 100)
}

fn do_filter(
  fuzzer: Fuzzer<a>,
  predicate: fn(a) -> Bool,
  max_tries: Int,
) -> Fuzzer<a> {
  if max_tries <= 0 {
    fail
  } else {
    let x <- and_then(fuzzer)
    if predicate(x) {
      constant(x)
    } else {
      do_filter(fuzzer, predicate, max_tries - 1)
    }
  }
}

pub fn distinct(fuzzer: Fuzzer<List<a>>) -> Fuzzer<List<a>> {
  let xs <- and_then(fuzzer)
  constant(dedup(xs, []))
}

fn dedup(xs: List<a>, seen: List<a>) -> List<a> {
  when xs is {
    [] ->
      []
    [x, ..xs] ->
      if list.has(seen, x) {
        dedup(xs, seen)
      } else {
        [x, ..dedup(xs, [x, ..seen])]
      }
  }
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
  uniform(math.log(len, 2) + 1)
    |> map(
        fn(ix: Int) {
          expect Some(item) = list.at(xs, ix % len)
          item
        },
      )
}

// Combining Fuzzers

pub fn either(fuzz_a: Fuzzer<a>, fuzz_b: Fuzzer<a>) -> Fuzzer<a> {
  bool()
    |> and_then(
        fn(b) {
          if b {
            fuzz_a
          } else {
            fuzz_b
          }
        },
      )
}

pub fn ordered_pair(
  fuzz_a: Fuzzer<a>,
  fuzz_b: Fuzzer<a>,
  compare: fn(a, a) -> Ordering,
) -> Fuzzer<(a, a)> {
  let a <- and_then(fuzz_a)
  let b <- and_then(fuzz_b)
  if compare(a, b) == Greater {
    constant((b, a))
  } else {
    constant((a, b))
  }
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
