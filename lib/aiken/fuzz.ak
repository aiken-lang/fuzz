use aiken/builtin
use aiken/list

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
  fail
}

pub fn bytearray_between(_min: Int, _max: Int) -> Fuzzer<ByteArray> {
  fail
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
  fuzz_a: Fuzzer<a>,
  fuzz_b: Fuzzer<b>,
  f: fn(a, b) -> result,
) -> Fuzzer<result> {
  fn(s0) {
    when fuzz_a(s0) is {
      Some((s1, a)) ->
        when fuzz_b(s1) is {
          Some((s2, b)) -> Some((s2, f(a, b)))
          None -> None
        }
      None -> None
    }
  }
}

/// Combine the results of three [Fuzzer](https://aiken-lang.github.io/prelude/aiken.html#Fuzzer)s
pub fn map3(
  fuzz_a: Fuzzer<a>,
  fuzz_b: Fuzzer<b>,
  fuzz_c: Fuzzer<c>,
  f: fn(a, b, c) -> result,
) -> Fuzzer<result> {
  fn(s0) {
    when fuzz_a(s0) is {
      Some((s1, a)) ->
        when fuzz_b(s1) is {
          Some((s2, b)) ->
            when fuzz_c(s2) is {
              Some((s3, c)) -> Some((s3, f(a, b, c)))
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
  fuzz_a: Fuzzer<a>,
  fuzz_b: Fuzzer<b>,
  fuzz_c: Fuzzer<c>,
  fuzz_d: Fuzzer<d>,
  f: fn(a, b, c, d) -> result,
) -> Fuzzer<result> {
  fn(s0) {
    when fuzz_a(s0) is {
      Some((s1, a)) ->
        when fuzz_b(s1) is {
          Some((s2, b)) ->
            when fuzz_c(s2) is {
              Some((s3, c)) ->
                when fuzz_d(s3) is {
                  Some((s4, d)) -> Some((s4, f(a, b, c, d)))
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
  fuzz_a: Fuzzer<a>,
  fuzz_b: Fuzzer<b>,
  fuzz_c: Fuzzer<c>,
  fuzz_d: Fuzzer<d>,
  fuzz_e: Fuzzer<e>,
  f: fn(a, b, c, d, e) -> result,
) -> Fuzzer<result> {
  fn(s0) {
    when fuzz_a(s0) is {
      Some((s1, a)) ->
        when fuzz_b(s1) is {
          Some((s2, b)) ->
            when fuzz_c(s2) is {
              Some((s3, c)) ->
                when fuzz_d(s3) is {
                  Some((s4, d)) ->
                    when fuzz_e(s4) is {
                      Some((s5, e)) -> Some((s5, f(a, b, c, d, e)))
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
    |> builtin.append_string(@" ", _)
    |> builtin.debug(Void)
}
