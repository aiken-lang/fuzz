use aiken/fuzz.{bool, int, label, list, list_between}
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

fn int_range() -> Fuzzer<(Int, Int, Int)> {
  fuzz.int()
    |> fuzz.and_then(
         fn(lo) {
           fuzz.int()
             |> fuzz.and_then(
                  fn(hi) {
                    fuzz.int_between(lo, hi)
                      |> fuzz.map(fn(in) { (lo, hi, in) })
                  },
                )
         },
       )
}

test prop_int_between(triple via int_range()) {
  let (lo, hi, in) = triple
  if lo < hi {
    and {
      lo <= in,
      in <= hi,
    }
  } else {
    and {
      hi <= in,
      in <= lo,
    }
  }
}

const max_u64: Int = 18_446_744_073_709_551_615

const max_u64_minus: Int = -18_446_744_073_709_551_616

test prop_int_between_large(n via fuzz.int_between(max_u64_minus, max_u64)) {
  label(string.from_int(n))
  n >= 1
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
