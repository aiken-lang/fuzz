use aiken/fuzz.{bool, int, label, list, list_between}
use aiken/list
use aiken/math

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
