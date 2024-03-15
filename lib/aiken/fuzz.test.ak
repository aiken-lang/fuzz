use aiken/fuzz.{bool, int, label, list}
use aiken/list

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
