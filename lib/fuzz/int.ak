use aiken/math.{pow2}
use fuzz/types.{Seed, Fuzz}
use fuzz/base.{step_seed}

pub fn int_range(lo: Int, hi: Int) -> Fuzz<Int> {
  /// Bounds inclusive
  fn(s: Seed) { (s.seed % ( 1 + hi - lo ) + lo , step_seed(s)) }
}

pub fn int() -> Fuzz<Int> {
  fn(s: Seed) { int_range( - pow2(s.size), pow2(s.size) )(s) }
}

pub fn pos_int() -> Fuzz<Int> {
  fn(s: Seed) { int_range( 1, pow2(s.size) )(s) }
}

pub fn non_neg_int() -> Fuzz<Int> {
  fn(s: Seed) { int_range( 0, pow2(s.size) )(s) }
}

