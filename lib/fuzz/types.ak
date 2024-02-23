pub type Seed {
  size: Int,
  seed: Int,
}

pub type Fuzz<a> =
  fn(Seed) -> (a, Seed)
