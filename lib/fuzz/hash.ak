use fuzz

pub fn blake2b_224() -> fuzz.Fuzzer<ByteArray> {
  fuzz.bytearray_fixed(28)
}

pub fn blake2b_256() -> fuzz.Fuzzer<ByteArray> {
  fuzz.bytearray_fixed(32)
}

pub fn sha2_256() -> fuzz.Fuzzer<ByteArray> {
  fuzz.bytearray_fixed(32)
}

pub fn sha3_256() -> fuzz.Fuzzer<ByteArray> {
  fuzz.bytearray_fixed(32)
}
