use aiken/builtin as bi
use aiken/bytearray as ba
use aiken/math.{pow2}

pub fn int_to_bytearray(x: Int) -> ByteArray {
  if x == 0 {
    ""
  } else {
    ba.push(int_to_bytearray(x / 256), x % 256 )
  }
}

pub fn bytearray_to_int(x: ByteArray) -> Int {
  if ba.length(x) == 0 {
    0
  } else {
    powsum(x, ba.length(x) - 1)
  }
}

fn powsum(x: ByteArray, ix: Int) {
  // UNSAFE : For empty bytearray
  if ix <= 0 {
    bi.index_bytearray(x, ix)
  } else {
    pow2(8 * ix) * bi.index_bytearray(x, ix) + powsum(x, ix - 1)
  }
}

fn int_roundtrip(x : Int) {
  bytearray_to_int(int_to_bytearray(x)) == x
}

test test_int_roundtrip() {
  and {
    int_roundtrip(0),
    int_roundtrip(21312312312),
    int_roundtrip(12838973429872394),
    int_roundtrip(901347983457987435984),
  }
}

fn ba_roundtrip(x : ByteArray) {
  int_to_bytearray(bytearray_to_int(x)) == x
}

test test_ba_roundtrip() {
  and {
    ba_roundtrip(#""),
    ba_roundtrip(#"eeffdda009928738279128737289817283"),
  }
}

test test_int_to_bytearray() {
  and { 
    int_to_bytearray(0) == #"",
    int_to_bytearray(1) == #"01",
    int_to_bytearray(255) == #"ff",
    int_to_bytearray(256) == #"0001",
    int_to_bytearray(512) == #"0002",
    int_to_bytearray(254 + 255 * 256) == #"feff",
  }
}

test test_bytearray_to_int() {
  and {
    bytearray_to_int(#"" ) == 0,
    bytearray_to_int(#"01" ) == 1,
    bytearray_to_int(#"ff" ) == 255,
    bytearray_to_int(#"0100" ) == 1,
    bytearray_to_int(#"0001" ) == 256,
    bytearray_to_int(#"0002" ) == 512,
    bytearray_to_int(#"feff" ) == 254 + 255 * 256 
  }
}

test test_powsum_1() {
  and {
    powsum(#"00", 0) == 0,
    powsum(#"01", 0) == 1,
    powsum(#"ff", 0) == 255,
    powsum(#"0100", 1) == 1,
    powsum(#"0001", 1) == 256,
    powsum(#"0002", 1) == 512,
    powsum(#"ffff", 1) == 255 + 255 * 256 
  }
}

