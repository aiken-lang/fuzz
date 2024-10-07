use cardano/address
use cardano/gen_address.{any_address, any_credential}

test prop_any_credential(c via any_credential()) {
  expect _: address.Credential = c
}

test prop_any_address(a via any_address()) {
  expect _: address.Address = a
}
