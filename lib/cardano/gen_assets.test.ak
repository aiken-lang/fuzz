use aiken/collection/dict
use aiken/fuzz.{and_then, map}
use cardano/assets
use cardano/gen_assets.{
  any_policy_id, any_value, any_value_extending, any_value_with,
}

test prop_any_value(v via any_value()) {
  expect _: assets.Value = v
}

fn help_prop_any_value_with() -> Fuzzer<(assets.PolicyId, assets.Value)> {
  let policy <- and_then(any_policy_id())
  map(any_value_with(policy), fn(b) { (policy, b) })
}

test prop_any_value_with((policy, value) via help_prop_any_value_with()) {
  assets.tokens(value, policy) != dict.empty
}

fn help_prop_any_value_extending() -> Fuzzer<(assets.Value, assets.Value)> {
  let v <- and_then(any_value())
  map(any_value_extending(v), fn(ve) { (v, ve) })
}

test prop_any_value_extending(
  (value, value_extended) via help_prop_any_value_extending(),
) {
  assets.reduce(
    value,
    True,
    fn(p, a, i, r) { r && assets.quantity_of(value_extended, p, a) >= i },
  )
}
// Here we will need to fuzz for the constaints,
// then we need to convert the constraints into values.
// Then need to match on both sides.
// test prop_any_constrained_value() {
// todo
// }
