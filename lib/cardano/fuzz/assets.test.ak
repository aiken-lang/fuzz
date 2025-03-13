use aiken/collection/dict
use aiken/fuzz
use cardano/assets.{PolicyId, Value}
use cardano/fuzz as cardano

fn help_prop_value_with() -> Fuzzer<(PolicyId, Value)> {
  let policy <- fuzz.and_then(cardano.policy_id())
  let value <-
    fuzz.map(
      cardano.value_with(
        assets.from_lovelace(1000000),
        fuzz.constant([policy]),
        fn(_) { cardano.asset_name() },
        fn(_) { fuzz.int_at_least(1) },
      ),
    )
  (policy, value)
}

test prop_value_with((policy, value) via help_prop_value_with()) {
  assets.tokens(value, policy) != dict.empty
}

fn help_prop_value() -> Fuzzer<(Value, Value)> {
  let initial <- fuzz.and_then(cardano.lovelace())
  let extended <- fuzz.map(cardano.value(initial))
  (initial, extended)
}

test prop_value((initial, extended) via help_prop_value()) {
  assets.reduce(
    extended,
    True,
    fn(policy_id, asset_name, quantity, is_larger) {
      is_larger && assets.quantity_of(initial, policy_id, asset_name) <= quantity
    },
  )
}
