use aiken/collection/dict
use aiken/collection/list
use aiken/fuzz
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/fuzz as cardano

fn help_prop_value_with() -> Fuzzer<(PolicyId, Value)> {
  let policy <- fuzz.and_then(cardano.policy_id())
  let value <- fuzz.map(cardano.assets(policy))
  (policy, value)
}

test prop_value_with((policy, value) via help_prop_value_with()) {
  assets.tokens(value, policy) != dict.empty
}

fn help_prop_value() -> Fuzzer<(Value, Value)> {
  let initial <- fuzz.and_then(cardano.lovelace())
  let extended <- fuzz.and_then(value(initial))
  (initial, extended)
}

test prop_value((initial, extended) via help_prop_value_extending()) {
  assets.reduce(
    extended,
    True,
    fn(policy_id, asset_name, quantity, is_larger) {
      is_larger && assets.quantity_of(initial, policy_id, asset_name) <= quantity
    },
  )
}

/// Helper function to generate asset constraints for a single policy
fn asset_constraint() -> Fuzzer<Pair<AssetName, Pair<Int, Int>>> {
  let min_quantity <- and_then(int_at_least(0))
  let max_quantity <- and_then(int_between(min_quantity, min_quantity + 100))
  fuzz.map(
    cardano.asset_name(),
    fn(asset_name) { Pair(asset_name, Pair(min_quantity, max_quantity)) },
  )
}

/// Helper function to generate constraints for a single policy
fn policy_constraints() -> Fuzzer<
  Pair<PolicyId, List<Pair<AssetName, Pair<Int, Int>>>>,
> {
  let asset_constraints <- and_then(list_between(asset_constraint(), 1, 10))
  map(policy_id(), fn(p) { Pair(p, asset_constraints) })
}

/// Helper function to generate a list of policy constraints
fn constraints() -> Fuzzer<
  List<Pair<PolicyId, List<Pair<AssetName, Pair<Int, Int>>>>>,
> {
  list_between(policy_constraints(), 1, 5)
}

/// Fuzzer to generate constraints along with a constrained value
fn help_prop_constrained_value() -> Fuzzer<
  Pair<List<Pair<PolicyId, List<Pair<AssetName, Pair<Int, Int>>>>>, Value>,
> {
  let constraints <- and_then(constraints())
  let merged = merge_policy_constraints(constraints)
  let a_c_v = constrained_value(merged)
  map(a_c_v, fn(v) { Pair(merged, v) })
}

///
/// Function to merge multiple constraints for the same asset within the same policy
fn merge_asset_constraints(
  asset_constraints: List<Pair<AssetName, Pair<Int, Int>>>,
) -> List<Pair<AssetName, Pair<Int, Int>>> {
  let grouped =
    list.foldr(
      asset_constraints,
      dict.empty,
      fn(pair, acc) {
        let Pair(asset_name, Pair(min, max)) = pair
        when dict.pop(acc, asset_name) is {
          (Some(Pair(existing_min, existing_max)), acc) -> {
            let new_min =
              if min < existing_min {
                min
              } else {
                existing_min
              }
            let new_max =
              if max > existing_max {
                max
              } else {
                existing_max
              }
            dict.insert(acc, asset_name, Pair(new_min, new_max))
          }
          (None, acc) -> dict.insert(acc, asset_name, Pair(min, max))
        }
      },
    )
  dict.to_pairs(grouped)
}

/// Function to merge multiple PolicyIds and their asset constraints into unique PolicyIds with merged asset constraints
fn merge_policy_constraints(
  constraints: List<Pair<PolicyId, List<Pair<AssetName, Pair<Int, Int>>>>>,
) -> List<Pair<PolicyId, List<Pair<AssetName, Pair<Int, Int>>>>> {
  // Group all asset constraints by PolicyId
  let grouped_policies =
    list.foldr(
      constraints,
      dict.empty,
      fn(pair, acc) {
        let Pair(policy_id, asset_constraints) = pair
        when dict.pop(acc, policy_id) is {
          (Some(existing_constraints), acc) ->
            dict.insert(
              acc,
              policy_id,
              list.concat(asset_constraints, existing_constraints),
            )
          (None, acc) -> dict.insert(acc, policy_id, asset_constraints)
        }
      },
    )

  // For each PolicyId, merge its asset constraints
  // let l_acc: List<Pair<PolicyId, List<Pair<AssetName, Pair<Int, Int>>>>> = []
  let merged_policies =
    dict.foldr(
      grouped_policies,
      [],
      fn(policy_id, asset_constraints, acc) {
        let merged_assets = merge_asset_constraints(asset_constraints)
        list.push(acc, Pair(policy_id, merged_assets))
      },
    )
  merged_policies
}

fn verify_constraints(
  constraints: List<Pair<PolicyId, List<Pair<AssetName, Pair<Int, Int>>>>>,
  value: Value,
) -> Bool {
  list.all(
    constraints,
    fn(constraint) {
      let Pair(policy_id, asset_constraints) = constraint
      let tokens = assets.tokens(value, policy_id)
      list.all(
        asset_constraints,
        fn(asset_constraint) {
          let Pair(asset_name, Pair(min, max)) = asset_constraint
          when dict.get(tokens, asset_name) is {
            Some(quantity) -> quantity >= min && quantity <= max
            None -> min <= 0
          }
        },
      )
    },
  )
}
