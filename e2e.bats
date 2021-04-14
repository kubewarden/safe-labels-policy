#!/usr/bin/env bats

@test "accept when no settings are provided" {
  run policy-testdrive -p policy.wasm -r test_data/ingress.json

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation passed
  [[ "$output" == *"valid: true"* ]]

  # request rejected
  [[ "$output" == *"allowed: true"* ]]
}

@test "accept user defined constraint is respected" {
  run policy-testdrive -p policy.wasm \
    -r test_data/ingress.json \
    -s '{"constrained_labels": {"owner": "^team-"}}'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation passed
  [[ "$output" == *"valid: true"* ]]

  # request accepted
  [[ "$output" == *"allowed: true"* ]]
}

@test "accept labels are not on deny list" {
  run policy-testdrive -p policy.wasm \
    -r test_data/ingress.json \
    -s '{"denied_labels": ["foo", "bar"]}'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation passed
  [[ "$output" == *"valid: true"* ]]

  # request accepted
  [[ "$output" == *"allowed: true"* ]]
}

@test "reject because label is on deny list" {
  run policy-testdrive -p policy.wasm \
    -r test_data/ingress.json -s '{"denied_labels": ["foo", "owner"]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation passed
  [[ "$output" == *"valid: true"* ]]

  # request rejected
  [[ "$output" == *"allowed: false"* ]]
  [[ "$output" == *"Label owner is on the deny list"* ]]
}

@test "reject because label doesn't pass validation constraint" {
  run policy-testdrive -p policy.wasm \
    -r test_data/ingress.json \
    -s '{"constrained_labels": {"cc-center": "^cc-\\d+$"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation passed
  [[ "$output" == *"valid: true"* ]]

  # request rejected
  [[ "$output" == *"allowed: false"* ]]
  [[ "$output" == *"The value of cc-center doesn\'t pass user-defined constraint"* ]]
}

@test "fail settings validation because of conflicting labels" {
  run policy-testdrive -p policy.wasm \
    -r test_data/ingress.json \
    -s '{"denied_labels": ["foo", "cc-center"], "constrained_labels": {"cc-center": "^cc-\\d+$"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation passed
  [[ "$output" == *"valid: false"* ]]
  [[ "$output" == *"Provided settings are not valid: These labels cannot be constrained and denied at the same time: Set{cc-center}"* ]]
}

@test "fail settings validation because of invalid constraint" {
  run policy-testdrive -p policy.wasm \
    -r test_data/ingress.json \
    -s '{"constrained_labels": {"cc-center": "^cc-[12$"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation passed
  [[ "$output" == *"valid: false"* ]]
  [[ "$output" == *"Provided settings are not valid: error parsing regexp: missing closing ]: `[12$`"* ]]
}
