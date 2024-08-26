#!/usr/bin/env bats

@test "accept when no settings are provided" {
  run kwctl run annotated-policy.wasm -r test_data/ingress.json

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "accept user defined constraint is respected" {
  run kwctl run annotated-policy.wasm \
    -r test_data/ingress.json \
    --settings-json '{"constrained_labels": {"owner": "^team-"}}'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "accept labels are not on deny list" {
  run kwctl run  annotated-policy.wasm \
    -r test_data/ingress.json \
    --settings-json '{"denied_labels": ["foo", "bar"]}'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "reject because label is on deny list" {
  run kwctl run annotated-policy.wasm \
    -r test_data/ingress.json --settings-json '{"denied_labels": ["foo", "owner"]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*The following labels are denied: owner".*') -ne 0 ]
}

@test "reject because label doesn't pass validation constraint" {
  run kwctl run annotated-policy.wasm \
    -r test_data/ingress.json \
    --settings-json '{"constrained_labels": {"cc-center": "^cc-\\d+$"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*The following labels are violating user constraints: cc-center.*") -ne 0 ]
}

@test "reject because a required label does not exist" {
  run kwctl run annotated-policy.wasm \
    -r test_data/ingress.json --settings-json '{"mandatory_labels": ["required"], "constrained_labels": {"foo": ".*"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*The following mandatory labels are missing: required.*') -ne 0 ]
}

@test "fail settings validation because constrained labels are also denied" {
  run kwctl run annotated-policy.wasm \
    -r test_data/ingress.json \
    --settings-json '{"denied_labels": ["foo", "cc-center"], "constrained_labels": {"cc-center": "^cc-\\d+$"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation fails
  [ "$status" -eq 1 ]
  [ $(expr "$output" : ".*Provided settings are not valid: These labels cannot be constrained and denied at the same time: cc-center.*") -ne 0 ]
}

@test "fail settings validation because mandatory labels are also denied" {
  run kwctl run annotated-policy.wasm \
    -r test_data/ingress.json \
    --settings-json '{"denied_labels": ["foo", "cc-center"], "mandatory_labels": ["cc-center"]}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation fails
  [ "$status" -eq 1 ]
  [ $(expr "$output" : ".*Provided settings are not valid: These labels cannot be mandatory and denied at the same time: cc-center.*") -ne 0 ]
}

@test "fail settings validation because of invalid constraint" {
  run kwctl run annotated-policy.wasm \
    -r test_data/ingress.json \
    --settings-json '{"constrained_labels": {"cc-center": "^cc-[12$"}}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # settings validation fails
  [ "$status" -eq 1 ]
  [ $(expr "$output" : ".*Provided settings are not valid: error parsing regexp: missing closing ]: `[12$`.*") -ne 0 ]
}
