#!/usr/bin/env bats

@test "accept containers within the expected range" {
  run kwctl run annotated-policy.wasm -r test_data/pod_within_range.json \
  	--settings-json '{"cpu": {"maxLimit": "3m", "defaultRequest" : "2m", "defaultLimit" : "2m"}, "memory" : {"maxLimit": "3G", "defaultRequest" : "2G", "defaultLimit" : "2G"}}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "do not validate user defined requests resources" {
  run kwctl run annotated-policy.wasm -r test_data/deployment_with_requests_resources_admission_request.json \
  	--settings-json '{"cpu": {"maxLimit": "3m", "defaultRequest" : "2m", "defaultLimit" : "2m"}, "memory" : {"maxLimit": "3G", "defaultRequest" : "2G", "defaultLimit" : "2G"}}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "reject containers exceeding the expected range" {
  run kwctl run annotated-policy.wasm -r test_data/pod_exceeding_range.json \
  	--settings-json '{"cpu": {"maxLimit": "1m", "defaultRequest" : "1m", "defaultLimit" : "1m"}, "memory" : {"maxLimit": "1G", "defaultRequest" : "1G", "defaultLimit" : "1G"}, "ignoreImages": ["image:latest"]}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "allow containers exceeding the expected range but with images in the ignore list" {
  run kwctl run annotated-policy.wasm -r test_data/pod_exceeding_range.json \
  	--settings-json '{"cpu": {"maxLimit": "1m", "defaultRequest" : "1m", "defaultLimit" : "1m"}, "memory" : {"maxLimit": "1G", "defaultRequest" : "1G", "defaultLimit" : "1G"}, "ignoreImages": ["image:*", "registry.k8s.io/pause*"]}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "mutate deployment with no resources" {
  run kwctl run annotated-policy.wasm -r test_data/deployment_without_resources_admission_request.json \
  	--settings-json '{"cpu": {"maxLimit": "4", "defaultRequest" : "2", "defaultLimit" : "2"}, "memory" : {"maxLimit": "4G", "defaultRequest" : "2G", "defaultLimit" : "2G"}}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -ne 0 ]
}

@test "mutate deployment with limits but no request resources" {
  run kwctl run annotated-policy.wasm -r test_data/deployment_with_limits_admission_request.json \
  	--settings-json '{"cpu": {"maxLimit": "4", "defaultRequest" : "2", "defaultLimit" : "2"}, "memory" : {"maxLimit": "4G", "defaultRequest" : "2G", "defaultLimit" : "2G"}}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -ne 0 ]
}

