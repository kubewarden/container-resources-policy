#!/usr/bin/env bats

@test "fail with empty settings" {
  run kwctl run annotated-policy.wasm -r test_data/pod_within_range.json --settings-json '{}'

  [ "$status" -ne 0 ]
  [ $(expr "$output" : '.*no settings provided. At least one resource limit or request must be verified.*') -ne 0 ]
}

@test "accept containers within the expected range" {
  run kwctl run annotated-policy.wasm -r test_data/pod_within_range.json \
  	--settings-json '{"cpu": {"maxLimit": "3m", "defaultRequest" : "2m", "defaultLimit" : "2m"}, "memory" : {"maxLimit": "3G", "defaultRequest" : "2G", "defaultLimit" : "2G"}}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "do not validate user defined requests resources" {
  run kwctl run annotated-policy.wasm -r test_data/deployment_with_requests_resources_admission_request.json \
  	--settings-json '{"cpu": {"maxLimit": "3m", "defaultRequest" : "2m", "defaultLimit" : "2m"}, "memory" : {"maxLimit": "3G", "defaultRequest" : "2G", "defaultLimit" : "2G"}}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "reject containers exceeding the expected range" {
  run kwctl run annotated-policy.wasm -r test_data/pod_exceeding_range.json \
  	--settings-json '{"cpu": {"maxLimit": "1m", "defaultRequest" : "1m", "defaultLimit" : "1m"}, "memory" : {"maxLimit": "1G", "defaultRequest" : "1G", "defaultLimit" : "1G"}, "ignoreImages": ["image:latest"]}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":false') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "allow containers exceeding the expected range but with images in the ignore list" {
  run kwctl run annotated-policy.wasm -r test_data/pod_exceeding_range.json \
  	--settings-json '{"cpu": {"maxLimit": "1m", "defaultRequest" : "1m", "defaultLimit" : "1m"}, "memory" : {"maxLimit": "1G", "defaultRequest" : "1G", "defaultLimit" : "1G"}, "ignoreImages": ["image:*", "registry.k8s.io/pause*"]}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "mutate deployment with no resources" {
  run kwctl run annotated-policy.wasm -r test_data/deployment_without_resources_admission_request.json \
  	--settings-json '{"cpu": {"maxLimit": "4", "defaultRequest" : "2", "defaultLimit" : "2"}, "memory" : {"maxLimit": "4G", "defaultRequest" : "2G", "defaultLimit" : "2G"}}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -ne 0 ]
}

@test "reject deployment with no resources when ignoreValues is true" {
  run kwctl run annotated-policy.wasm -r test_data/deployment_without_resources_admission_request.json \
    	--settings-json '{"cpu": {"ignoreValues": true}, "memory" : {"ignoreValues": true}}'

    [ "$status" -eq 0 ]
    [ $(expr "$output" : '.*allowed":false') -ne 0 ]
    [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "mutate deployment with limits but no request resources" {
  run kwctl run annotated-policy.wasm -r test_data/deployment_with_limits_admission_request.json \
  	--settings-json '{"cpu": {"maxLimit": "4", "defaultRequest" : "1", "defaultLimit" : "1"}, "memory" : {"maxLimit": "4G", "defaultRequest" : "1G", "defaultLimit" : "1G"}}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -ne 0 ]
}
@test "reject containers with no resources when ignoreValues is true" {
  run kwctl run annotated-policy.wasm -r test_data/pod_without_resources.json \
  	--settings-json '{"cpu": {"ignoreValues": true}, "memory" : {"ignoreValues": true}}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":false') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}
@test "allow containers while ignoring resources" {
  run kwctl run annotated-policy.wasm -r test_data/pod_within_range.json \
  	--settings-json '{"cpu": {"ignoreValues": true}, "memory" : {"ignoreValues": true}}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "allow containers while ignoring cpu resources with missing memory settings" {
  run kwctl run annotated-policy.wasm -r test_data/pod_within_range.json \
  	--settings-json '{"cpu": {"ignoreValues": true}}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "allow containers while ignoring memory resources with missing cpu settings" {
  run kwctl run annotated-policy.wasm -r test_data/pod_within_range.json \
  	--settings-json '{"memory": {"ignoreValues": true}}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "allow containers exceeding the expected range when ignoreValues is true" {
  run kwctl run annotated-policy.wasm -r test_data/pod_exceeding_range.json \
  	--settings-json '{"cpu": {"maxLimit": "1m", "defaultRequest" : "1m", "defaultLimit" : "1m", "ignoreValues":true}, "memory" : {"maxLimit": "1G", "defaultRequest" : "1G", "defaultLimit" : "1G", "ignoreValues":true}, "ignoreImages": ["image:latest"]}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "reject containers exceeding the expected range ignoring memory values" {
  run kwctl run annotated-policy.wasm -r test_data/pod_exceeding_range.json \
  	--settings-json '{"cpu": {"maxLimit": "1m", "defaultRequest" : "1m", "defaultLimit" : "1m"}, "memory" : {"maxLimit": "1G", "defaultRequest" : "1G", "defaultLimit" : "1G", "ignoreValues": true}, "ignoreImages": ["image:latest"]}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":false') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "reject containers exceeding the expected CPU range ignoring memory values due missing values" {
  run kwctl run annotated-policy.wasm -r test_data/pod_exceeding_range.json \
  	--settings-json '{"cpu": {"maxLimit": "1m", "defaultRequest" : "1m", "defaultLimit" : "1m"}, "memory" : {"ignoreValues": false}, "ignoreImages": ["image:latest"]}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":false') -ne 0 ]
  [ $(expr "$output" : '.*cpu limit.*exceeds the max allowed value.*') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "allow containers exceeding the expected CPU range when the resource should be ignore due missing values" {
  run kwctl run annotated-policy.wasm -r test_data/pod_exceeding_cpu_range.json \
  	--settings-json '{"cpu": {"ignoreValues":false}, "memory" : {"maxLimit": "1Gi", "defaultRequest" : "1Gi", "defaultLimit" : "1Gi", "ignoreValues":false}, "ignoreImages": ["image:latest"]}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "allow containers exceeding the expected memory range when the resource should be ignore due missing values" {
  run kwctl run annotated-policy.wasm -r test_data/pod_exceeding_memory_range.json \
  	--settings-json '{"cpu": {"maxLimit": "1m", "defaultRequest" : "1m", "defaultLimit" : "1m", "ignoreVaues": false}, "memory" : {"ignoreValues":false}, "ignoreImages": ["image:latest"]}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":true') -ne 0 ]
  [ $(expr "$output" : '.*patch.*') -eq 0 ]
}

@test "invalid settings when both resources have empty values" {
  run kwctl run annotated-policy.wasm -r test_data/pod_within_range.json \
  	--settings-json '{"cpu": {"ignoreVaues": false}, "memory" : {"ignoreValues":false}, "ignoreImages": ["image:latest"]}'

  [ "$status" -ne 0 ]
  [ $(expr "$output" : '.*invalid cpu settings.*') -ne 0 ]
  [ $(expr "$output" : '.*invalid memory settings.*') -ne 0 ]
}

@test "policy fails when the request resource is greater than the limit set by the policy" {
  run kwctl run annotated-policy.wasm -r test_data/deployment_with_requests_no_limit_resources_admission_request.json \
  	--settings-json '{"cpu": {"maxLimit": 2, "defaultRequest": 1, "defaultLimit": 1, "ignoreValues":false}, "memory" : {"maxLimit": "1Gi", "defaultRequest" : "200Mi", "defaultLimit" : "200Mi", "ignoreValues":false}, "ignoreImages": ["image:latest"]}'

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed":false') -ne 0 ]
  [ $(expr "$output" : ".*memory limit '200Mi' is less than the requested '250Mi' value.*") -ne 0 ]
}
