## Container resources policy

This policy is designed to enforce constraints on the resource requirements  of
Kubernetes containers. It follows a two-step verification process: initially
checking whether the container has defined resource requirements, and
subsequently ensuring that these resources fall within the permissible range
set by the maximum resource requirements configured in the policy settings.

## Configuration

Users can configure the policy using the following parameters in YAML format:

```yaml
# optional
memory:
  defaultRequest: "100M"
  defaultLimit: "500M"
  maxLimit: "4G"
# optional
cpu:
  defaultRequest: 100m
  defaultLimit: 200m
  maxLimit: 500m
# optional
ignoreImages: ["ghcr.io/foo/bar:1.23", "myimage", "otherimages:v1"]
```

Users can skip the optional parts of the configuration, but an empty configuration is not
allowed. Thus, at least one of the configurations,  `cpu`, or `memory` should
be defined including all their sub fields.  All CPU and memory configuration
should be expressed using the [quantity
definitions](https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/)
of Kubernetes.

Any container that uses an image that matches an entry in this list will be excluded
                from enforcement. 

The `ignoreImages` configuration can be used to exclude containers from
enforcement. Any container image that matches an entry in the list will be
skipped. Prefix-matching can be signified with `*`. For example: `my-image-*`.

The policy verifies the consistency of the values provides:

- `defaultRequest` must be <= `maxLimit`
- `defaultLimit` must be <= `maxLimit`
Full example of policy definition:

```yaml
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: container-resources-policy
spec:
  policyServer: container-resources-policy
  module: registry://ghcr.io/kubewarden/policies/container-resources:latest
  rules:
  - apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
    operations:
    - CREATE
    - UPDATE
  mutating: true
  settings:
    memory:
      defaultRequest: "1G"
      defaultLimit: "1G"
      maxLimit: "4G"
    cpu:
      defaultRequest: 1
      defaultLimit: 1
      maxLimit: 2
    ignoreImages: ["myimage:latest", "registry.k8s.io/pause"]
```

## Behavior

The policy skips all the containers that are using an image that is part of the
`ignoreImages` list. These containers are always considered valid and are never
mutated.

When the CPU/Memory request is specified: no action or check is done against
it. If the requested memory is higher than the limit the Pod will not be
scheduled. This is the same approach taken by the `LimitRange` admission
controller bundled with Kubernetes.

When the CPU/Memory request is not specified: the policy mutates the container
definition, the `defaultRequest` value is used. The policy does not check the
consistency of the applied value.

When the CPU/Memory limit is specified: the request is accepted if the limit
defined by the container is less than or equal to the `maxLimit`. Otherwise the
request is rejected. In this way the end user becomes aware of the issue and
can ask the Kubernetes administrator to add the container image to the
`ignoreImages` list.

When the CPU/Memory limit is not specified: the container is mutated to use the
`defaultLimit`.
