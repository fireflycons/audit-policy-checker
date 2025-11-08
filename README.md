# Audit Policy Checker for Kubernetes

Sick of crashing your API Server with malformed audit policy files? This tool's for you!

Use it to pre-validate policy files before uploading them to the API Server, either manually or as part of a CI pipeline.

## Requirements

Access to a cluster, ideally the cluster to which the policy will be applied since that will also allow rules for custom resources to be checked.

It looks for cluster credentials in the following order
1. If path to a kubeconfig is provided with `-k` then it loads that.
1. Check if running in a pod, then use pod's service account credential.
1. Look for default kubeconfig.

## What is checked

### File level

* The policy file can be loaded and is syntactically correct for `audit.k8s.io/v1`. This will catch basic YAML errors and should ensure that API server won't crashloop when reading your policy.
* The policy contains at least one rule.
* Any top level `omitStages` has valid stage names.

### For each rule

* `level` is an allowed value.
* `omitStages` if present has valid stage names.
* `verbs` if present has valid verb names.

### For each group/resource within a rule

* `group` if present is known to the cluster. I you omit `group`, this is still valid, but defaults to `""`, i.e. `v1`
* `resources` if present then all listed resources are checked for being known to the cluster. If not present, the default is all resources within the group.
* `namespaces` - If a namespace doesn't exist then a warning will be issued.

## What it does not check

* If a YAML key is missplelled. API server simply ignores keys it doesn't recognize, and since this tool uses the same code as API server for loading policy, then the behavior is the same. You will end up with a rule that does not do what you expect.
* If you specify the same key twice in a YAML object. This is down to the behavior of the Go YAML parser, which will accept the last occurrence of that key in the input, e.g.
    ```yaml
    rules:
    - level: RequestResponse
        resources:
        - group: ""
          resources: ["pods"]    # This will be ignored and not part of the rule
          resources: ["configmaps"]
    ```
* `users`, `userGroups`, `nonResourceURLs`.

## Installation

1. Download the tarball/zip appropriate for the system you intend to run the tool on.
1. Extract the archive which contains a standalone executable file and optionally place in a directory in the path.

### Note for KodeKloud CKS students

* You *can* use this in KodeKloud labs/mocks/playgrounds.
* You *cannot* use it in the real CKS exam, so get to know the kinds of mistakes you commonly make and practice getting it right without this tool!

## Usage

```bash
audit-policy-check my-policy.yaml
```
or
```
audit-policy-check -k path/to/my-kubeconfig.config my-policy.yaml
```

