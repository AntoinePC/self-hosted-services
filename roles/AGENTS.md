# Ansible Roles Agent Guide

This guide applies to the `roles` subtree. Follow the repository-wide
[`AGENTS.md`](../AGENTS.md) as well.

## Role Design

- You SHOULD prefer roles over direct tasks in playbooks.
- You MUST gate optional behavior with `when` clauses for `skip_*` variables.

## Global Variables

- When you add a global Ansible variable, you MUST add it to the inventory
  example in [`../README.md`](../README.md) and to the `vars` section under
  `provisioner.inventory.hosts.all` in every applicable Molecule file.

## Validation

- Before running Ansible playbooks or Molecule tests, you MUST install
  dependencies from the repository root with
  `ansible-galaxy install -r requirements.yml`.
- You MUST validate roles with `molecule test` in a sandbox.
- You SHOULD refer to
  [`../.woodpecker/test.yaml`](../.woodpecker/test.yaml) for dependencies and
  the canonical command flow.
- The root guide's permission requirement for `ansible-playbook` continues to
  apply.

## Router Safety

- Keep fw4 validation ahead of firewall, network, and SQM handlers: network
  and SQM reloads can trigger firewall work indirectly.
- Preserve the Qualcomm NSS flow-offloading guard and the persistent firewall
  recovery in `router_setup` when updating router roles. Test failure paths with
  `tests/test_router_safety.py`; lint alone cannot verify handler ordering.
- When upstream renames facts or moves templates between roles, audit existing
  router safeguards for stale names and paths, even when Git merges cleanly.
