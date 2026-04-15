# Paper Alignment

This page maps the implementation in this repository to the modeling gap
described in the 2025 ALFA-Chains preprint.

| Paper Requirement | This Prototype | Current Gap |
| --- | --- | --- |
| Manual PDDL problem-file modeling is a bottleneck | Automates problem-file generation from scan results | Still requires overlay data for segmented topology |
| `connected_to_network` predicate | Supported | Network semantics inferred from IP ranges are approximate |
| `has_product` predicate | Supported from CPEs or service fingerprints | Quality depends on scanner output fidelity |
| `has_version` predicate with major/minor/patch tokens | Supported | Non-semver products may lose detail |
| `TCP_listen` / `UDP_listen` predicates | Supported | Ports are abstracted away, matching the paper's service-level model |
| Initial foothold as `is_compromised attacker_host ... ROOT_PRIVILEGES` | Supported | Assumes attacker entry network is given explicitly |
| Goal state modeled as `is_compromised target_host ... ROOT_PRIVILEGES` | Supported | Goal host must be specified via CLI or overlay |
| Domain-file generation from exploit metadata | Not implemented | Future integration point for BRON / exploit selection |
| End-to-end planning with ALFA-Chains planners | Not implemented | Requires compatible domain file and planner setup |

## Interpretation

The paper's future-work section suggests integrating network scanning tools to
extract host and service information and assist with producing problem files.
This repository focuses on exactly that boundary: it translates observed
network-state evidence into the PDDL problem-file predicates that the planner
expects.

The prototype does not claim full ALFA-Chains compatibility because the public
paper describes the PDDL representation but does not provide the complete
implementation used in the experiments.

## Concrete Alignment To The Public PDDL Representation

The repository includes a generated motivating-example problem file at
[`examples/alfa_motivating_problem.pddl`](../examples/alfa_motivating_problem.pddl).
The following elements are intentionally aligned to the public paper:

| Public Paper Element | Generated Example |
| --- | --- |
| Listing 1 initial foothold | `(is_compromised attacker_host agent ROOT_PRIVILEGES)` |
| Listing 1 topology predicate | `(connected_to_network web_server dmz)` |
| Listing 1 product predicate | `(has_product web_server a--drupal--drupal)` |
| Listing 1 version tokenization | `(has_version web_server a--drupal--drupal ma8 mi6 pa9)` |
| Listing 1 exposed service predicate | `(TCP_listen db_server a--apache--couchdb)` |
| Listing 1 goal clause | `(:goal (is_compromised db_server agent ROOT_PRIVILEGES))` |
| Table III object categories | generated `Host`, `Agent`, `Network`, `Privilege`, `Product`, `Major`, `Minor`, `Patch` objects |
| Table IV configuration predicates | generated `has_product`, `has_version`, `TCP_listen`, and `UDP_listen` predicates |

This is a claim about alignment to the public representation in the paper, not
about verified drop-in compatibility with the original research codebase.
