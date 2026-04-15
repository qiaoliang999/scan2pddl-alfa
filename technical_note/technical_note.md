# Scan2PDDL-ALFA: Reducing Manual Network Modeling for ALFA-Chains

## Problem

The 2025 ALFA-Chains preprint, *Hybrid Privilege Escalation and Remote Code
Execution Exploit Chains*, identifies network modeling as a critical bottleneck
in exploit-chain discovery. The planner depends on a PDDL problem file that
describes hosts, products, versions, service exposure, and network topology.
In the paper, that information is modeled manually. The authors explicitly note
that incomplete or ambiguous network descriptions can hinder exploit-chain
discovery and suggest future integration with network scanning tools to assist
in producing problem files.

This repository explores one adjacent automation step in that future-work
direction.

## Contribution

`Scan2PDDL-ALFA` is a prototype that converts network scan results into
ALFA-Chains-style PDDL problem files. The tool currently supports:

- `Nmap XML` as the primary scan input
- a normalized `JSON` inventory format for structured environments
- an optional `overlay JSON` file for analyst-supplied topology semantics such
  as `dmz`, `lan`, attacker entry network, and multi-homed hosts

The generated output is intended to align with the public PDDL representation
shown in the paper, including predicates such as `connected_to_network`,
`has_product`, `has_version`, `TCP_listen`, `UDP_listen`, and
`is_compromised`.

## Design

The prototype separates observed scan facts from analyst intent:

1. Parse scan-time facts:
   - host addresses and names
   - service fingerprints and CPEs
   - operating system hints
2. Normalize products and versions into ALFA-style product tokens and
   `major/minor/patch` objects
3. Merge a lightweight overlay when the scanner cannot infer logical topology
4. Emit a PDDL problem file with initial state, host configuration predicates,
   service exposure predicates, and a target goal state

This design keeps the automation honest. It extracts what the scanner can
observe directly and uses a small explicit overlay for the topology semantics
that are not reliably inferable from scan output alone.

## Validation

The repository includes a motivating-example scan and overlay pair that
reconstruct the paper's DMZ-LAN example at the problem-file level. The emitted
PDDL is checked for paper-level structural alignment and contains the expected
public-facing elements for:

- an external attacker connected to the `dmz`
- a `web_server` attached to both `dmz` and `lan`
- a `db_server` attached to the `lan`
- vulnerable software stacks such as Drupal 8.6.9 and Apache CouchDB 2.0.0
- a goal state targeting `ROOT_PRIVILEGES` on the database host

Automated tests cover both `Nmap XML` and normalized `JSON` inputs. This is
evidence of structural consistency, not evidence of verified compatibility with
the authors' internal ALFA-Chains implementation.

## Limitations

The prototype intentionally automates only the PDDL problem-file step. It does
not yet:

- generate a compatible ALFA-Chains domain file
- select relevant exploits from BRON
- run a planner end-to-end
- infer trust channels or reachability policies beyond network membership

For that reason, this repository should be understood as a research-engineering
building block rather than a complete exploit-chain discovery system.

## Why The Overlay Matters

The overlay mechanism is a deliberate design choice rather than a workaround.
Scanners can usually observe host addresses, product hints, and exposed
services, but they generally cannot recover analyst-defined topology semantics
such as `dmz`, `lan`, or the intended attacker entry point. By separating
observed scan facts from analyst-provided topology semantics, the tool avoids
over-claiming what can be inferred directly from the scan.

## Next Step

The natural extension is to connect the generated product-version tuples to a
knowledge source such as BRON, filter relevant exploits, and automatically
assemble a constrained domain file. That would move the workflow from
scan-assisted modeling toward a more complete end-to-end ALFA-Chains pipeline.

More concretely, the next research milestones are:

- query BRON using normalized product-version tuples
- select only exploits relevant to the observed hosts
- generate a constrained PDDL domain file
- test planner compatibility on motivating and larger benchmark networks
