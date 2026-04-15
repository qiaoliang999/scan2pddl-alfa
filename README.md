# Scan2PDDL-ALFA

`Scan2PDDL-ALFA` is a prototype that converts network scan output into
ALFA-Chains-style PDDL problem files.

The project is motivated by the network-modeling limitation described in the
2025 preprint *Hybrid Privilege Escalation and Remote Code Execution Exploit
Chains*. In Section VII, the paper notes that exploit-chain discovery depends
heavily on complete and correct network modeling, and explicitly suggests
future integration with network scanning tools to reduce manual modeling effort.

This repository implements that missing adjacent step.

## What It Does

- parses `Nmap XML`
- parses a normalized `JSON` inventory format
- extracts hosts, products, versions, and exposed services
- emits ALFA-Chains-style PDDL predicates such as:
  - `is_compromised`
  - `connected_to_network`
  - `has_product`
  - `has_version`
  - `TCP_listen`
  - `UDP_listen`
- supports an `overlay JSON` file for segmented topologies and multi-homed hosts

## What It Does Not Do Yet

- does not generate ALFA-Chains domain files
- does not query BRON to select relevant exploits
- does not run a planner end-to-end
- does not infer trust relationships or subnet semantics reliably from scans

## Why This Exists

The ALFA-Chains paper demonstrates that exploit-chain planning can be effective
once a network is modeled in PDDL. However, the paper also states that this
network modeling is still a manual step and that errors in host descriptions
and interconnections can degrade exploit-chain discovery.

`Scan2PDDL-ALFA` is an engineering prototype for reducing that manual modeling
burden by translating scan-time host and service data into planner-ready PDDL
problem files.

## Pipeline

```text
Nmap XML / JSON Inventory
          |
          v
   Scan2PDDL-ALFA
          |
          v
ALFA-Chains-style PDDL Problem File
```

## Quickstart

Install the package in editable mode:

```bash
python -m pip install -e .
```

Generate the motivating example problem file:

```bash
scan2pddl-alfa examples/alfa_motivating_scan.xml ^
  --overlay examples/alfa_motivating_overlay.json ^
  --output output/pddl/problem.pddl
```

Or run the module directly:

```bash
python -m scan2pddl_alfa.cli examples/alfa_motivating_scan.xml ^
  --overlay examples/alfa_motivating_overlay.json ^
  --output output/pddl/problem.pddl
```

## Repository Layout

```text
src/scan2pddl_alfa/      CLI and conversion logic
examples/                motivating-example scan and overlay files
tests/                   parser and rendering checks
docs/paper_alignment.md  paper-to-implementation mapping
docs/limitations.md      explicit scope and caveats
technical_note/          1-2 page project note
output/pdf/              generated technical-note PDF
```

## Example Output

The motivating example produces a problem file with the following core shape:

```lisp
(is_compromised attacker_host agent ROOT_PRIVILEGES)
(connected_to_network attacker_host dmz)
(connected_to_network web_server dmz)
(connected_to_network web_server lan)
(has_product web_server a--drupal--drupal)
(has_version web_server a--drupal--drupal ma8 mi6 pa9)
(TCP_listen db_server a--apache--couchdb)
(:goal
  (is_compromised db_server agent ROOT_PRIVILEGES)
)
```

## Validation

- the predicate names and overall structure are aligned to the paper's PDDL
  presentation in Listing 1 and Table IV
- the motivating example can be reconstructed using a scan file plus a small
  overlay for topology details Nmap cannot infer directly
- test coverage checks both `Nmap XML` and normalized `JSON` input flows

## Documentation

- [Paper Alignment](docs/paper_alignment.md)
- [Limitations](docs/limitations.md)
- [Roadmap](docs/roadmap.md)
- [Technical Note (Markdown)](technical_note/technical_note.md)
- [Technical Note (PDF)](technical_note/scan2pddl_alfa_technical_note.pdf)
- [Motivating Example Output](examples/alfa_motivating_problem.pddl)

## Status

This is an early research-engineering prototype intended to reduce manual
network modeling for ALFA-Chains-style workflows. It should be treated as a
building block for a larger end-to-end pipeline, not as a complete exploit
chain discovery framework.
