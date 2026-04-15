# Limitations

`Scan2PDDL-ALFA` is intentionally narrow in scope. The current implementation
automates one important step in the ALFA-Chains workflow, but it does not
replace the rest of the pipeline.

## Current Limitations

- Only the `problem file` is generated automatically.
- The `domain file` is not generated.
- No planner is bundled or executed.
- No exploit relevance filtering is performed against BRON or any other source.
- Segmented topology still needs light operator input when scan data alone is
  insufficient.
- Host trust channels and policy relationships are not inferred.
- Service naming depends on the quality of scan fingerprints and CPE hints.
- Version parsing is best-effort and optimized for semantic version patterns.

## Why The Overlay Exists

Nmap can reveal a host, its services, and often a useful software fingerprint.
It usually cannot reliably reconstruct:

- business semantics for subnets such as `dmz` or `lan`
- whether a host should belong to more than one logical network
- the attacker's intended entry network
- the analyst's chosen target host

The overlay file exists to keep the automated portion honest. It allows a small
amount of analyst-provided topology knowledge to be combined with scan-time
facts instead of pretending the scanner can derive everything alone.

## Compatibility Claim

This repository aims for *paper-level structural alignment* with the public
ALFA-Chains PDDL representation. It does not claim verified drop-in
compatibility with the authors' internal implementation.
