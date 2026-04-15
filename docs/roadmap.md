# Roadmap

## Near-Term

1. Add richer JSON schema documentation and more sample inventories.
2. Add support for additional scanner formats beyond Nmap XML.
3. Improve CPE and product-name normalization.
4. Add planner-facing smoke tests for generated problem files.

## Research Extensions

1. Query BRON or a similar vulnerability knowledge layer to match products and
   versions against relevant exploits.
2. Generate a constrained PDDL domain file from selected exploit metadata.
3. Add topology enrichment from asset inventories, CMDB exports, or NetBox.
4. Support trust channels and service reachability relationships beyond subnet
   membership.
5. Produce a complete planner-ready benchmark from scan + overlay + exploit
   metadata.
