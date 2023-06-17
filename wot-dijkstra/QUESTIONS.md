# Questions

## Graph of Certificates or Graph of Subkeys?

## Persistable Graph or Dynamic Recalculation?

https://de.wikipedia.org/wiki/Dijkstra-Algorithmus
Dijkstra: Outgoing edges "live" in origin, WoT: Incoming edges "live" in target

When processing incoming edges on certificate (node): origin of incoming nodes (signing key) might not be known -> cannot verify.

multi-step process:
Firstly create intermediate graph with unverified edges, invert edge such that origin owns edges to targets
Secondly for edges where origin and target exist, verify signatures

What information from signatures to cache? Creation date, expiration? Regex, depth, amount!

What are then nodes? Certs? Bindings?

