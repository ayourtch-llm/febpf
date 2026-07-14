# Verified map-effect summaries

`effects::summarize` converts a successful verifier result into conservative,
instruction-level effects on map state. It uses verifier register provenance,
not source declarations.

The initial effect kinds are lookup, direct read, ordinary write, atomic
read-modify-write, delete, lock, and unlock. Direct map-value accesses include
the inclusive byte range proven by the verifier. Helper effects identify the
logical map but leave the byte range unknown because keys and helper semantics
operate on logical entries.

The summary has a `complete` flag. Verifier joins deliberately erase pointer
identity when different pointer kinds or map identities meet at one program
counter. If that prevents exact attribution, `complete` is false. A consumer
must reject that summary or conservatively assume it affects every shared map;
it must never interpret a missing exact effect as race freedom.

This is evidence for a higher-level concurrency policy, not such a policy
itself. In particular:

- an atomic operation protects only that cell operation;
- key partitions are not yet proven;
- lock/unlock effects are reported but critical sections are not paired;
- user-registered helpers have no declared map effects yet;
- race freedom does not prove invariants spanning several cells.

febpf owns instruction, helper, and verifier-proven provenance facts. Embedders
such as febpf-graph own scheduling, region capabilities, and the decision about
which programs may execute concurrently.
