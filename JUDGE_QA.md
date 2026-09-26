# Fast judge Q&A

**What problem are you solving?**  
Finding old cryptography is not enough. Migration can break dependent clients or silently fall back to classical crypto. CipherAtlas checks whether the target migration actually works.

**What is PQC?**  
Post-Quantum Cryptography: cryptographic algorithms designed to resist attacks from future sufficiently capable quantum computers.

**What is TLS?**  
Transport Layer Security, the protocol that secures connections such as HTTPS.

**What is X25519?**  
A classical key-agreement mechanism used to help two systems establish a shared secret.

**What is ML-KEM?**  
Module-Lattice-Based Key Encapsulation Mechanism, a post-quantum method for establishing a shared secret.

**What is X25519MLKEM768?**  
A hybrid TLS key-establishment mechanism combining classical X25519 with ML-KEM-768.

**Why not just scan and replace algorithms?**  
Replacement depends on cryptographic purpose and on consumers' compatibility. A server can support the new mechanism while an old client does not.

**What is your strongest measured result?**  
The Phase 0 TLS matrix reproduced silent classical fallback: legacy clients could connect when fallback was enabled but negotiated X25519 rather than the PQ target.

**Why no machine-learning model?**  
The core decisions are deterministic security logic: parsing, standards-aware rules, constraint reasoning and measured interoperability. ML would add training bias and opacity without evidence that it improves this task.

**How do you prevent fake confidence?**  
Missing evidence stays `READY_FOR_PROBE` or `INCONCLUSIVE`. A successful probe is scoped to its version/configuration/environment.

**Do you execute uploaded repositories?**  
No. Uploaded content is statically parsed only. Dynamic tests use CipherAtlas' own controlled probe harness.

**What failed in your research?**  
The sophisticated test-ordering selector did not beat the simple strategy enough to justify itself, so it was removed from the product pitch.

**What is still a limitation?**  
The MVP supports narrow source/config/certificate coverage, demo dependency contracts, limited stack profiles, and controlled TLS experiments rather than full enterprise infrastructure.
