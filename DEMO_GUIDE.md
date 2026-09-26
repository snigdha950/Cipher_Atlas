# Judge demo guide

## 20-second problem explanation

Organizations cannot migrate to post-quantum cryptography by replacing algorithm names. Clients, servers and libraries depend on each other's cryptographic capabilities. A connection can even succeed while silently falling back to classical cryptography. CipherAtlas discovers those dependencies, tests uncertain compatibility, and changes the migration decision using evidence.

## 90-second flow

1. **Overview**: point to `Discover → Understand → Probe → Decide`.
2. **Inventory**: show OpenSSL version, TLS configuration, certificate evidence, and scan coverage.
3. **Judge mode → Silent fallback**: run it. Explain that connection success is not enough because the observed group is X25519 instead of X25519MLKEM768.
4. **Judge mode → Modern pass**: run it. Show that the state changes because the observed evidence changed.
5. Open **raw evidence** and **download JSON**.
6. If asked whether it is scripted, choose **This laptop · live OpenSSL probe**. If the machine supports the target, the test runs on loopback using a temporary certificate.

## If a judge changes the scenario

- **Hybrid required + old client** → expect handshake failure / `BLOCKED`.
- **Hybrid + fallback + old client** → connection may succeed on X25519, still `BLOCKED` for the PQ target.
- **Hybrid required + modern client** → expected measured `X25519MLKEM768`, `VALIDATED_IN_TEST_ENV`.
- **No evidence for a stack** → `INCONCLUSIVE`; CipherAtlas does not guess.

## What never to claim

Do not say “the enterprise is quantum-safe”, “verified”, “production-ready”, or “100% secure”. Say: “This exact migration condition passed the named probe on the recorded version/configuration/environment.”
