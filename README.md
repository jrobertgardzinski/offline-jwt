# offline-jwt

Offline verification of microservice-security's access tokens, as a library: the token's own
EdDSA signature is verified against the JWKS security serves at `/.well-known/jwks.json`, and the
caller (subject, roles, MFA floor) is read from the claims — no per-request introspection
round-trip. The trade-off is revocation blindness until the token's `exp`; the payoff is that a
security outage or hot path does not cost a network hop per request.

```java
OfflineJwtVerifier verifier = OfflineJwtVerifier.overHttp(securityUrl, objectMapper);
Optional<VerifiedToken> caller = verifier.verify(bearerToken);  // empty = fail closed
```

This code used to live as five byte-identical copies (memes, comments, paddock,
user-collections, formula) with a "change one, change both" comment. Duplication normally beats
coupling between services — but drifting copies of security-critical verification are the
exception, so the copies converged here. Services keep their own gate interfaces and policies
(e.g. withholding privileged roles when `mfaCompliant` is false); only the verification core is
shared.

Part of the [security workspace](https://github.com/jrobertgardzinski); consumed as
`com.jrobertgardzinski:offline-jwt:1.0.0-SNAPSHOT` by the sibling services.
