package com.jrobertgardzinski.offlinejwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Offline verification of microservice-security's access tokens: instead of introspecting every
 * bearer token against security's {@code GET /me}, the token's own EdDSA signature is verified
 * against the public keys security serves at {@code /.well-known/jwks.json} and the caller is
 * read from the claims. One JWKS fetch amortises over every request — the deliberate trade-off is
 * revocation blindness: a logout or role change is invisible until the token's {@code exp}. Keys
 * are cached with a max-age (default 15 minutes): an unknown {@code kid} triggers one refetch
 * (which also covers security restarting with fresh ephemeral keys), and a stale cache refetches
 * too — so REMOVING a compromised key from the JWKS reaches every consumer within minutes, not
 * at its next restart (the emergency kill-switch must propagate). A failed refetch keeps serving
 * the last good keys rather than dropping every caller: an unreachable JWKS is an availability
 * incident, not a revocation. Every per-token failure — malformed token, wrong algorithm, forged
 * signature, foreign issuer, expiry — verifies to empty: the caller fails closed.
 */
public final class OfflineJwtVerifier {

    private static final String EXPECTED_ISSUER = "microservice-security";
    private static final byte[] ED25519_DER_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    private final Supplier<Map<String, PublicKey>> jwksFetcher;
    private final ObjectMapper mapper;
    private final Duration keysMaxAge;
    private final Supplier<Instant> clock;
    private final AtomicReference<Map<String, PublicKey>> cachedKeys = new AtomicReference<>(Map.of());
    private volatile Instant fetchedAt = Instant.EPOCH;

    /**
     * How long an unknown kid must wait before it may provoke another JWKS fetch.
     *
     * <p>Short enough that a genuine key rotation still propagates in seconds, long enough that a
     * stream of forged kids cannot turn this gate into a traffic amplifier pointed at the identity
     * service. Separate from {@link #keysMaxAge}, which governs how long GOOD keys stay trusted.
     */
    private static final Duration REFETCH_FLOOR = Duration.ofSeconds(10);

    private final Duration refetchFloor = REFETCH_FLOOR;
    private volatile Instant lastFetchAttempt = Instant.EPOCH;

    /** Full control of the key source — the constructor tests (and unusual transports) use. */
    public OfflineJwtVerifier(Supplier<Map<String, PublicKey>> jwksFetcher, ObjectMapper mapper) {
        this(jwksFetcher, mapper, Duration.ofMinutes(15), Instant::now);
    }

    /** Plus control of time and the cache max-age — what the revocation-propagation tests use. */
    public OfflineJwtVerifier(Supplier<Map<String, PublicKey>> jwksFetcher, ObjectMapper mapper,
                              Duration keysMaxAge, Supplier<Instant> clock) {
        this.jwksFetcher = jwksFetcher;
        this.mapper = mapper;
        this.keysMaxAge = keysMaxAge;
        this.clock = clock;
    }

    /** The common case: fetch the JWKS from security over plain HTTP (JDK client, short timeouts). */
    public static OfflineJwtVerifier overHttp(String securityUrl, ObjectMapper mapper) {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
        return new OfflineJwtVerifier(() -> {
            try {
                HttpResponse<String> response = client.send(
                        HttpRequest.newBuilder(URI.create(securityUrl + "/.well-known/jwks.json"))
                                .timeout(Duration.ofSeconds(5)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                JsonNode set = mapper.readTree(response.body());
                Map<String, PublicKey> byKid = new HashMap<>();
                for (JsonNode jwk : set.path("keys")) {
                    if ("OKP".equals(jwk.path("kty").asText()) && "Ed25519".equals(jwk.path("crv").asText())) {
                        byKid.put(jwk.path("kid").asText(), publicKeyFrom(jwk.path("x").asText()));
                    }
                }
                return Map.copyOf(byKid);
            } catch (Exception jwksUnavailable) {
                return Map.of();   // no keys, no callers — fails closed
            }
        }, mapper);
    }

    /** The verified caller, or empty — every failure mode fails closed. */
    public Optional<VerifiedToken> verify(String accessToken) {
        try {
            String[] parts = accessToken.split("\\.");
            if (parts.length != 3) {
                return Optional.empty();
            }
            JsonNode header = json(parts[0]);
            if (!"EdDSA".equals(header.path("alg").asText())) {
                return Optional.empty();
            }
            PublicKey key = keyFor(header.path("kid").asText());
            if (key == null || !signatureVerifies(key, parts)) {
                return Optional.empty();
            }
            JsonNode claims = json(parts[1]);
            if (!EXPECTED_ISSUER.equals(claims.path("iss").asText())
                    // the INJECTED clock, not Instant.now(): security mints exp from an injected
                    // java.time.Clock and its tests steer it, so a gate judging expiry by wall time
                    // disagreed with the mint in any environment with a shifted clock — and made
                    // expiry impossible to test offline by moving time, which is the whole point of
                    // having the clock here (it used to govern only the JWKS cache)
                    || claims.path("exp").asLong() <= clock.get().getEpochSecond()) {
                return Optional.empty();
            }
            String subject = claims.path("sub").asText();
            if (subject.isBlank()) {
                return Optional.empty();
            }
            Set<String> roles = claims.path("roles").isArray()
                    ? StreamSupport.stream(claims.path("roles").spliterator(), false)
                            .map(JsonNode::asText).collect(Collectors.toUnmodifiableSet())
                    : Set.of("USER");
            // absent on an older token counts as false — nothing is withheld from ordinary users,
            // only from privileged ones (fail-closed)
            boolean mfaCompliant = claims.path("mfaCompliant").asBoolean(false);
            return Optional.of(new VerifiedToken(subject, roles, mfaCompliant));
        } catch (Exception invalidTokenOrJwksDown) {
            return Optional.empty();
        }
    }

    private PublicKey keyFor(String kid) {
        Map<String, PublicKey> known = cachedKeys.get();
        boolean stale = clock.get().isAfter(fetchedAt.plus(keysMaxAge));
        if (!stale && known.containsKey(kid)) {
            return known.get(kid);
        }
        // A FLOOR on how often an unknown kid may provoke a fetch. Without it, any anonymous
        // request carrying "Authorization: Bearer <token with a made-up kid>" turned into one HTTP
        // GET against security's /.well-known/jwks.json — a fresh fetch never contains an invented
        // kid, so every such request missed again. An unauthenticated caller therefore drove
        // traffic to the identity service one-for-one, amplified across every service that runs
        // this gate. A real rotation still propagates within the floor, and a flood of junk kids
        // now costs at most one fetch per floor.
        if (!stale && clock.get().isBefore(lastFetchAttempt.plus(refetchFloor))) {
            return known.get(kid);
        }
        lastFetchAttempt = clock.get();
        Map<String, PublicKey> fresh = jwksFetcher.get();
        if (fresh.isEmpty()) {
            // the JWKS is unreachable: keep serving the last good keys (and retry next time —
            // fetchedAt stays put) instead of turning a fetch hiccup into a total outage
            return known.get(kid);
        }
        cachedKeys.set(fresh);
        fetchedAt = clock.get();
        return fresh.get(kid);
    }

    private static boolean signatureVerifies(PublicKey key, String[] parts) throws Exception {
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(key);
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        return verifier.verify(Base64.getUrlDecoder().decode(parts[2]));
    }

    private JsonNode json(String base64Url) throws Exception {
        return mapper.readTree(Base64.getUrlDecoder().decode(base64Url));
    }

    /** Rebuild the Ed25519 public key from a JWK's raw {@code x}: fixed DER prefix + 32 raw bytes. */
    private static PublicKey publicKeyFrom(String x) throws Exception {
        byte[] raw = Base64.getUrlDecoder().decode(x);
        byte[] encoded = new byte[ED25519_DER_PREFIX.length + raw.length];
        System.arraycopy(ED25519_DER_PREFIX, 0, encoded, 0, ED25519_DER_PREFIX.length);
        System.arraycopy(raw, 0, encoded, ED25519_DER_PREFIX.length, raw.length);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
    }
}
