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
 * are cached; an unknown {@code kid} triggers one refetch, which also covers security restarting
 * with fresh ephemeral keys. Every failure — malformed token, wrong algorithm, forged signature,
 * foreign issuer, expiry, unreachable JWKS — verifies to empty: the caller fails closed.
 */
public final class OfflineJwtVerifier {

    private static final String EXPECTED_ISSUER = "microservice-security";
    private static final byte[] ED25519_DER_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    private final Supplier<Map<String, PublicKey>> jwksFetcher;
    private final ObjectMapper mapper;
    private final AtomicReference<Map<String, PublicKey>> cachedKeys = new AtomicReference<>(Map.of());

    /** Full control of the key source — the constructor tests (and unusual transports) use. */
    public OfflineJwtVerifier(Supplier<Map<String, PublicKey>> jwksFetcher, ObjectMapper mapper) {
        this.jwksFetcher = jwksFetcher;
        this.mapper = mapper;
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
                    || claims.path("exp").asLong() <= Instant.now().getEpochSecond()) {
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
        PublicKey known = cachedKeys.get().get(kid);
        if (known != null) {
            return known;
        }
        // unknown kid: maybe a rotation (or security restarted with fresh keys) — refetch once
        Map<String, PublicKey> fresh = jwksFetcher.get();
        cachedKeys.set(fresh);
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
