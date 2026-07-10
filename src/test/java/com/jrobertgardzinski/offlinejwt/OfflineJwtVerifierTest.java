package com.jrobertgardzinski.offlinejwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The verifier trusts only what verifies: a token signed by the key the JWKS names comes back
 * with its subject, roles and MFA floor; a forged signature, a foreign issuer, an expired token
 * or a key the JWKS does not know (after one refetch) all verify to empty — fail closed. This
 * suite is the merged conscience of the five service copies this library replaced.
 */
class OfflineJwtVerifierTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final KeyPair keys = generate();
    private final KeyPair otherKeys = generate();

    @Test
    void a_properly_signed_token_carries_the_caller() throws Exception {
        OfflineJwtVerifier verifier = new OfflineJwtVerifier(
                () -> Map.of("kid-1", keys.getPublic()), mapper);
        String token = token(keys, "kid-1", "mod@example.com", "[\"USER\",\"MODERATOR\"]",
                Instant.now().getEpochSecond() + 300, "microservice-security");

        Optional<VerifiedToken> verified = verifier.verify(token);

        assertTrue(verified.isPresent());
        assertEquals("mod@example.com", verified.get().subject());
        assertEquals(Set.of("USER", "MODERATOR"), verified.get().roles(), "roles ride inside the token");
        assertTrue(verified.get().mfaCompliant());
    }

    @Test
    void a_token_without_a_roles_claim_is_a_plain_user() throws Exception {
        OfflineJwtVerifier verifier = new OfflineJwtVerifier(
                () -> Map.of("kid-1", keys.getPublic()), mapper);
        String header = b64(("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"kid-1\"}")
                .getBytes(StandardCharsets.UTF_8));
        String claims = b64(("{\"iss\":\"microservice-security\",\"sub\":\"user@example.com\",\"exp\":"
                + (Instant.now().getEpochSecond() + 300) + "}").getBytes(StandardCharsets.UTF_8));
        String token = signed(keys, header, claims);

        Optional<VerifiedToken> verified = verifier.verify(token);

        assertTrue(verified.isPresent());
        assertEquals(Set.of("USER"), verified.get().roles(), "no roles claim defaults to plain USER");
        assertFalse(verified.get().mfaCompliant(), "an older token without the claim counts as false");
    }

    @Test
    void the_mfa_floor_rides_the_token() throws Exception {
        OfflineJwtVerifier verifier = new OfflineJwtVerifier(
                () -> Map.of("kid-1", keys.getPublic()), mapper);
        String token = token(keys, "kid-1", "mod@example.com", "[\"USER\",\"MODERATOR\"]",
                Instant.now().getEpochSecond() + 300, "microservice-security", false);

        Optional<VerifiedToken> verified = verifier.verify(token);

        assertTrue(verified.isPresent(), "the account still verifies — what to withhold is the service's policy");
        assertFalse(verified.get().mfaCompliant());
    }

    @Test
    void forged_expired_or_foreign_tokens_are_refused() throws Exception {
        OfflineJwtVerifier verifier = new OfflineJwtVerifier(
                () -> Map.of("kid-1", keys.getPublic()), mapper);
        long alive = Instant.now().getEpochSecond() + 300;

        String forged = token(otherKeys, "kid-1", "x@example.com", "[\"USER\"]", alive, "microservice-security");
        String expired = token(keys, "kid-1", "x@example.com", "[\"USER\"]",
                Instant.now().getEpochSecond() - 1, "microservice-security");
        String foreign = token(keys, "kid-1", "x@example.com", "[\"USER\"]", alive, "someone-else");

        assertTrue(verifier.verify(forged).isEmpty(), "a signature by another key must not verify");
        assertTrue(verifier.verify(expired).isEmpty(), "expiry is the offline verifier's only revocation");
        assertTrue(verifier.verify(foreign).isEmpty(), "another issuer's tokens mean nothing here");
        assertTrue(verifier.verify("not-a-jwt").isEmpty());
    }

    @Test
    void an_unknown_kid_triggers_one_refetch_which_covers_key_rotation() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        OfflineJwtVerifier verifier = new OfflineJwtVerifier(
                () -> {
                    fetches.incrementAndGet();
                    return Map.of("kid-2", keys.getPublic());
                }, mapper);
        String token = token(keys, "kid-2", "user@example.com", "[\"USER\"]",
                Instant.now().getEpochSecond() + 300, "microservice-security");

        assertTrue(verifier.verify(token).isPresent(), "the fresh key set knows the new kid");
        assertTrue(verifier.verify(token).isPresent());
        assertEquals(1, fetches.get(), "the refetched keys are cached, not refetched per request");
    }

    // --- Helpers --------------------------------------------------------------

    private static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private String token(KeyPair signer, String kid, String sub, String rolesJson, long exp, String issuer)
            throws Exception {
        return token(signer, kid, sub, rolesJson, exp, issuer, true);
    }

    private String token(KeyPair signer, String kid, String sub, String rolesJson, long exp, String issuer,
                         boolean mfaCompliant) throws Exception {
        String header = b64(("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}")
                .getBytes(StandardCharsets.UTF_8));
        String claims = b64(("{\"iss\":\"" + issuer + "\",\"sub\":\"" + sub + "\",\"roles\":" + rolesJson
                + ",\"mfaCompliant\":" + mfaCompliant + ",\"exp\":" + exp + "}").getBytes(StandardCharsets.UTF_8));
        return signed(signer, header, claims);
    }

    private static String signed(KeyPair signer, String header, String claims) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(signer.getPrivate());
        signature.update((header + "." + claims).getBytes(StandardCharsets.US_ASCII));
        return header + "." + claims + "." + b64(signature.sign());
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
