package com.jrobertgardzinski.offlinejwt;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslJsonBody;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The consumer's half of the JWKS contract. This library is THE consumer of
 * {@code /.well-known/jwks.json} — the services delegate their offline verification here — so the
 * pact lives here too, not copied into five repos. The interaction states exactly what the
 * fetcher relies on: an Ed25519 key (kty OKP, crv Ed25519) addressable by {@code kid}, its public
 * half as raw base64url {@code x}. Proven end to end: the REAL fetcher pulls the pact's key set
 * and a token signed by the matching (fixed, test-only) private key verifies through it.
 */
@ExtendWith(PactConsumerTestExt.class)
@PactTestFor(providerName = "microservice-security", pactVersion = PactSpecVersion.V3)
class JwksContractTest {

    /** Fixed test-only keypair, so the committed pact does not churn between runs. */
    private static final String X = "HbFDOOdmqwUJtwEk2uvSiQFBSJlAEojLBuc6IegdA2k";
    private static final String PRIVATE_PKCS8_B64 =
            "MC4CAQAwBQYDK2VwBCIEIF86VPIoqkdaY3S4YyOCAMz+wJVZu3ClwdUaAMZwtCdE";

    @Pact(consumer = "offline-jwt")
    RequestResponsePact jwks(PactDslWithProvider builder) {
        return builder
                .uponReceiving("a fetch of the JWK set")
                .path("/.well-known/jwks.json")
                .method("GET")
                .willRespondWith()
                .status(200)
                .headers(java.util.Map.of("Content-Type", "application/json"))
                .body(new PactDslJsonBody()
                        .minArrayLike("keys", 1)
                        .stringValue("kty", "OKP")
                        .stringValue("crv", "Ed25519")
                        .stringType("kid", "key-1")
                        .stringType("x", X)
                        .closeObject().closeArray().asBody())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "jwks")
    void theFetcherTurnsTheKeySetIntoVerification(MockServer security) throws Exception {
        OfflineJwtVerifier verifier = OfflineJwtVerifier.overHttp(security.getUrl(), new ObjectMapper());

        Optional<VerifiedToken> verified = verifier.verify(tokenSignedByTheFixedKey());

        assertTrue(verified.isPresent(),
                "the key fetched from the pact's JWKS verifies a token signed by its private half");
        assertEquals("user@example.com", verified.get().subject());
    }

    private static String tokenSignedByTheFixedKey() throws Exception {
        PrivateKey key = KeyFactory.getInstance("Ed25519").generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_PKCS8_B64)));
        String header = b64("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"key-1\"}");
        String claims = b64("{\"iss\":\"microservice-security\",\"sub\":\"user@example.com\",\"exp\":"
                + (Instant.now().getEpochSecond() + 300) + "}");
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(key);
        signature.update((header + "." + claims).getBytes(StandardCharsets.US_ASCII));
        return header + "." + claims + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
    }

    private static String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
