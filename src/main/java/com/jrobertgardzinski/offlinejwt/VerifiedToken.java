package com.jrobertgardzinski.offlinejwt;

import java.util.Set;

/**
 * What a successfully verified access token says about its caller: the subject (the caller's
 * e-mail in this ecosystem), the roles riding as a claim (defaulting to plain {@code USER} when
 * the claim is absent), and the MFA floor — whether the token attests the account's enrolment
 * satisfies the deployment's requirement. What a service does with the floor (e.g. withhold
 * privileged roles) is the service's policy, not this library's.
 */
public record VerifiedToken(String subject, Set<String> roles, boolean mfaCompliant) {
}
