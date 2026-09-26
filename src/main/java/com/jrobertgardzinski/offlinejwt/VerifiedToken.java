package com.jrobertgardzinski.offlinejwt;

import java.util.Set;

/**
 * What a verified access token says about its caller: the subject (security's stable user id),
 * the e-mail address as a separate claim, the roles, and whether the token attests the account
 * meets its MFA floor. What a service does with the floor is the service's policy.
 */
public record VerifiedToken(String subject, String email, Set<String> roles, boolean mfaCompliant) {
}
