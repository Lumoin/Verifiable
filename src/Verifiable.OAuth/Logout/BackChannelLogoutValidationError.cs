namespace Verifiable.OAuth.Logout;

/// <summary>
/// The reason a Logout Token failed the OIDC Back-Channel Logout 1.0 §2.6 validation,
/// reported by <see cref="BackChannelLogout.VerifyLogoutTokenAsync"/> so a Receiver can
/// branch on the cause rather than catch an exception.
/// </summary>
public enum BackChannelLogoutValidationError
{
    /// <summary>The token could not be parsed as a compact JWS, or its payload was not a JSON object.</summary>
    Malformed,

    /// <summary>The signature did not verify under the supplied key (not issued by the expected OP).</summary>
    SignatureInvalid,

    /// <summary>The <c>iss</c> claim is absent or does not equal the expected issuer (ordinal match).</summary>
    IssuerMismatch,

    /// <summary>The <c>aud</c> claim does not include the expected audience (this Receiver's client identifier).</summary>
    AudienceMismatch,

    /// <summary>The <c>iat</c> claim is absent (§2.6 requires it, as for an ID Token).</summary>
    MissingIssuedAt,

    /// <summary>Neither a <c>sub</c> nor a <c>sid</c> claim is present (§2.4/§2.6 require at least one).</summary>
    MissingSubjectAndSession,

    /// <summary>The <c>events</c> claim does not carry the back-channel logout member (§2.6).</summary>
    MissingLogoutEvent,

    /// <summary>A <c>nonce</c> claim is present, which a Logout Token MUST NOT contain (§2.6).</summary>
    ForbiddenNonce
}
