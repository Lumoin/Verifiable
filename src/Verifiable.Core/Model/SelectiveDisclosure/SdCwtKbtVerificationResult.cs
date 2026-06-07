namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// The parsed and cryptographically verified contents of an SD-CWT Key Binding
/// Token (KBT) per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see>. The serialization-neutral result of
/// <c>KbCwtVerification.VerifyAsync</c>.
/// </summary>
/// <remarks>
/// <para>
/// Unlike the SD-JWT KB-JWT there is <strong>no <c>sd_hash</c></strong> in SD-CWT:
/// the binding is that the holder signs over the embedded presentation SD-CWT, so a
/// valid holder signature (<see cref="HolderSignatureValid"/>) <em>is</em> the binding.
/// The embedded SD-CWT's issuer signature and per-disclosure digest binding are reported
/// in <see cref="CredentialSignatureValid"/>; the disclosed claims recovered from the
/// presentation are in <see cref="DisclosedClaims"/>.
/// </para>
/// </remarks>
public sealed record SdCwtKbtVerificationResult
{
    /// <summary>
    /// Whether the KBT holder signature verified against the holder public key
    /// reconstructed from the embedded SD-CWT <c>cnf</c> COSE_Key.
    /// </summary>
    public bool HolderSignatureValid { get; init; }

    /// <summary>
    /// Whether the embedded presentation SD-CWT verified in full: the issuer
    /// COSE_Sign1 signature plus the per-disclosure digest binding.
    /// </summary>
    public bool CredentialSignatureValid { get; init; }

    /// <summary>
    /// The embedded SD-CWT's verified <c>iss</c> claim (CWT claim 1) — the issuer
    /// identifier the verifier resolved to find the issuer key — or <see langword="null"/>
    /// when the credential carries none. Surfaced so a verifier can enforce a DCQL
    /// <c>trusted_authorities</c> constraint of type <c>openid_federation</c> against it.
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>The <c>aud</c> claim (CWT claim 3) identifying the Verifier.</summary>
    public string? Audience { get; init; }

    /// <summary>The <c>cnonce</c> claim (CWT claim 39), or <see langword="null"/> when omitted.</summary>
    public string? Cnonce { get; init; }

    /// <summary>The <c>iat</c> claim (CWT claim 6), or <see langword="null"/> when absent.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>The disclosed claims recovered from the embedded SD-CWT presentation, keyed by claim name.</summary>
    public IReadOnlyDictionary<string, string> DisclosedClaims { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// The shortest disclosure salt length, in bytes, across the embedded SD-CWT's disclosures, or
    /// <see langword="null"/> when there were no disclosures. Observed for the verifier salt-length
    /// signal — RFC 9901 §9.3 RECOMMENDS at least 16 bytes (128 bits).
    /// </summary>
    public int? MinimumDisclosureSaltLengthBytes { get; init; }

    /// <summary>
    /// Whether any embedded-SD-CWT disclosure salt was already seen by the application's salt-reuse
    /// store (RFC 9901 §9.4 — unique salts; a repeat is a correlation/replay signal). Only ever
    /// <see langword="true"/> when a salt-reuse seam was wired and a reuse was found; <see langword="false"/>
    /// otherwise. The verifier mirror of DPoP-JTI replay.
    /// </summary>
    public bool SaltReused { get; init; }
}
