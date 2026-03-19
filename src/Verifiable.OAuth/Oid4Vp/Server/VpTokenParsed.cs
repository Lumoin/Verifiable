using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Raw results from parsing and cryptographically verifying a VP token.
/// Produced by <see cref="SdJwtVpTokenVerification"/>, consumed by the executor
/// to construct a <see cref="Validation.ValidationContext"/> for library-side
/// validation.
/// </summary>
[DebuggerDisplay("VpTokenParsed KbJwtSignatureValid={KbJwtSignatureValid} CredentialSignatureValid={CredentialSignatureValid}")]
public sealed record VpTokenParsed
{
    /// <summary>The <c>nonce</c> claim extracted from the KB-JWT.</summary>
    public string? KbJwtNonce { get; init; }

    /// <summary>The <c>aud</c> claim extracted from the KB-JWT.</summary>
    public string? KbJwtAud { get; init; }

    /// <summary>The <c>iat</c> claim extracted from the KB-JWT.</summary>
    public DateTimeOffset? KbJwtIat { get; init; }

    /// <summary>Whether the KB-JWT signature was cryptographically valid.</summary>
    public bool KbJwtSignatureValid { get; init; }

    /// <summary>Whether the credential issuer signature was cryptographically valid.</summary>
    public bool CredentialSignatureValid { get; init; }

    /// <summary>Whether the <c>sd_hash</c> matched the presented disclosures (SD-JWT).</summary>
    public bool SdHashValid { get; init; }

    /// <summary>Whether the session transcript was correctly computed (mdoc).</summary>
    public bool SessionTranscriptValid { get; init; }

    /// <summary>
    /// The extracted credential claims, keyed by DCQL credential query identifier.
    /// Each inner dictionary maps claim name to claim value.
    /// </summary>
    public required IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> ExtractedClaims { get; init; }
}
