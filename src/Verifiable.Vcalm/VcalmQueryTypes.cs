using Verifiable.Cryptography.Text;

namespace Verifiable.Vcalm;

/// <summary>
/// Well-known wire VALUES of the §3.4.1 query <c>type</c> discriminator — the string values a
/// verifiable-presentation-request query entry sets its <see cref="VcalmParameterNames.Type"/> to,
/// selecting which §3.4 query language the entry carries
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>).
/// </summary>
/// <remarks>
/// These are the VALUES of the <c>type</c> member (e.g. <c>QueryByExample</c>), not member names.
/// They are UTF-8-first per the library convention: each <c>XUtf8</c> span sits beside an interned
/// string <c>X</c> whose value is the span's UTF-8 decoding, swept by the well-known-constant guard.
/// The §3.4.1 query array is an open extension point — a verifier MAY define further query types,
/// so an entry carrying an unrecognized <c>type</c> parses into the model and the holder-side
/// evaluator simply does not satisfy it, rather than the request being rejected.
/// </remarks>
public static class VcalmQueryTypes
{
    /// <summary>The UTF-8 source literal of <see cref="QueryByExample"/>.</summary>
    public static ReadOnlySpan<byte> QueryByExampleUtf8 => "QueryByExample"u8;

    /// <summary>The §3.4.2 query type carrying a single <c>credentialQuery</c> (example, accepted issuers / cryptosuites / envelopes).</summary>
    public static readonly string QueryByExample = Utf8Constants.ToInternedString(QueryByExampleUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DidAuthentication"/>.</summary>
    public static ReadOnlySpan<byte> DidAuthenticationUtf8 => "DIDAuthentication"u8;

    /// <summary>The §3.4.3 query type requesting DID-based authentication (<c>acceptedMethods</c>, <c>acceptedCryptosuites</c>).</summary>
    public static readonly string DidAuthentication = Utf8Constants.ToInternedString(DidAuthenticationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DigitalCredentialQueryLanguage"/>.</summary>
    public static ReadOnlySpan<byte> DigitalCredentialQueryLanguageUtf8 => "DigitalCredentialQueryLanguage"u8;

    /// <summary>
    /// The §3.4 / §3.4.5 co-equal query type carrying a DCQL query — the existing
    /// <see cref="Verifiable.Core.Model.Dcql.DcqlQuery"/> model, adapted rather than reimplemented.
    /// </summary>
    public static readonly string DigitalCredentialQueryLanguage = Utf8Constants.ToInternedString(DigitalCredentialQueryLanguageUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationCapabilityQuery"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationCapabilityQueryUtf8 => "AuthorizationCapabilityQuery"u8;

    /// <summary>
    /// The §3.4.4 query type asking for authorization capabilities ("zcaps"). Editor-flagged as
    /// possibly-not-standardized: modeled defensively, never a conformance gate.
    /// </summary>
    public static readonly string AuthorizationCapabilityQuery = Utf8Constants.ToInternedString(AuthorizationCapabilityQueryUtf8);
}
