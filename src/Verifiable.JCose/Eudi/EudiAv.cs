using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography.Text;

namespace Verifiable.JCose.Eudi;

/// <summary>
/// Well-known constants for the EUDI Wallet Age Verification (AV) /
/// Pseudonym attestation — the focused attestation used to assert
/// age-over-N thresholds without revealing other PID claims.
/// </summary>
/// <remarks>
/// <para>
/// The EUDI AV attestation pseudonymously commits to one or more
/// age-threshold booleans (most commonly <c>age_over_18</c>). It exists
/// as a separate attestation from the full PID so that age-only flows
/// (alcohol/tobacco/gambling) can be served without the relying party
/// needing the broader PID surface — the wallet picks the narrowest
/// attestation that satisfies the verifier's request.
/// </para>
/// <para>
/// See the EUDI Wallet Attestation Rulebooks Catalog at
/// <see href="https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog">eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog</see>
/// for the AV-specific rulebook. Constant values track the rulebook's
/// identifiers; verify against the current rulebook revision before
/// production use as the EUDI ARF is still in active iteration.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "This groups together EUDI AV constants.")]
public static class EudiAv
{
    /// <summary>The UTF-8 source literal of <see cref="AttestationType"/>.</summary>
    public static ReadOnlySpan<byte> AttestationTypeUtf8 => "eu.europa.ec.eudi.pseudonym.age_over_18.1"u8;

    /// <summary>
    /// The AV attestation type and ISO/IEC 18013-5 mdoc namespace.
    /// Attestation type and namespace share the same value per the EUDI
    /// rulebook convention.
    /// </summary>
    public static readonly string AttestationType = Utf8Constants.ToInternedString(AttestationTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DefaultCredentialQueryId"/>.</summary>
    public static ReadOnlySpan<byte> DefaultCredentialQueryIdUtf8 => "age_verification"u8;

    /// <summary>
    /// Conventional credential query identifier for AV in DCQL queries and
    /// VP Token responses. Not mandated by the AV Rulebook but a widely
    /// used convention in the EUDI Wallet ecosystem.
    /// </summary>
    public static readonly string DefaultCredentialQueryId = Utf8Constants.ToInternedString(DefaultCredentialQueryIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SdJwtVct"/>.</summary>
    public static ReadOnlySpan<byte> SdJwtVctUtf8 => "urn:eudi:av:1"u8;

    /// <summary>
    /// The SD-JWT VC Verifiable Credential Type (<c>vct</c>) base for AV
    /// attestations. Domestic types extend this base using the convention
    /// <c>urn:eudi:av:{country}:1</c>, mirroring <see cref="EudiPid.SdJwtVct"/>.
    /// </summary>
    public static readonly string SdJwtVct = Utf8Constants.ToInternedString(SdJwtVctUtf8);

    private const string VctPrefix = "urn:eudi:av:";
    private const string VctVersionSuffix = ":1";

    private const string NamespacePrefix = "eu.europa.ec.eudi.pseudonym.age_over_18.";
    private const string NamespaceVersionSuffix = ".1";


    /// <summary>
    /// Builds a domestic AV SD-JWT VCT value for the specified country.
    /// Parallels <see cref="EudiPid.DomesticVct"/>.
    /// </summary>
    /// <param name="countryCode">ISO 3166-1 alpha-2 code (normalised to lowercase).</param>
    /// <returns>The domestic VCT string (e.g. <c>urn:eudi:av:fi:1</c>).</returns>
    [SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "Country code is normalized to lowercase for consistency with ISO 3166-1 alpha-2 codes.")]
    public static string DomesticVct(string countryCode)
    {
        ArgumentException.ThrowIfNullOrEmpty(countryCode);

        if(countryCode.Length != 2)
        {
            throw new ArgumentException(
                "Country code must be an ISO 3166-1 alpha-2 code (exactly two characters).",
                nameof(countryCode));
        }

        return string.Concat(VctPrefix, countryCode.ToLowerInvariant(), VctVersionSuffix);
    }


    /// <summary>
    /// Builds a domestic AV mdoc namespace for the specified country.
    /// Parallels <see cref="EudiPid.DomesticNamespace"/>.
    /// </summary>
    /// <param name="countryCode">ISO 3166-1 alpha-2 code (normalised to lowercase).</param>
    /// <returns>The domestic namespace string (e.g. <c>eu.europa.ec.eudi.pseudonym.age_over_18.fi.1</c>).</returns>
    [SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "Country code is normalized to lowercase for consistency with ISO 3166-1 alpha-2 codes.")]
    public static string DomesticNamespace(string countryCode)
    {
        ArgumentException.ThrowIfNullOrEmpty(countryCode);

        if(countryCode.Length != 2)
        {
            throw new ArgumentException(
                "Country code must be an ISO 3166-1 alpha-2 code (exactly two characters).",
                nameof(countryCode));
        }

        return string.Concat(NamespacePrefix, countryCode.ToLowerInvariant(), NamespaceVersionSuffix);
    }


    /// <summary>
    /// Attempts to parse a domestic AV mdoc namespace and extract the
    /// country code. Mirror of <see cref="EudiPid.TryParseDomesticNamespace"/>.
    /// </summary>
    [SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "Country code is normalized to lowercase for consistency with ISO 3166-1 alpha-2 codes.")]
    public static bool TryParseDomesticNamespace(string nameSpace, [NotNullWhen(true)] out string? countryCode)
    {
        countryCode = null;

        if(string.IsNullOrEmpty(nameSpace))
        {
            return false;
        }

        if(!nameSpace.StartsWith(NamespacePrefix, StringComparison.Ordinal) ||
           !nameSpace.EndsWith(NamespaceVersionSuffix, StringComparison.Ordinal))
        {
            return false;
        }

        int segmentStart = NamespacePrefix.Length;
        int segmentEnd = nameSpace.Length - NamespaceVersionSuffix.Length;

        if(segmentEnd <= segmentStart)
        {
            return false;
        }

        string segment = nameSpace[segmentStart..segmentEnd];

        if(segment.Length != 2)
        {
            return false;
        }

        countryCode = segment.ToLowerInvariant();

        return true;
    }


    /// <summary>
    /// Returns whether <paramref name="nameSpace"/> identifies an AV mdoc
    /// namespace — either the base namespace or a domestic extension.
    /// </summary>
    public static bool IsAvNamespace(string nameSpace)
    {
        if(string.IsNullOrEmpty(nameSpace))
        {
            return false;
        }

        return string.Equals(nameSpace, AttestationType, StringComparison.Ordinal) ||
               TryParseDomesticNamespace(nameSpace, out _);
    }


    /// <summary>
    /// Attribute identifiers for the ISO/IEC 18013-5-compliant (mso_mdoc)
    /// encoding of AV. The namespace is <see cref="AttestationType"/>
    /// (<c>eu.europa.ec.eudi.pseudonym.age_over_18.1</c>) for the base form
    /// or a <see cref="DomesticNamespace"/> variant.
    /// </summary>
    public static class Mdoc
    {
        /// <summary>The namespace for AV attributes in mso_mdoc encoding.</summary>
        public static readonly string Namespace = AttestationType;

        /// <summary>The UTF-8 source literal of <see cref="AgeOver18"/>.</summary>
        public static ReadOnlySpan<byte> AgeOver18Utf8 => "age_over_18"u8;

        /// <summary>
        /// Whether the holder is at least 18 years old. The primary AV
        /// attribute; the entire attestation centres on this single
        /// boolean.
        /// </summary>
        public static readonly string AgeOver18 = Utf8Constants.ToInternedString(AgeOver18Utf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuanceDate"/>.</summary>
        public static ReadOnlySpan<byte> IssuanceDateUtf8 => "issuance_date"u8;

        /// <summary>
        /// Optional metadata: date the AV attestation was issued.
        /// Mirrors the same field on PID per the rulebook convention.
        /// </summary>
        public static readonly string IssuanceDate = Utf8Constants.ToInternedString(IssuanceDateUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ExpiryDate"/>.</summary>
        public static ReadOnlySpan<byte> ExpiryDateUtf8 => "expiry_date"u8;

        /// <summary>
        /// Optional metadata: date the AV attestation expires.
        /// </summary>
        public static readonly string ExpiryDate = Utf8Constants.ToInternedString(ExpiryDateUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingAuthority"/>.</summary>
        public static ReadOnlySpan<byte> IssuingAuthorityUtf8 => "issuing_authority"u8;

        /// <summary>
        /// Optional metadata: the issuing authority's name or country code.
        /// </summary>
        public static readonly string IssuingAuthority = Utf8Constants.ToInternedString(IssuingAuthorityUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingCountry"/>.</summary>
        public static ReadOnlySpan<byte> IssuingCountryUtf8 => "issuing_country"u8;

        /// <summary>
        /// Optional metadata: ISO 3166-1 alpha-2 country code of the AV
        /// provider.
        /// </summary>
        public static readonly string IssuingCountry = Utf8Constants.ToInternedString(IssuingCountryUtf8);
    }


    /// <summary>
    /// Claim names for the SD-JWT VC encoding of AV. The base
    /// <see cref="SdJwtVct"/> commits to the single mandatory attribute
    /// <see cref="AgeEqualOrOver"/> with a nested <c>18</c> property —
    /// matching the OpenID Connect for Identity Assurance (EKYC) Section
    /// 4.1 age-attestation shape PID uses.
    /// </summary>
    public static class SdJwt
    {
        /// <summary>The UTF-8 source literal of <see cref="AgeEqualOrOver"/>.</summary>
        public static ReadOnlySpan<byte> AgeEqualOrOverUtf8 => "age_equal_or_over"u8;

        /// <summary>
        /// Age attestation object. Individual ages are selectively
        /// disclosable properties under it
        /// (e.g. <c>age_equal_or_over.18</c>).
        /// </summary>
        public static readonly string AgeEqualOrOver = Utf8Constants.ToInternedString(AgeEqualOrOverUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AgeEqualOrOver18"/>.</summary>
        public static ReadOnlySpan<byte> AgeEqualOrOver18Utf8 => "age_equal_or_over.18"u8;

        /// <summary>The over-18 boolean under <see cref="AgeEqualOrOver"/>.</summary>
        public static readonly string AgeEqualOrOver18 = Utf8Constants.ToInternedString(AgeEqualOrOver18Utf8);

        /// <summary>The UTF-8 source literal of <see cref="DateOfIssuance"/>.</summary>
        public static ReadOnlySpan<byte> DateOfIssuanceUtf8 => "date_of_issuance"u8;

        /// <summary>Administrative issuance date in ISO 8601-1 YYYY-MM-DD format.</summary>
        public static readonly string DateOfIssuance = Utf8Constants.ToInternedString(DateOfIssuanceUtf8);

        /// <summary>The UTF-8 source literal of <see cref="DateOfExpiry"/>.</summary>
        public static ReadOnlySpan<byte> DateOfExpiryUtf8 => "date_of_expiry"u8;

        /// <summary>Administrative expiry date in ISO 8601-1 YYYY-MM-DD format.</summary>
        public static readonly string DateOfExpiry = Utf8Constants.ToInternedString(DateOfExpiryUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingAuthority"/>.</summary>
        public static ReadOnlySpan<byte> IssuingAuthorityUtf8 => "issuing_authority"u8;

        /// <summary>Name of the authority that issued the AV attestation.</summary>
        public static readonly string IssuingAuthority = Utf8Constants.ToInternedString(IssuingAuthorityUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingCountry"/>.</summary>
        public static ReadOnlySpan<byte> IssuingCountryUtf8 => "issuing_country"u8;

        /// <summary>ISO 3166-1 alpha-2 country code of the AV provider.</summary>
        public static readonly string IssuingCountry = Utf8Constants.ToInternedString(IssuingCountryUtf8);
    }
}
