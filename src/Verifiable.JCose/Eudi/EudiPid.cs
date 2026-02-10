using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose.Eudi;

/// <summary>
/// Well-known constants for the EUDI Wallet Person Identification Data (PID) attestation.
/// </summary>
/// <remarks>
/// <para>
/// Constants are derived from the PID Rulebook in the EUDI Wallet Architecture and
/// Reference Framework attestation rulebooks catalog.
/// </para>
/// <para>
/// See <see href="https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md">PID Rulebook</see>
/// and <see href="https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog">Attestation Rulebooks Catalog</see>.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "This groups together EUDI PID constants.")]
public static class EudiPid
{
    /// <summary>
    /// The PID attestation type and namespace for ISO/IEC 18013-5-compliant (mso_mdoc) encoding.
    /// The attestation type and namespace share the same value.
    /// </summary>
    public const string AttestationType = "eu.europa.ec.eudi.pid.1";

    /// <summary>
    /// Conventional credential query identifier for PID in DCQL queries and VP Token responses.
    /// This is not mandated by the PID Rulebook but is a widely used convention
    /// in the EUDI Wallet ecosystem (e.g., EWC RFC 002 examples).
    /// </summary>
    public const string DefaultCredentialQueryId = "pid";

    /// <summary>
    /// The SD-JWT VC Verifiable Credential Type (vct) base type for PIDs.
    /// Domestic types extend this base using the convention <c>urn:eudi:pid:{country}:1</c>.
    /// </summary>
    /// <remarks>
    /// See <see href="https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md#4-pid-sd-jwt-vc">PID Rulebook Chapter 4</see>.
    /// </remarks>
    public const string SdJwtVct = "urn:eudi:pid:1";

    /// <summary>
    /// The prefix for all PID VCT URNs, including the base type and domestic extensions.
    /// </summary>
    private const string VctPrefix = "urn:eudi:pid:";

    /// <summary>
    /// The version suffix for domestic PID VCT URNs.
    /// </summary>
    private const string VctVersionSuffix = ":1";


    /// <summary>
    /// Builds a domestic PID VCT value for the specified country.
    /// </summary>
    /// <param name="countryCode">
    /// ISO 3166-1 alpha-2 country code (e.g., <c>"fi"</c>, <c>"de"</c>).
    /// The value is normalized to lowercase.
    /// </param>
    /// <returns>
    /// The domestic VCT string following the convention <c>urn:eudi:pid:{country}:1</c>,
    /// for example <c>urn:eudi:pid:fi:1</c>.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="countryCode"/> is null, empty, or not exactly two characters.
    /// </exception>
    /// <remarks>
    /// <para>
    /// Domestic PID types extend the base <see cref="SdJwtVct"/> with a country-specific segment.
    /// SD-JWT VC verifiers use the <c>vct</c> claim to determine which domestic PID rulebook applies.
    /// </para>
    /// <para>
    /// See <see href="https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md#4-pid-sd-jwt-vc">PID Rulebook Chapter 4</see>.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// string finnishVct = EudiPid.DomesticVct("fi");
    /// //Returns "urn:eudi:pid:fi:1".
    /// </code>
    /// </example>
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
    /// Attempts to parse a domestic PID VCT value and extract the country code.
    /// </summary>
    /// <param name="vct">The VCT string to parse.</param>
    /// <param name="countryCode">
    /// When this method returns <see langword="true"/>, the ISO 3166-1 alpha-2 country code
    /// in lowercase. When this method returns <see langword="false"/>, <see langword="null"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="vct"/> is a valid domestic PID VCT
    /// of the form <c>urn:eudi:pid:{country}:1</c>; otherwise, <see langword="false"/>.
    /// Returns <see langword="false"/> for the base type <see cref="SdJwtVct"/> since
    /// it has no country segment.
    /// </returns>
    /// <remarks>
    /// See <see href="https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md#4-pid-sd-jwt-vc">PID Rulebook Chapter 4</see>.
    /// </remarks>
    /// <example>
    /// <code>
    /// if(EudiPid.TryParseDomesticVct("urn:eudi:pid:de:1", out string? country))
    /// {
    ///     //country is "de".
    /// }
    /// </code>
    /// </example>
    [SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "Country code is normalized to lowercase for consistency with ISO 3166-1 alpha-2 codes.")]
    public static bool TryParseDomesticVct(string vct, [NotNullWhen(true)] out string? countryCode)
    {
        countryCode = null;

        if(string.IsNullOrEmpty(vct))
        {
            return false;
        }

        if(!vct.StartsWith(VctPrefix, StringComparison.Ordinal) ||
           !vct.EndsWith(VctVersionSuffix, StringComparison.Ordinal))
        {
            return false;
        }

        //Extract the segment between "urn:eudi:pid:" and ":1".
        int segmentStart = VctPrefix.Length;
        int segmentEnd = vct.Length - VctVersionSuffix.Length;

        if(segmentEnd <= segmentStart)
        {
            return false;
        }

        string segment = vct[segmentStart..segmentEnd];

        if(segment.Length != 2)
        {
            return false;
        }

        countryCode = segment.ToLowerInvariant();
        return true;
    }


    /// <summary>
    /// Determines whether the specified VCT string identifies a PID credential,
    /// either the base type or a domestic extension.
    /// </summary>
    /// <param name="vct">The VCT string to check.</param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="vct"/> is <see cref="SdJwtVct"/>
    /// or a domestic variant matching <c>urn:eudi:pid:{country}:1</c>;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    public static bool IsPidVct(string vct)
    {
        if(string.IsNullOrEmpty(vct))
        {
            return false;
        }

        return string.Equals(vct, SdJwtVct, StringComparison.Ordinal) ||
               TryParseDomesticVct(vct, out _);
    }


    /// <summary>
    /// Attribute identifiers for the ISO/IEC 18013-5-compliant (mso_mdoc) encoding of PID.
    /// These identifiers are used in presentation requests and responses according to ISO/IEC 18013-5.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The namespace for these attributes is <see cref="AttestationType"/> (<c>eu.europa.ec.eudi.pid.1</c>).
    /// </para>
    /// <para>
    /// See Chapter 3 of the
    /// <see href="https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md">PID Rulebook</see>.
    /// </para>
    /// </remarks>
    public static class Mdoc
    {
        /// <summary>
        /// The namespace for PID attributes in mso_mdoc encoding.
        /// Same value as <see cref="AttestationType"/>.
        /// </summary>
        public const string Namespace = AttestationType;

        /// <summary>
        /// Current last name(s) or surname(s) of the PID user. Mandatory.
        /// </summary>
        public const string FamilyName = "family_name";

        /// <summary>
        /// Current first name(s), including middle name(s), of the PID user. Mandatory.
        /// </summary>
        public const string GivenName = "given_name";

        /// <summary>
        /// Day, month, and year on which the PID user was born. Mandatory.
        /// Encoded as <c>full-date</c> per RFC 8943.
        /// </summary>
        public const string BirthDate = "birth_date";

        /// <summary>
        /// Place of birth of the PID user. Mandatory.
        /// Contains at least one of: country, region, or locality.
        /// </summary>
        public const string PlaceOfBirth = "place_of_birth";

        /// <summary>
        /// Nationality of the PID user as an array of ISO 3166-1 alpha-2 country codes. Mandatory.
        /// </summary>
        public const string Nationalities = "nationalities";

        /// <summary>
        /// Full address of where the PID user currently resides. Optional.
        /// </summary>
        public const string ResidentAddress = "resident_address";

        /// <summary>
        /// Country where the PID user currently resides as an ISO 3166-1 alpha-2 code. Optional.
        /// </summary>
        public const string ResidentCountry = "resident_country";

        /// <summary>
        /// State, province, district, or local area where the PID user resides. Optional.
        /// </summary>
        public const string ResidentState = "resident_state";

        /// <summary>
        /// Municipality, city, town, or village where the PID user resides. Optional.
        /// </summary>
        public const string ResidentCity = "resident_city";

        /// <summary>
        /// Postal code of the place where the PID user resides. Optional.
        /// </summary>
        public const string ResidentPostalCode = "resident_postal_code";

        /// <summary>
        /// Name of the street where the PID user resides. Optional.
        /// </summary>
        public const string ResidentStreet = "resident_street";

        /// <summary>
        /// House number where the PID user resides, including any affix or suffix. Optional.
        /// </summary>
        public const string ResidentHouseNumber = "resident_house_number";

        /// <summary>
        /// A unique value assigned to the natural person by the PID provider. Optional.
        /// </summary>
        public const string PersonalAdministrativeNumber = "personal_administrative_number";

        /// <summary>
        /// Facial image of the PID user compliant with ISO 19794-5 or ISO 39794. Optional.
        /// </summary>
        public const string Portrait = "portrait";

        /// <summary>
        /// Last name(s) or surname(s) of the PID user at the time of birth. Optional.
        /// </summary>
        public const string FamilyNameBirth = "family_name_birth";

        /// <summary>
        /// First name(s), including middle name(s), of the PID user at the time of birth. Optional.
        /// </summary>
        public const string GivenNameBirth = "given_name_birth";

        /// <summary>
        /// Sex of the PID user. Optional. Values per ISO/IEC 5218 plus EUDI extensions.
        /// </summary>
        public const string Sex = "sex";

        /// <summary>
        /// Email address of the PID user per RFC 5322. Optional.
        /// </summary>
        public const string EmailAddress = "email_address";

        /// <summary>
        /// Mobile phone number of the PID user in international format. Optional.
        /// </summary>
        public const string MobilePhoneNumber = "mobile_phone_number";

        /// <summary>
        /// Date (and if possible time) when the PID will expire. Mandatory metadata.
        /// </summary>
        public const string ExpiryDate = "expiry_date";

        /// <summary>
        /// Name of the authority that issued the PID, or country code. Mandatory metadata.
        /// </summary>
        public const string IssuingAuthority = "issuing_authority";

        /// <summary>
        /// ISO 3166-1 alpha-2 country code of the PID provider. Mandatory metadata.
        /// </summary>
        public const string IssuingCountry = "issuing_country";

        /// <summary>
        /// Number for the PID assigned by the provider. Optional metadata.
        /// </summary>
        public const string DocumentNumber = "document_number";

        /// <summary>
        /// ISO 3166-2 country subdivision code of the issuing jurisdiction. Optional metadata.
        /// </summary>
        public const string IssuingJurisdiction = "issuing_jurisdiction";

        /// <summary>
        /// Date (and if possible time) when the PID was issued. Optional.
        /// </summary>
        public const string IssuanceDate = "issuance_date";

        /// <summary>
        /// Whether the PID user is currently an adult. Optional.
        /// </summary>
        public const string AgeOver18 = "age_over_18";

        /// <summary>
        /// The current age of the PID user in years. Optional.
        /// </summary>
        public const string AgeInYears = "age_in_years";

        /// <summary>
        /// The birth year of the PID user. Optional.
        /// </summary>
        public const string AgeBirthYear = "age_birth_year";

        /// <summary>
        /// URL of a machine-readable trust anchor for verifying the PID. Optional.
        /// </summary>
        public const string TrustAnchor = "trust_anchor";
    }

    /// <summary>
    /// Claim names for the SD-JWT VC encoding of PID.
    /// These claim names are used in SD-JWT VC-compliant PIDs and may differ
    /// from the mso_mdoc attribute identifiers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Claim names follow IANA JWT Claims Registry, OpenID Connect Core, and
    /// OpenID Connect for Identity Assurance (EKYC) conventions.
    /// </para>
    /// <para>
    /// See Chapter 4 of the
    /// <see href="https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md">PID Rulebook</see>.
    /// </para>
    /// </remarks>
    public static class SdJwt
    {
        /// <summary>
        /// Current last name(s) or surname(s). IANA registered claim per OIDC Section 5.1.
        /// </summary>
        public const string FamilyName = "family_name";

        /// <summary>
        /// Current first name(s), including middle name(s). IANA registered claim per OIDC Section 5.1.
        /// </summary>
        public const string GivenName = "given_name";

        /// <summary>
        /// Date of birth in ISO 8601-1 YYYY-MM-DD format. IANA registered claim per OIDC Section 5.1.
        /// </summary>
        public const string Birthdate = "birthdate";

        /// <summary>
        /// Place of birth as a JSON structure with country, region, and/or locality.
        /// Per EKYC Section 4.1.
        /// </summary>
        public const string PlaceOfBirth = "place_of_birth";

        /// <summary>
        /// Array of ISO 3166-1 alpha-2 nationality codes. Per EKYC Section 4.1.
        /// </summary>
        public const string Nationalities = "nationalities";

        /// <summary>
        /// Full formatted address. Hierarchical claim under <c>address</c>. Per OIDC Section 5.1.
        /// </summary>
        public const string AddressFormatted = "address.formatted";

        /// <summary>
        /// Country of residence. Hierarchical claim under <c>address</c>. Per OIDC Section 5.1.
        /// </summary>
        public const string AddressCountry = "address.country";

        /// <summary>
        /// State/province/region of residence. Hierarchical claim under <c>address</c>.
        /// </summary>
        public const string AddressRegion = "address.region";

        /// <summary>
        /// City of residence. Hierarchical claim under <c>address</c>.
        /// </summary>
        public const string AddressLocality = "address.locality";

        /// <summary>
        /// Postal code of residence. Hierarchical claim under <c>address</c>.
        /// </summary>
        public const string AddressPostalCode = "address.postal_code";

        /// <summary>
        /// Street address of residence. Hierarchical claim under <c>address</c>.
        /// </summary>
        public const string AddressStreetAddress = "address.street_address";

        /// <summary>
        /// House number of residence. Hierarchical claim under <c>address</c>.
        /// </summary>
        public const string AddressHouseNumber = "address.house_number";

        /// <summary>
        /// Last name(s) at birth. Per EKYC Section 4.1.
        /// </summary>
        public const string BirthFamilyName = "birth_family_name";

        /// <summary>
        /// First name(s) at birth. Per EKYC Section 4.1.
        /// </summary>
        public const string BirthGivenName = "birth_given_name";

        /// <summary>
        /// Email address. IANA registered claim per OIDC Section 5.1.
        /// </summary>
        public const string Email = "email";

        /// <summary>
        /// Mobile phone number. IANA registered claim per OIDC Section 5.1.
        /// </summary>
        public const string PhoneNumber = "phone_number";

        /// <summary>
        /// Portrait as a data URL with base64-encoded JPEG. IANA registered claim per OIDC Section 5.1.
        /// </summary>
        public const string Picture = "picture";

        /// <summary>
        /// A unique value assigned to the natural person by the PID provider.
        /// </summary>
        public const string PersonalAdministrativeNumber = "personal_administrative_number";

        /// <summary>
        /// Sex of the PID user. Numeric encoding per EUDI PID Rulebook.
        /// </summary>
        public const string Sex = "sex";

        /// <summary>
        /// Name of the authority that issued the PID, or country code.
        /// </summary>
        public const string IssuingAuthority = "issuing_authority";

        /// <summary>
        /// ISO 3166-1 alpha-2 country code of the PID provider.
        /// </summary>
        public const string IssuingCountry = "issuing_country";

        /// <summary>
        /// Number for the PID assigned by the provider.
        /// </summary>
        public const string DocumentNumber = "document_number";

        /// <summary>
        /// ISO 3166-2 country subdivision code of the issuing jurisdiction.
        /// </summary>
        public const string IssuingJurisdiction = "issuing_jurisdiction";

        /// <summary>
        /// Administrative expiry date in ISO 8601-1 YYYY-MM-DD format.
        /// Per EKYC Schema Section 5.4.4.2.
        /// </summary>
        public const string DateOfExpiry = "date_of_expiry";

        /// <summary>
        /// Administrative issuance date in ISO 8601-1 YYYY-MM-DD format.
        /// Per EKYC Schema Section 5.4.4.2.
        /// </summary>
        public const string DateOfIssuance = "date_of_issuance";

        /// <summary>
        /// Age attestation object. Individual ages are selectively disclosable properties
        /// (e.g., <c>age_equal_or_over.18</c>).
        /// </summary>
        public const string AgeEqualOrOver = "age_equal_or_over";

        /// <summary>
        /// The current age of the PID user in years.
        /// </summary>
        public const string AgeInYears = "age_in_years";

        /// <summary>
        /// The birth year of the PID user.
        /// </summary>
        public const string AgeBirthYear = "age_birth_year";

        /// <summary>
        /// URL of a machine-readable trust anchor for verifying the PID.
        /// </summary>
        public const string TrustAnchor = "trust_anchor";
    }
}