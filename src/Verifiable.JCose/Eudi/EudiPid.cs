using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography.Text;

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
    /// <summary>The UTF-8 source literal of <see cref="AttestationType"/>.</summary>
    public static ReadOnlySpan<byte> AttestationTypeUtf8 => "eu.europa.ec.eudi.pid.1"u8;

    /// <summary>
    /// The PID attestation type and namespace for ISO/IEC 18013-5-compliant (mso_mdoc) encoding.
    /// The attestation type and namespace share the same value.
    /// </summary>
    public static readonly string AttestationType = Utf8Constants.ToInternedString(AttestationTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DefaultCredentialQueryId"/>.</summary>
    public static ReadOnlySpan<byte> DefaultCredentialQueryIdUtf8 => "pid"u8;

    /// <summary>
    /// Conventional credential query identifier for PID in DCQL queries and VP Token responses.
    /// This is not mandated by the PID Rulebook but is a widely used convention
    /// in the EUDI Wallet ecosystem (e.g., EWC RFC 002 examples).
    /// </summary>
    public static readonly string DefaultCredentialQueryId = Utf8Constants.ToInternedString(DefaultCredentialQueryIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SdJwtVct"/>.</summary>
    public static ReadOnlySpan<byte> SdJwtVctUtf8 => "urn:eudi:pid:1"u8;

    /// <summary>
    /// The SD-JWT VC Verifiable Credential Type (vct) base type for PIDs.
    /// Domestic types extend this base using the convention <c>urn:eudi:pid:{country}:1</c>.
    /// </summary>
    /// <remarks>
    /// See <see href="https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md#4-pid-sd-jwt-vc">PID Rulebook Chapter 4</see>.
    /// </remarks>
    public static readonly string SdJwtVct = Utf8Constants.ToInternedString(SdJwtVctUtf8);

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
    /// Builds a domestic PID mdoc namespace for the specified country, mirroring
    /// the SD-JWT VC <see cref="DomesticVct"/> shape but for the mdoc encoding
    /// per the PID Rulebook's domestic extension convention
    /// <c>eu.europa.ec.eudi.pid.{country}.1</c>.
    /// </summary>
    /// <param name="countryCode">
    /// ISO 3166-1 alpha-2 country code (e.g., <c>"fi"</c>, <c>"de"</c>).
    /// Normalised to lowercase.
    /// </param>
    /// <returns>The domestic mdoc namespace string.</returns>
    /// <example>
    /// <code>
    /// string finnishNamespace = EudiPid.DomesticNamespace("fi");
    /// //Returns "eu.europa.ec.eudi.pid.fi.1".
    /// </code>
    /// </example>
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
    /// Attempts to parse a domestic PID mdoc namespace and extract the country code.
    /// </summary>
    /// <param name="nameSpace">The namespace string to parse.</param>
    /// <param name="countryCode">
    /// When this method returns <see langword="true"/>, the ISO 3166-1 alpha-2 country code
    /// in lowercase. When <see langword="false"/>, <see langword="null"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when <paramref name="nameSpace"/> matches
    /// <c>eu.europa.ec.eudi.pid.{country}.1</c>. Returns <see langword="false"/> for the
    /// base namespace <see cref="AttestationType"/> (no country segment).
    /// </returns>
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
    /// Determines whether the specified namespace string identifies a PID mdoc
    /// namespace, either the base namespace or a domestic extension.
    /// </summary>
    /// <param name="nameSpace">The namespace string to check.</param>
    /// <returns>
    /// <see langword="true"/> when <paramref name="nameSpace"/> is
    /// <see cref="AttestationType"/> or matches <c>eu.europa.ec.eudi.pid.{country}.1</c>.
    /// </returns>
    public static bool IsPidNamespace(string nameSpace)
    {
        if(string.IsNullOrEmpty(nameSpace))
        {
            return false;
        }

        return string.Equals(nameSpace, AttestationType, StringComparison.Ordinal) ||
               TryParseDomesticNamespace(nameSpace, out _);
    }


    private const string NamespacePrefix = "eu.europa.ec.eudi.pid.";
    private const string NamespaceVersionSuffix = ".1";


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
        public static readonly string Namespace = AttestationType;

        /// <summary>The UTF-8 source literal of <see cref="FamilyName"/>.</summary>
        public static ReadOnlySpan<byte> FamilyNameUtf8 => "family_name"u8;

        /// <summary>
        /// Current last name(s) or surname(s) of the PID user. Mandatory.
        /// </summary>
        public static readonly string FamilyName = Utf8Constants.ToInternedString(FamilyNameUtf8);

        /// <summary>The UTF-8 source literal of <see cref="GivenName"/>.</summary>
        public static ReadOnlySpan<byte> GivenNameUtf8 => "given_name"u8;

        /// <summary>
        /// Current first name(s), including middle name(s), of the PID user. Mandatory.
        /// </summary>
        public static readonly string GivenName = Utf8Constants.ToInternedString(GivenNameUtf8);

        /// <summary>The UTF-8 source literal of <see cref="BirthDate"/>.</summary>
        public static ReadOnlySpan<byte> BirthDateUtf8 => "birth_date"u8;

        /// <summary>
        /// Day, month, and year on which the PID user was born. Mandatory.
        /// Encoded as <c>full-date</c> per RFC 8943.
        /// </summary>
        public static readonly string BirthDate = Utf8Constants.ToInternedString(BirthDateUtf8);

        /// <summary>The UTF-8 source literal of <see cref="PlaceOfBirth"/>.</summary>
        public static ReadOnlySpan<byte> PlaceOfBirthUtf8 => "place_of_birth"u8;

        /// <summary>
        /// Place of birth of the PID user. Mandatory.
        /// Contains at least one of: country, region, or locality.
        /// </summary>
        public static readonly string PlaceOfBirth = Utf8Constants.ToInternedString(PlaceOfBirthUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Nationalities"/>.</summary>
        public static ReadOnlySpan<byte> NationalitiesUtf8 => "nationalities"u8;

        /// <summary>
        /// Nationality of the PID user as an array of ISO 3166-1 alpha-2 country codes. Mandatory.
        /// </summary>
        public static readonly string Nationalities = Utf8Constants.ToInternedString(NationalitiesUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ResidentAddress"/>.</summary>
        public static ReadOnlySpan<byte> ResidentAddressUtf8 => "resident_address"u8;

        /// <summary>
        /// Full address of where the PID user currently resides. Optional.
        /// </summary>
        public static readonly string ResidentAddress = Utf8Constants.ToInternedString(ResidentAddressUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ResidentCountry"/>.</summary>
        public static ReadOnlySpan<byte> ResidentCountryUtf8 => "resident_country"u8;

        /// <summary>
        /// Country where the PID user currently resides as an ISO 3166-1 alpha-2 code. Optional.
        /// </summary>
        public static readonly string ResidentCountry = Utf8Constants.ToInternedString(ResidentCountryUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ResidentState"/>.</summary>
        public static ReadOnlySpan<byte> ResidentStateUtf8 => "resident_state"u8;

        /// <summary>
        /// State, province, district, or local area where the PID user resides. Optional.
        /// </summary>
        public static readonly string ResidentState = Utf8Constants.ToInternedString(ResidentStateUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ResidentCity"/>.</summary>
        public static ReadOnlySpan<byte> ResidentCityUtf8 => "resident_city"u8;

        /// <summary>
        /// Municipality, city, town, or village where the PID user resides. Optional.
        /// </summary>
        public static readonly string ResidentCity = Utf8Constants.ToInternedString(ResidentCityUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ResidentPostalCode"/>.</summary>
        public static ReadOnlySpan<byte> ResidentPostalCodeUtf8 => "resident_postal_code"u8;

        /// <summary>
        /// Postal code of the place where the PID user resides. Optional.
        /// </summary>
        public static readonly string ResidentPostalCode = Utf8Constants.ToInternedString(ResidentPostalCodeUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ResidentStreet"/>.</summary>
        public static ReadOnlySpan<byte> ResidentStreetUtf8 => "resident_street"u8;

        /// <summary>
        /// Name of the street where the PID user resides. Optional.
        /// </summary>
        public static readonly string ResidentStreet = Utf8Constants.ToInternedString(ResidentStreetUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ResidentHouseNumber"/>.</summary>
        public static ReadOnlySpan<byte> ResidentHouseNumberUtf8 => "resident_house_number"u8;

        /// <summary>
        /// House number where the PID user resides, including any affix or suffix. Optional.
        /// </summary>
        public static readonly string ResidentHouseNumber = Utf8Constants.ToInternedString(ResidentHouseNumberUtf8);

        /// <summary>The UTF-8 source literal of <see cref="PersonalAdministrativeNumber"/>.</summary>
        public static ReadOnlySpan<byte> PersonalAdministrativeNumberUtf8 => "personal_administrative_number"u8;

        /// <summary>
        /// A unique value assigned to the natural person by the PID provider. Optional.
        /// </summary>
        public static readonly string PersonalAdministrativeNumber = Utf8Constants.ToInternedString(PersonalAdministrativeNumberUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Portrait"/>.</summary>
        public static ReadOnlySpan<byte> PortraitUtf8 => "portrait"u8;

        /// <summary>
        /// Facial image of the PID user compliant with ISO 19794-5 or ISO 39794. Optional.
        /// </summary>
        public static readonly string Portrait = Utf8Constants.ToInternedString(PortraitUtf8);

        /// <summary>The UTF-8 source literal of <see cref="FamilyNameBirth"/>.</summary>
        public static ReadOnlySpan<byte> FamilyNameBirthUtf8 => "family_name_birth"u8;

        /// <summary>
        /// Last name(s) or surname(s) of the PID user at the time of birth. Optional.
        /// </summary>
        public static readonly string FamilyNameBirth = Utf8Constants.ToInternedString(FamilyNameBirthUtf8);

        /// <summary>The UTF-8 source literal of <see cref="GivenNameBirth"/>.</summary>
        public static ReadOnlySpan<byte> GivenNameBirthUtf8 => "given_name_birth"u8;

        /// <summary>
        /// First name(s), including middle name(s), of the PID user at the time of birth. Optional.
        /// </summary>
        public static readonly string GivenNameBirth = Utf8Constants.ToInternedString(GivenNameBirthUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Sex"/>.</summary>
        public static ReadOnlySpan<byte> SexUtf8 => "sex"u8;

        /// <summary>
        /// Sex of the PID user. Optional. Values per ISO/IEC 5218 plus EUDI extensions.
        /// </summary>
        public static readonly string Sex = Utf8Constants.ToInternedString(SexUtf8);

        /// <summary>The UTF-8 source literal of <see cref="EmailAddress"/>.</summary>
        public static ReadOnlySpan<byte> EmailAddressUtf8 => "email_address"u8;

        /// <summary>
        /// Email address of the PID user per RFC 5322. Optional.
        /// </summary>
        public static readonly string EmailAddress = Utf8Constants.ToInternedString(EmailAddressUtf8);

        /// <summary>The UTF-8 source literal of <see cref="MobilePhoneNumber"/>.</summary>
        public static ReadOnlySpan<byte> MobilePhoneNumberUtf8 => "mobile_phone_number"u8;

        /// <summary>
        /// Mobile phone number of the PID user in international format. Optional.
        /// </summary>
        public static readonly string MobilePhoneNumber = Utf8Constants.ToInternedString(MobilePhoneNumberUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ExpiryDate"/>.</summary>
        public static ReadOnlySpan<byte> ExpiryDateUtf8 => "expiry_date"u8;

        /// <summary>
        /// Date (and if possible time) when the PID will expire. Mandatory metadata.
        /// </summary>
        public static readonly string ExpiryDate = Utf8Constants.ToInternedString(ExpiryDateUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingAuthority"/>.</summary>
        public static ReadOnlySpan<byte> IssuingAuthorityUtf8 => "issuing_authority"u8;

        /// <summary>
        /// Name of the authority that issued the PID, or country code. Mandatory metadata.
        /// </summary>
        public static readonly string IssuingAuthority = Utf8Constants.ToInternedString(IssuingAuthorityUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingCountry"/>.</summary>
        public static ReadOnlySpan<byte> IssuingCountryUtf8 => "issuing_country"u8;

        /// <summary>
        /// ISO 3166-1 alpha-2 country code of the PID provider. Mandatory metadata.
        /// </summary>
        public static readonly string IssuingCountry = Utf8Constants.ToInternedString(IssuingCountryUtf8);

        /// <summary>The UTF-8 source literal of <see cref="DocumentNumber"/>.</summary>
        public static ReadOnlySpan<byte> DocumentNumberUtf8 => "document_number"u8;

        /// <summary>
        /// Number for the PID assigned by the provider. Optional metadata.
        /// </summary>
        public static readonly string DocumentNumber = Utf8Constants.ToInternedString(DocumentNumberUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingJurisdiction"/>.</summary>
        public static ReadOnlySpan<byte> IssuingJurisdictionUtf8 => "issuing_jurisdiction"u8;

        /// <summary>
        /// ISO 3166-2 country subdivision code of the issuing jurisdiction. Optional metadata.
        /// </summary>
        public static readonly string IssuingJurisdiction = Utf8Constants.ToInternedString(IssuingJurisdictionUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuanceDate"/>.</summary>
        public static ReadOnlySpan<byte> IssuanceDateUtf8 => "issuance_date"u8;

        /// <summary>
        /// Date (and if possible time) when the PID was issued. Optional.
        /// </summary>
        public static readonly string IssuanceDate = Utf8Constants.ToInternedString(IssuanceDateUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AgeOver18"/>.</summary>
        public static ReadOnlySpan<byte> AgeOver18Utf8 => "age_over_18"u8;

        /// <summary>
        /// Whether the PID user is currently an adult. Optional.
        /// </summary>
        public static readonly string AgeOver18 = Utf8Constants.ToInternedString(AgeOver18Utf8);

        /// <summary>The UTF-8 source literal of <see cref="AgeInYears"/>.</summary>
        public static ReadOnlySpan<byte> AgeInYearsUtf8 => "age_in_years"u8;

        /// <summary>
        /// The current age of the PID user in years. Optional.
        /// </summary>
        public static readonly string AgeInYears = Utf8Constants.ToInternedString(AgeInYearsUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AgeBirthYear"/>.</summary>
        public static ReadOnlySpan<byte> AgeBirthYearUtf8 => "age_birth_year"u8;

        /// <summary>
        /// The birth year of the PID user. Optional.
        /// </summary>
        public static readonly string AgeBirthYear = Utf8Constants.ToInternedString(AgeBirthYearUtf8);

        /// <summary>The UTF-8 source literal of <see cref="TrustAnchor"/>.</summary>
        public static ReadOnlySpan<byte> TrustAnchorUtf8 => "trust_anchor"u8;

        /// <summary>
        /// URL of a machine-readable trust anchor for verifying the PID. Optional.
        /// </summary>
        public static readonly string TrustAnchor = Utf8Constants.ToInternedString(TrustAnchorUtf8);
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
        /// <summary>The UTF-8 source literal of <see cref="FamilyName"/>.</summary>
        public static ReadOnlySpan<byte> FamilyNameUtf8 => "family_name"u8;

        /// <summary>
        /// Current last name(s) or surname(s). IANA registered claim per OIDC Section 5.1.
        /// </summary>
        public static readonly string FamilyName = Utf8Constants.ToInternedString(FamilyNameUtf8);

        /// <summary>The UTF-8 source literal of <see cref="GivenName"/>.</summary>
        public static ReadOnlySpan<byte> GivenNameUtf8 => "given_name"u8;

        /// <summary>
        /// Current first name(s), including middle name(s). IANA registered claim per OIDC Section 5.1.
        /// </summary>
        public static readonly string GivenName = Utf8Constants.ToInternedString(GivenNameUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Birthdate"/>.</summary>
        public static ReadOnlySpan<byte> BirthdateUtf8 => "birthdate"u8;

        /// <summary>
        /// Date of birth in ISO 8601-1 YYYY-MM-DD format. IANA registered claim per OIDC Section 5.1.
        /// </summary>
        public static readonly string Birthdate = Utf8Constants.ToInternedString(BirthdateUtf8);

        /// <summary>The UTF-8 source literal of <see cref="PlaceOfBirth"/>.</summary>
        public static ReadOnlySpan<byte> PlaceOfBirthUtf8 => "place_of_birth"u8;

        /// <summary>
        /// Place of birth as a JSON structure with country, region, and/or locality.
        /// Per EKYC Section 4.1.
        /// </summary>
        public static readonly string PlaceOfBirth = Utf8Constants.ToInternedString(PlaceOfBirthUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Nationalities"/>.</summary>
        public static ReadOnlySpan<byte> NationalitiesUtf8 => "nationalities"u8;

        /// <summary>
        /// Array of ISO 3166-1 alpha-2 nationality codes. Per EKYC Section 4.1.
        /// </summary>
        public static readonly string Nationalities = Utf8Constants.ToInternedString(NationalitiesUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AddressFormatted"/>.</summary>
        public static ReadOnlySpan<byte> AddressFormattedUtf8 => "address.formatted"u8;

        /// <summary>
        /// Full formatted address. Hierarchical claim under <c>address</c>. Per OIDC Section 5.1.
        /// </summary>
        public static readonly string AddressFormatted = Utf8Constants.ToInternedString(AddressFormattedUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AddressCountry"/>.</summary>
        public static ReadOnlySpan<byte> AddressCountryUtf8 => "address.country"u8;

        /// <summary>
        /// Country of residence. Hierarchical claim under <c>address</c>. Per OIDC Section 5.1.
        /// </summary>
        public static readonly string AddressCountry = Utf8Constants.ToInternedString(AddressCountryUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AddressRegion"/>.</summary>
        public static ReadOnlySpan<byte> AddressRegionUtf8 => "address.region"u8;

        /// <summary>
        /// State/province/region of residence. Hierarchical claim under <c>address</c>.
        /// </summary>
        public static readonly string AddressRegion = Utf8Constants.ToInternedString(AddressRegionUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AddressLocality"/>.</summary>
        public static ReadOnlySpan<byte> AddressLocalityUtf8 => "address.locality"u8;

        /// <summary>
        /// City of residence. Hierarchical claim under <c>address</c>.
        /// </summary>
        public static readonly string AddressLocality = Utf8Constants.ToInternedString(AddressLocalityUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AddressPostalCode"/>.</summary>
        public static ReadOnlySpan<byte> AddressPostalCodeUtf8 => "address.postal_code"u8;

        /// <summary>
        /// Postal code of residence. Hierarchical claim under <c>address</c>.
        /// </summary>
        public static readonly string AddressPostalCode = Utf8Constants.ToInternedString(AddressPostalCodeUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AddressStreetAddress"/>.</summary>
        public static ReadOnlySpan<byte> AddressStreetAddressUtf8 => "address.street_address"u8;

        /// <summary>
        /// Street address of residence. Hierarchical claim under <c>address</c>.
        /// </summary>
        public static readonly string AddressStreetAddress = Utf8Constants.ToInternedString(AddressStreetAddressUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AddressHouseNumber"/>.</summary>
        public static ReadOnlySpan<byte> AddressHouseNumberUtf8 => "address.house_number"u8;

        /// <summary>
        /// House number of residence. Hierarchical claim under <c>address</c>.
        /// </summary>
        public static readonly string AddressHouseNumber = Utf8Constants.ToInternedString(AddressHouseNumberUtf8);

        /// <summary>The UTF-8 source literal of <see cref="BirthFamilyName"/>.</summary>
        public static ReadOnlySpan<byte> BirthFamilyNameUtf8 => "birth_family_name"u8;

        /// <summary>
        /// Last name(s) at birth. Per EKYC Section 4.1.
        /// </summary>
        public static readonly string BirthFamilyName = Utf8Constants.ToInternedString(BirthFamilyNameUtf8);

        /// <summary>The UTF-8 source literal of <see cref="BirthGivenName"/>.</summary>
        public static ReadOnlySpan<byte> BirthGivenNameUtf8 => "birth_given_name"u8;

        /// <summary>
        /// First name(s) at birth. Per EKYC Section 4.1.
        /// </summary>
        public static readonly string BirthGivenName = Utf8Constants.ToInternedString(BirthGivenNameUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Email"/>.</summary>
        public static ReadOnlySpan<byte> EmailUtf8 => "email"u8;

        /// <summary>
        /// Email address. IANA registered claim per OIDC Section 5.1.
        /// </summary>
        public static readonly string Email = Utf8Constants.ToInternedString(EmailUtf8);

        /// <summary>The UTF-8 source literal of <see cref="PhoneNumber"/>.</summary>
        public static ReadOnlySpan<byte> PhoneNumberUtf8 => "phone_number"u8;

        /// <summary>
        /// Mobile phone number. IANA registered claim per OIDC Section 5.1.
        /// </summary>
        public static readonly string PhoneNumber = Utf8Constants.ToInternedString(PhoneNumberUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Picture"/>.</summary>
        public static ReadOnlySpan<byte> PictureUtf8 => "picture"u8;

        /// <summary>
        /// Portrait as a data URL with base64-encoded JPEG. IANA registered claim per OIDC Section 5.1.
        /// </summary>
        public static readonly string Picture = Utf8Constants.ToInternedString(PictureUtf8);

        /// <summary>The UTF-8 source literal of <see cref="PersonalAdministrativeNumber"/>.</summary>
        public static ReadOnlySpan<byte> PersonalAdministrativeNumberUtf8 => "personal_administrative_number"u8;

        /// <summary>
        /// A unique value assigned to the natural person by the PID provider.
        /// </summary>
        public static readonly string PersonalAdministrativeNumber = Utf8Constants.ToInternedString(PersonalAdministrativeNumberUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Sex"/>.</summary>
        public static ReadOnlySpan<byte> SexUtf8 => "sex"u8;

        /// <summary>
        /// Sex of the PID user. Numeric encoding per EUDI PID Rulebook.
        /// </summary>
        public static readonly string Sex = Utf8Constants.ToInternedString(SexUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingAuthority"/>.</summary>
        public static ReadOnlySpan<byte> IssuingAuthorityUtf8 => "issuing_authority"u8;

        /// <summary>
        /// Name of the authority that issued the PID, or country code.
        /// </summary>
        public static readonly string IssuingAuthority = Utf8Constants.ToInternedString(IssuingAuthorityUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingCountry"/>.</summary>
        public static ReadOnlySpan<byte> IssuingCountryUtf8 => "issuing_country"u8;

        /// <summary>
        /// ISO 3166-1 alpha-2 country code of the PID provider.
        /// </summary>
        public static readonly string IssuingCountry = Utf8Constants.ToInternedString(IssuingCountryUtf8);

        /// <summary>The UTF-8 source literal of <see cref="DocumentNumber"/>.</summary>
        public static ReadOnlySpan<byte> DocumentNumberUtf8 => "document_number"u8;

        /// <summary>
        /// Number for the PID assigned by the provider.
        /// </summary>
        public static readonly string DocumentNumber = Utf8Constants.ToInternedString(DocumentNumberUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingJurisdiction"/>.</summary>
        public static ReadOnlySpan<byte> IssuingJurisdictionUtf8 => "issuing_jurisdiction"u8;

        /// <summary>
        /// ISO 3166-2 country subdivision code of the issuing jurisdiction.
        /// </summary>
        public static readonly string IssuingJurisdiction = Utf8Constants.ToInternedString(IssuingJurisdictionUtf8);

        /// <summary>The UTF-8 source literal of <see cref="DateOfExpiry"/>.</summary>
        public static ReadOnlySpan<byte> DateOfExpiryUtf8 => "date_of_expiry"u8;

        /// <summary>
        /// Administrative expiry date in ISO 8601-1 YYYY-MM-DD format.
        /// Per EKYC Schema Section 5.4.4.2.
        /// </summary>
        public static readonly string DateOfExpiry = Utf8Constants.ToInternedString(DateOfExpiryUtf8);

        /// <summary>The UTF-8 source literal of <see cref="DateOfIssuance"/>.</summary>
        public static ReadOnlySpan<byte> DateOfIssuanceUtf8 => "date_of_issuance"u8;

        /// <summary>
        /// Administrative issuance date in ISO 8601-1 YYYY-MM-DD format.
        /// Per EKYC Schema Section 5.4.4.2.
        /// </summary>
        public static readonly string DateOfIssuance = Utf8Constants.ToInternedString(DateOfIssuanceUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AgeEqualOrOver"/>.</summary>
        public static ReadOnlySpan<byte> AgeEqualOrOverUtf8 => "age_equal_or_over"u8;

        /// <summary>
        /// Age attestation object. Individual ages are selectively disclosable properties
        /// (e.g., <c>age_equal_or_over.18</c>).
        /// </summary>
        public static readonly string AgeEqualOrOver = Utf8Constants.ToInternedString(AgeEqualOrOverUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AgeInYears"/>.</summary>
        public static ReadOnlySpan<byte> AgeInYearsUtf8 => "age_in_years"u8;

        /// <summary>
        /// The current age of the PID user in years.
        /// </summary>
        public static readonly string AgeInYears = Utf8Constants.ToInternedString(AgeInYearsUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AgeBirthYear"/>.</summary>
        public static ReadOnlySpan<byte> AgeBirthYearUtf8 => "age_birth_year"u8;

        /// <summary>
        /// The birth year of the PID user.
        /// </summary>
        public static readonly string AgeBirthYear = Utf8Constants.ToInternedString(AgeBirthYearUtf8);

        /// <summary>The UTF-8 source literal of <see cref="TrustAnchor"/>.</summary>
        public static ReadOnlySpan<byte> TrustAnchorUtf8 => "trust_anchor"u8;

        /// <summary>
        /// URL of a machine-readable trust anchor for verifying the PID.
        /// </summary>
        public static readonly string TrustAnchor = Utf8Constants.ToInternedString(TrustAnchorUtf8);
    }
}
