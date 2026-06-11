using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography.Text;

namespace Verifiable.JCose.Eudi;

/// <summary>
/// Well-known constants for the mobile driving licence (mDL) attestation
/// within the EUDI Wallet ecosystem.
/// </summary>
/// <remarks>
/// <para>
/// The mDL data model is fully specified in ISO/IEC 18013-5. Mobile driving licences
/// within the EUDI Wallet ecosystem are issued exclusively in mso_mdoc format; SD-JWT VC
/// encoding is not used for mDLs per the proposed EC Regulation 2023/127
/// (4th Driving Licence Regulation).
/// </para>
/// <para>
/// See <see href="https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/mdl/mdl-rulebook.md">mDL Rulebook</see>
/// and <see href="https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog">Attestation Rulebooks Catalog</see>.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "This groups together EUDI mDL constants.")]
public static class EudiMdl
{
    /// <summary>The UTF-8 source literal of <see cref="Doctype"/>.</summary>
    public static ReadOnlySpan<byte> DoctypeUtf8 => "org.iso.18013.5.1.mDL"u8;

    /// <summary>
    /// The document type for mobile driving licences per ISO/IEC 18013-5.
    /// </summary>
    public static readonly string Doctype = Utf8Constants.ToInternedString(DoctypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Namespace"/>.</summary>
    public static ReadOnlySpan<byte> NamespaceUtf8 => "org.iso.18013.5.1"u8;

    /// <summary>
    /// The primary namespace for mDL attributes per ISO/IEC 18013-5.
    /// </summary>
    public static readonly string Namespace = Utf8Constants.ToInternedString(NamespaceUtf8);

    /// <summary>
    /// Attribute identifiers for the ISO/IEC 18013-5 mDL namespace.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These identifiers are defined in ISO/IEC 18013-5, Section 7.2.1, Table 5.
    /// They are used in presentation requests and responses within the
    /// <see cref="Namespace"/> (<c>org.iso.18013.5.1</c>).
    /// </para>
    /// </remarks>
    public static class Attributes
    {
        /// <summary>The UTF-8 source literal of <see cref="FamilyName"/>.</summary>
        public static ReadOnlySpan<byte> FamilyNameUtf8 => "family_name"u8;

        /// <summary>
        /// Last name, surname, or primary identifier of the mDL holder.
        /// </summary>
        public static readonly string FamilyName = Utf8Constants.ToInternedString(FamilyNameUtf8);

        /// <summary>The UTF-8 source literal of <see cref="GivenName"/>.</summary>
        public static ReadOnlySpan<byte> GivenNameUtf8 => "given_name"u8;

        /// <summary>
        /// First name(s), other name(s), or secondary identifier of the mDL holder.
        /// </summary>
        public static readonly string GivenName = Utf8Constants.ToInternedString(GivenNameUtf8);

        /// <summary>The UTF-8 source literal of <see cref="BirthDate"/>.</summary>
        public static ReadOnlySpan<byte> BirthDateUtf8 => "birth_date"u8;

        /// <summary>
        /// Day, month, and year on which the mDL holder was born.
        /// </summary>
        public static readonly string BirthDate = Utf8Constants.ToInternedString(BirthDateUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssueDate"/>.</summary>
        public static ReadOnlySpan<byte> IssueDateUtf8 => "issue_date"u8;

        /// <summary>
        /// Date when the document was issued.
        /// </summary>
        public static readonly string IssueDate = Utf8Constants.ToInternedString(IssueDateUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ExpiryDate"/>.</summary>
        public static ReadOnlySpan<byte> ExpiryDateUtf8 => "expiry_date"u8;

        /// <summary>
        /// Date when the document expires.
        /// </summary>
        public static readonly string ExpiryDate = Utf8Constants.ToInternedString(ExpiryDateUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingCountry"/>.</summary>
        public static ReadOnlySpan<byte> IssuingCountryUtf8 => "issuing_country"u8;

        /// <summary>
        /// Alpha-2 country code as defined in ISO 3166-1 of the issuing authority's country.
        /// </summary>
        public static readonly string IssuingCountry = Utf8Constants.ToInternedString(IssuingCountryUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingAuthority"/>.</summary>
        public static ReadOnlySpan<byte> IssuingAuthorityUtf8 => "issuing_authority"u8;

        /// <summary>
        /// Issuing authority name or code.
        /// </summary>
        public static readonly string IssuingAuthority = Utf8Constants.ToInternedString(IssuingAuthorityUtf8);

        /// <summary>The UTF-8 source literal of <see cref="DocumentNumber"/>.</summary>
        public static ReadOnlySpan<byte> DocumentNumberUtf8 => "document_number"u8;

        /// <summary>
        /// The number assigned to the mDL.
        /// </summary>
        public static readonly string DocumentNumber = Utf8Constants.ToInternedString(DocumentNumberUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Portrait"/>.</summary>
        public static ReadOnlySpan<byte> PortraitUtf8 => "portrait"u8;

        /// <summary>
        /// A reproduction of the mDL holder's portrait.
        /// </summary>
        public static readonly string Portrait = Utf8Constants.ToInternedString(PortraitUtf8);

        /// <summary>The UTF-8 source literal of <see cref="DrivingPrivileges"/>.</summary>
        public static ReadOnlySpan<byte> DrivingPrivilegesUtf8 => "driving_privileges"u8;

        /// <summary>
        /// Driving privileges of the mDL holder.
        /// </summary>
        public static readonly string DrivingPrivileges = Utf8Constants.ToInternedString(DrivingPrivilegesUtf8);

        /// <summary>The UTF-8 source literal of <see cref="UnDistinguishingSign"/>.</summary>
        public static ReadOnlySpan<byte> UnDistinguishingSignUtf8 => "un_distinguishing_sign"u8;

        /// <summary>
        /// Distinguishing sign of the issuing country per the 1949 and 1968 conventions.
        /// </summary>
        public static readonly string UnDistinguishingSign = Utf8Constants.ToInternedString(UnDistinguishingSignUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AdministrativeNumber"/>.</summary>
        public static ReadOnlySpan<byte> AdministrativeNumberUtf8 => "administrative_number"u8;

        /// <summary>
        /// Administrative number of the mDL.
        /// </summary>
        public static readonly string AdministrativeNumber = Utf8Constants.ToInternedString(AdministrativeNumberUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Sex"/>.</summary>
        public static ReadOnlySpan<byte> SexUtf8 => "sex"u8;

        /// <summary>
        /// Sex of the mDL holder per ISO/IEC 5218.
        /// </summary>
        public static readonly string Sex = Utf8Constants.ToInternedString(SexUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Height"/>.</summary>
        public static ReadOnlySpan<byte> HeightUtf8 => "height"u8;

        /// <summary>
        /// Height of the mDL holder in centimetres.
        /// </summary>
        public static readonly string Height = Utf8Constants.ToInternedString(HeightUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Weight"/>.</summary>
        public static ReadOnlySpan<byte> WeightUtf8 => "weight"u8;

        /// <summary>
        /// Weight of the mDL holder in kilograms.
        /// </summary>
        public static readonly string Weight = Utf8Constants.ToInternedString(WeightUtf8);

        /// <summary>The UTF-8 source literal of <see cref="EyeColour"/>.</summary>
        public static ReadOnlySpan<byte> EyeColourUtf8 => "eye_colour"u8;

        /// <summary>
        /// Eye colour of the mDL holder.
        /// </summary>
        public static readonly string EyeColour = Utf8Constants.ToInternedString(EyeColourUtf8);

        /// <summary>The UTF-8 source literal of <see cref="HairColour"/>.</summary>
        public static ReadOnlySpan<byte> HairColourUtf8 => "hair_colour"u8;

        /// <summary>
        /// Hair colour of the mDL holder.
        /// </summary>
        public static readonly string HairColour = Utf8Constants.ToInternedString(HairColourUtf8);

        /// <summary>The UTF-8 source literal of <see cref="BirthPlace"/>.</summary>
        public static ReadOnlySpan<byte> BirthPlaceUtf8 => "birth_place"u8;

        /// <summary>
        /// Country of birth as an ISO 3166-1 alpha-2 code.
        /// </summary>
        public static readonly string BirthPlace = Utf8Constants.ToInternedString(BirthPlaceUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ResidentAddress"/>.</summary>
        public static ReadOnlySpan<byte> ResidentAddressUtf8 => "resident_address"u8;

        /// <summary>
        /// Country and municipality or state/province where the mDL holder lives.
        /// </summary>
        public static readonly string ResidentAddress = Utf8Constants.ToInternedString(ResidentAddressUtf8);

        /// <summary>The UTF-8 source literal of <see cref="PortraitCaptureDate"/>.</summary>
        public static ReadOnlySpan<byte> PortraitCaptureDateUtf8 => "portrait_capture_date"u8;

        /// <summary>
        /// Date of the portrait capture.
        /// </summary>
        public static readonly string PortraitCaptureDate = Utf8Constants.ToInternedString(PortraitCaptureDateUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AgeOver18"/>.</summary>
        public static ReadOnlySpan<byte> AgeOver18Utf8 => "age_over_18"u8;

        /// <summary>
        /// Whether the mDL holder is at least 18 years old. Per ISO/IEC 18013-5, Section 7.2.5.
        /// </summary>
        public static readonly string AgeOver18 = Utf8Constants.ToInternedString(AgeOver18Utf8);

        /// <summary>The UTF-8 source literal of <see cref="AgeOver21"/>.</summary>
        public static ReadOnlySpan<byte> AgeOver21Utf8 => "age_over_21"u8;

        /// <summary>
        /// Whether the mDL holder is at least 21 years old. Per ISO/IEC 18013-5, Section 7.2.5.
        /// </summary>
        public static readonly string AgeOver21 = Utf8Constants.ToInternedString(AgeOver21Utf8);

        /// <summary>The UTF-8 source literal of <see cref="AgeInYears"/>.</summary>
        public static ReadOnlySpan<byte> AgeInYearsUtf8 => "age_in_years"u8;

        /// <summary>
        /// The age of the mDL holder in years.
        /// </summary>
        public static readonly string AgeInYears = Utf8Constants.ToInternedString(AgeInYearsUtf8);

        /// <summary>The UTF-8 source literal of <see cref="AgeBirthYear"/>.</summary>
        public static ReadOnlySpan<byte> AgeBirthYearUtf8 => "age_birth_year"u8;

        /// <summary>
        /// The birth year of the mDL holder.
        /// </summary>
        public static readonly string AgeBirthYear = Utf8Constants.ToInternedString(AgeBirthYearUtf8);

        /// <summary>The UTF-8 source literal of <see cref="IssuingJurisdiction"/>.</summary>
        public static ReadOnlySpan<byte> IssuingJurisdictionUtf8 => "issuing_jurisdiction"u8;

        /// <summary>
        /// Country subdivision code of the issuing jurisdiction per ISO 3166-2.
        /// </summary>
        public static readonly string IssuingJurisdiction = Utf8Constants.ToInternedString(IssuingJurisdictionUtf8);

        /// <summary>The UTF-8 source literal of <see cref="Nationality"/>.</summary>
        public static ReadOnlySpan<byte> NationalityUtf8 => "nationality"u8;

        /// <summary>
        /// Nationality of the mDL holder as an ISO 3166-1 alpha-2 code.
        /// </summary>
        public static readonly string Nationality = Utf8Constants.ToInternedString(NationalityUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ResidentCity"/>.</summary>
        public static ReadOnlySpan<byte> ResidentCityUtf8 => "resident_city"u8;

        /// <summary>
        /// City where the mDL holder lives.
        /// </summary>
        public static readonly string ResidentCity = Utf8Constants.ToInternedString(ResidentCityUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ResidentState"/>.</summary>
        public static ReadOnlySpan<byte> ResidentStateUtf8 => "resident_state"u8;

        /// <summary>
        /// State, province, or district where the mDL holder lives.
        /// </summary>
        public static readonly string ResidentState = Utf8Constants.ToInternedString(ResidentStateUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ResidentPostalCode"/>.</summary>
        public static ReadOnlySpan<byte> ResidentPostalCodeUtf8 => "resident_postal_code"u8;

        /// <summary>
        /// Postal code of the mDL holder's place of residence.
        /// </summary>
        public static readonly string ResidentPostalCode = Utf8Constants.ToInternedString(ResidentPostalCodeUtf8);

        /// <summary>The UTF-8 source literal of <see cref="ResidentCountry"/>.</summary>
        public static ReadOnlySpan<byte> ResidentCountryUtf8 => "resident_country"u8;

        /// <summary>
        /// Country where the mDL holder lives as an ISO 3166-1 alpha-2 code.
        /// </summary>
        public static readonly string ResidentCountry = Utf8Constants.ToInternedString(ResidentCountryUtf8);

        /// <summary>The UTF-8 source literal of <see cref="FamilyNameNationalCharacter"/>.</summary>
        public static ReadOnlySpan<byte> FamilyNameNationalCharacterUtf8 => "family_name_national_character"u8;

        /// <summary>
        /// Last name of the mDL holder at birth.
        /// </summary>
        public static readonly string FamilyNameNationalCharacter = Utf8Constants.ToInternedString(FamilyNameNationalCharacterUtf8);

        /// <summary>The UTF-8 source literal of <see cref="GivenNameNationalCharacter"/>.</summary>
        public static ReadOnlySpan<byte> GivenNameNationalCharacterUtf8 => "given_name_national_character"u8;

        /// <summary>
        /// First name of the mDL holder using national characters.
        /// </summary>
        public static readonly string GivenNameNationalCharacter = Utf8Constants.ToInternedString(GivenNameNationalCharacterUtf8);

        /// <summary>The UTF-8 source literal of <see cref="SignatureUsualMark"/>.</summary>
        public static ReadOnlySpan<byte> SignatureUsualMarkUtf8 => "signature_usual_mark"u8;

        /// <summary>
        /// Image of the mDL holder's signature or usual mark.
        /// </summary>
        public static readonly string SignatureUsualMark = Utf8Constants.ToInternedString(SignatureUsualMarkUtf8);
    }
}
