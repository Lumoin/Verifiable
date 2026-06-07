using System.Diagnostics.CodeAnalysis;

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
    /// <summary>
    /// The document type for mobile driving licences per ISO/IEC 18013-5.
    /// </summary>
    public static readonly string Doctype = "org.iso.18013.5.1.mDL";

    /// <summary>
    /// The primary namespace for mDL attributes per ISO/IEC 18013-5.
    /// </summary>
    public static readonly string Namespace = "org.iso.18013.5.1";

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
        /// <summary>
        /// Last name, surname, or primary identifier of the mDL holder.
        /// </summary>
        public static readonly string FamilyName = "family_name";

        /// <summary>
        /// First name(s), other name(s), or secondary identifier of the mDL holder.
        /// </summary>
        public static readonly string GivenName = "given_name";

        /// <summary>
        /// Day, month, and year on which the mDL holder was born.
        /// </summary>
        public static readonly string BirthDate = "birth_date";

        /// <summary>
        /// Date when the document was issued.
        /// </summary>
        public static readonly string IssueDate = "issue_date";

        /// <summary>
        /// Date when the document expires.
        /// </summary>
        public static readonly string ExpiryDate = "expiry_date";

        /// <summary>
        /// Alpha-2 country code as defined in ISO 3166-1 of the issuing authority's country.
        /// </summary>
        public static readonly string IssuingCountry = "issuing_country";

        /// <summary>
        /// Issuing authority name or code.
        /// </summary>
        public static readonly string IssuingAuthority = "issuing_authority";

        /// <summary>
        /// The number assigned to the mDL.
        /// </summary>
        public static readonly string DocumentNumber = "document_number";

        /// <summary>
        /// A reproduction of the mDL holder's portrait.
        /// </summary>
        public static readonly string Portrait = "portrait";

        /// <summary>
        /// Driving privileges of the mDL holder.
        /// </summary>
        public static readonly string DrivingPrivileges = "driving_privileges";

        /// <summary>
        /// Distinguishing sign of the issuing country per the 1949 and 1968 conventions.
        /// </summary>
        public static readonly string UnDistinguishingSign = "un_distinguishing_sign";

        /// <summary>
        /// Administrative number of the mDL.
        /// </summary>
        public static readonly string AdministrativeNumber = "administrative_number";

        /// <summary>
        /// Sex of the mDL holder per ISO/IEC 5218.
        /// </summary>
        public static readonly string Sex = "sex";

        /// <summary>
        /// Height of the mDL holder in centimetres.
        /// </summary>
        public static readonly string Height = "height";

        /// <summary>
        /// Weight of the mDL holder in kilograms.
        /// </summary>
        public static readonly string Weight = "weight";

        /// <summary>
        /// Eye colour of the mDL holder.
        /// </summary>
        public static readonly string EyeColour = "eye_colour";

        /// <summary>
        /// Hair colour of the mDL holder.
        /// </summary>
        public static readonly string HairColour = "hair_colour";

        /// <summary>
        /// Country of birth as an ISO 3166-1 alpha-2 code.
        /// </summary>
        public static readonly string BirthPlace = "birth_place";

        /// <summary>
        /// Country and municipality or state/province where the mDL holder lives.
        /// </summary>
        public static readonly string ResidentAddress = "resident_address";

        /// <summary>
        /// Date of the portrait capture.
        /// </summary>
        public static readonly string PortraitCaptureDate = "portrait_capture_date";

        /// <summary>
        /// Whether the mDL holder is at least 18 years old. Per ISO/IEC 18013-5, Section 7.2.5.
        /// </summary>
        public static readonly string AgeOver18 = "age_over_18";

        /// <summary>
        /// Whether the mDL holder is at least 21 years old. Per ISO/IEC 18013-5, Section 7.2.5.
        /// </summary>
        public static readonly string AgeOver21 = "age_over_21";

        /// <summary>
        /// The age of the mDL holder in years.
        /// </summary>
        public static readonly string AgeInYears = "age_in_years";

        /// <summary>
        /// The birth year of the mDL holder.
        /// </summary>
        public static readonly string AgeBirthYear = "age_birth_year";

        /// <summary>
        /// Country subdivision code of the issuing jurisdiction per ISO 3166-2.
        /// </summary>
        public static readonly string IssuingJurisdiction = "issuing_jurisdiction";

        /// <summary>
        /// Nationality of the mDL holder as an ISO 3166-1 alpha-2 code.
        /// </summary>
        public static readonly string Nationality = "nationality";

        /// <summary>
        /// City where the mDL holder lives.
        /// </summary>
        public static readonly string ResidentCity = "resident_city";

        /// <summary>
        /// State, province, or district where the mDL holder lives.
        /// </summary>
        public static readonly string ResidentState = "resident_state";

        /// <summary>
        /// Postal code of the mDL holder's place of residence.
        /// </summary>
        public static readonly string ResidentPostalCode = "resident_postal_code";

        /// <summary>
        /// Country where the mDL holder lives as an ISO 3166-1 alpha-2 code.
        /// </summary>
        public static readonly string ResidentCountry = "resident_country";

        /// <summary>
        /// Last name of the mDL holder at birth.
        /// </summary>
        public static readonly string FamilyNameNationalCharacter = "family_name_national_character";

        /// <summary>
        /// First name of the mDL holder using national characters.
        /// </summary>
        public static readonly string GivenNameNationalCharacter = "given_name_national_character";

        /// <summary>
        /// Image of the mDL holder's signature or usual mark.
        /// </summary>
        public static readonly string SignatureUsualMark = "signature_usual_mark";
    }
}
