namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorBioEnrollment</c> response structure.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, the response structure table
/// (snapshot lines 6484-6533) — eight members, every one Optional, a DIFFERENT set from
/// <see cref="WellKnownCtapCredentialManagementResponseKeys"/> entirely (no member number is shared with
/// the same meaning across the two commands). <see cref="TemplateInfos"/> (<c>0x07</c>) is a CBOR ARRAY
/// of nested maps (snapshot lines 6534-6553) — this codebase's first repeated-nested-map CTAP response
/// member.
/// </remarks>
public static class WellKnownCtapBioEnrollmentResponseKeys
{
    /// <summary>The <c>modality</c> member (<c>0x01</c>): the user verification modality — value 1 for fingerprint.</summary>
    public const int Modality = 0x01;

    /// <summary>The <c>fingerprintKind</c> member (<c>0x02</c>): 1 for a touch sensor, 2 for a swipe sensor.</summary>
    public const int FingerprintKind = 0x02;

    /// <summary>The <c>maxCaptureSamplesRequiredForEnroll</c> member (<c>0x03</c>): the maximum good samples an enrollment needs.</summary>
    public const int MaxCaptureSamplesRequiredForEnroll = 0x03;

    /// <summary>The <c>templateId</c> member (<c>0x04</c>): the enrollment's template identifier, minted by <c>enrollBegin</c>.</summary>
    public const int TemplateId = 0x04;

    /// <summary>The <c>lastEnrollSampleStatus</c> member (<c>0x05</c>): the most recent capture's outcome, one of <see cref="WellKnownCtapLastEnrollSampleStatuses"/>.</summary>
    public const int LastEnrollSampleStatus = 0x05;

    /// <summary>The <c>remainingSamples</c> member (<c>0x06</c>): the number of further good samples an in-progress enrollment still needs.</summary>
    public const int RemainingSamples = 0x06;

    /// <summary>The <c>templateInfos</c> member (<c>0x07</c>): the CBOR array of <c>TemplateInfo</c> maps <c>enumerateEnrollments</c> reports.</summary>
    public const int TemplateInfos = 0x07;

    /// <summary>The <c>maxTemplateFriendlyName</c> member (<c>0x08</c>): the maximum byte length this authenticator accepts for a template friendly name.</summary>
    public const int MaxTemplateFriendlyName = 0x08;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Modality"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>modality</c> key.</returns>
    public static bool IsModality(int key) => key == Modality;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="FingerprintKind"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>fingerprintKind</c> key.</returns>
    public static bool IsFingerprintKind(int key) => key == FingerprintKind;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="MaxCaptureSamplesRequiredForEnroll"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>maxCaptureSamplesRequiredForEnroll</c> key.</returns>
    public static bool IsMaxCaptureSamplesRequiredForEnroll(int key) => key == MaxCaptureSamplesRequiredForEnroll;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="TemplateId"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>templateId</c> key.</returns>
    public static bool IsTemplateId(int key) => key == TemplateId;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="LastEnrollSampleStatus"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>lastEnrollSampleStatus</c> key.</returns>
    public static bool IsLastEnrollSampleStatus(int key) => key == LastEnrollSampleStatus;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="RemainingSamples"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>remainingSamples</c> key.</returns>
    public static bool IsRemainingSamples(int key) => key == RemainingSamples;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="TemplateInfos"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>templateInfos</c> key.</returns>
    public static bool IsTemplateInfos(int key) => key == TemplateInfos;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="MaxTemplateFriendlyName"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>maxTemplateFriendlyName</c> key.</returns>
    public static bool IsMaxTemplateFriendlyName(int key) => key == MaxTemplateFriendlyName;
}
