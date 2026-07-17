namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>modality</c> (<c>0x01</c>) values <c>authenticatorBioEnrollment</c> requests/responses carry.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, the modality table (snapshot lines
/// 6419-6428): "The type of modalities supported are as under:" — exactly one registered value.
/// Distinct from <c>uvModality</c>'s (getInfo member <c>0x12</c>) FIDO Registry bit-flag vocabulary,
/// which enumerates several built-in user-verification METHODS (fingerprint being one bit among
/// several); this type enumerates <c>authenticatorBioEnrollment</c>'s own single-valued modality field.
/// </remarks>
public static class WellKnownCtapBioEnrollmentModalities
{
    /// <summary>
    /// <c>fingerprint</c> (<c>0x01</c>): the only registered <c>authenticatorBioEnrollment</c> modality.
    /// </summary>
    public const int Fingerprint = 0x01;


    /// <summary>
    /// Gets a value indicating whether <paramref name="modality"/> is <see cref="Fingerprint"/>.
    /// </summary>
    /// <param name="modality">The <c>modality</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="modality"/> is <c>fingerprint</c>.</returns>
    public static bool IsFingerprint(int modality) => modality == Fingerprint;
}
