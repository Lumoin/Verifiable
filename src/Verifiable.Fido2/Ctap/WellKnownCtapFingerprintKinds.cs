namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>fingerprintKind</c> (response member <c>0x02</c>) values <c>getFingerprintSensorInfo</c>
/// reports.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, the response structure table
/// (snapshot line 6502): "For touch type sensor, its value is 1. For swipe type sensor its value is 2."
/// This simulator's own sensor is modeled as <see cref="Touch"/> (<c>CtapAuthenticatorState.FingerprintKind</c>).
/// </remarks>
public static class WellKnownCtapFingerprintKinds
{
    /// <summary>A touch-type fingerprint sensor (<c>1</c>).</summary>
    public const int Touch = 1;

    /// <summary>A swipe-type fingerprint sensor (<c>2</c>).</summary>
    public const int Swipe = 2;


    /// <summary>
    /// Gets a value indicating whether <paramref name="fingerprintKind"/> is <see cref="Touch"/>.
    /// </summary>
    /// <param name="fingerprintKind">The <c>fingerprintKind</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="fingerprintKind"/> is a touch sensor.</returns>
    public static bool IsTouch(int fingerprintKind) => fingerprintKind == Touch;

    /// <summary>
    /// Gets a value indicating whether <paramref name="fingerprintKind"/> is <see cref="Swipe"/>.
    /// </summary>
    /// <param name="fingerprintKind">The <c>fingerprintKind</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="fingerprintKind"/> is a swipe sensor.</returns>
    public static bool IsSwipe(int fingerprintKind) => fingerprintKind == Swipe;
}
