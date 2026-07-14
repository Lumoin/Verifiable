namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>lastEnrollSampleStatus</c> (response member <c>0x05</c>) values a fingerprint capture attempt
/// can report.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, the <c>lastEnrollSampleStatus</c>
/// types table (snapshot lines 6554-6621). Every value here is a FIELD value inside a successful
/// <c>CTAP2_OK</c> response, never a CTAP2 protocol-level error code — a failed or poor-quality capture
/// is still a successful <c>enrollBegin</c>/<c>enrollCaptureNextSample</c> response whose
/// <see cref="Good"/>-or-not value is carried here. <c>0x0C</c> is deliberately absent: the spec's own
/// table marks it "(this error number is available)" (snapshot line 6613) — a genuine registered gap,
/// not an omission this type fills.
/// </remarks>
public static class WellKnownCtapLastEnrollSampleStatuses
{
    /// <summary><c>CTAP2_ENROLL_FEEDBACK_FP_GOOD</c> (<c>0x00</c>): good fingerprint capture.</summary>
    public const int Good = 0x00;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_FP_TOO_HIGH</c> (<c>0x01</c>): fingerprint was too high.</summary>
    public const int TooHigh = 0x01;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_FP_TOO_LOW</c> (<c>0x02</c>): fingerprint was too low.</summary>
    public const int TooLow = 0x02;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_FP_TOO_LEFT</c> (<c>0x03</c>): fingerprint was too left.</summary>
    public const int TooLeft = 0x03;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_FP_TOO_RIGHT</c> (<c>0x04</c>): fingerprint was too right.</summary>
    public const int TooRight = 0x04;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_FP_TOO_FAST</c> (<c>0x05</c>): fingerprint was too fast.</summary>
    public const int TooFast = 0x05;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_FP_TOO_SLOW</c> (<c>0x06</c>): fingerprint was too slow.</summary>
    public const int TooSlow = 0x06;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_FP_POOR_QUALITY</c> (<c>0x07</c>): fingerprint was of poor quality.</summary>
    public const int PoorQuality = 0x07;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_FP_TOO_SKEWED</c> (<c>0x08</c>): fingerprint was too skewed.</summary>
    public const int TooSkewed = 0x08;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_FP_TOO_SHORT</c> (<c>0x09</c>): fingerprint was too short.</summary>
    public const int TooShort = 0x09;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_FP_MERGE_FAILURE</c> (<c>0x0A</c>): merge failure of the capture.</summary>
    public const int MergeFailure = 0x0A;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_FP_EXISTS</c> (<c>0x0B</c>): fingerprint already exists.</summary>
    public const int Exists = 0x0B;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_NO_USER_ACTIVITY</c> (<c>0x0D</c>): user did not touch/swipe the authenticator.</summary>
    public const int NoUserActivity = 0x0D;

    /// <summary><c>CTAP2_ENROLL_FEEDBACK_NO_USER_PRESENCE_TRANSITION</c> (<c>0x0E</c>): user did not lift the finger off the sensor.</summary>
    public const int NoUserPresenceTransition = 0x0E;


    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="Good"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_FP_GOOD</c>.</returns>
    public static bool IsGood(int status) => status == Good;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="TooHigh"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_FP_TOO_HIGH</c>.</returns>
    public static bool IsTooHigh(int status) => status == TooHigh;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="TooLow"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_FP_TOO_LOW</c>.</returns>
    public static bool IsTooLow(int status) => status == TooLow;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="TooLeft"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_FP_TOO_LEFT</c>.</returns>
    public static bool IsTooLeft(int status) => status == TooLeft;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="TooRight"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_FP_TOO_RIGHT</c>.</returns>
    public static bool IsTooRight(int status) => status == TooRight;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="TooFast"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_FP_TOO_FAST</c>.</returns>
    public static bool IsTooFast(int status) => status == TooFast;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="TooSlow"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_FP_TOO_SLOW</c>.</returns>
    public static bool IsTooSlow(int status) => status == TooSlow;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="PoorQuality"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_FP_POOR_QUALITY</c>.</returns>
    public static bool IsPoorQuality(int status) => status == PoorQuality;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="TooSkewed"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_FP_TOO_SKEWED</c>.</returns>
    public static bool IsTooSkewed(int status) => status == TooSkewed;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="TooShort"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_FP_TOO_SHORT</c>.</returns>
    public static bool IsTooShort(int status) => status == TooShort;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="MergeFailure"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_FP_MERGE_FAILURE</c>.</returns>
    public static bool IsMergeFailure(int status) => status == MergeFailure;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="Exists"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_FP_EXISTS</c>.</returns>
    public static bool IsExists(int status) => status == Exists;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="NoUserActivity"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_NO_USER_ACTIVITY</c>.</returns>
    public static bool IsNoUserActivity(int status) => status == NoUserActivity;

    /// <summary>Gets a value indicating whether <paramref name="status"/> is <see cref="NoUserPresenceTransition"/>.</summary>
    /// <param name="status">The <c>lastEnrollSampleStatus</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="status"/> is <c>CTAP2_ENROLL_FEEDBACK_NO_USER_PRESENCE_TRANSITION</c>.</returns>
    public static bool IsNoUserPresenceTransition(int status) => status == NoUserPresenceTransition;
}
