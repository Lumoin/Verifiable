namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>subCommand</c> (<c>0x02</c>) values <c>authenticatorBioEnrollment</c> requests carry for the
/// <see cref="WellKnownCtapBioEnrollmentModalities.Fingerprint"/> modality.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, the subcommand table (snapshot lines
/// 6430-6458). Models all seven spec-defined numbers. <see cref="GetFingerprintSensorInfo"/> and
/// <see cref="CancelCurrentEnrollment"/> are token-free (no <c>pinUvAuthParam</c> is ever sent for
/// either); the remaining five require a <c>be</c>-scoped <c>pinUvAuthToken</c>.
/// </remarks>
public static class WellKnownCtapBioEnrollmentSubCommands
{
    /// <summary>
    /// <c>enrollBegin</c> (<c>0x01</c>): starts a new fingerprint enrollment, auto-cancelling any
    /// unfinished one, and performs the first sample capture.
    /// </summary>
    public const int EnrollBegin = 0x01;

    /// <summary>
    /// <c>enrollCaptureNextSample</c> (<c>0x02</c>): continues the enrollment <see cref="EnrollBegin"/>
    /// started, capturing the next sample.
    /// </summary>
    public const int EnrollCaptureNextSample = 0x02;

    /// <summary>
    /// <c>cancelCurrentEnrollment</c> (<c>0x03</c>): cancels the current in-progress enrollment, if any.
    /// Token-free; always <c>CTAP2_OK</c> (snapshot line 6799).
    /// </summary>
    public const int CancelCurrentEnrollment = 0x03;

    /// <summary><c>enumerateEnrollments</c> (<c>0x04</c>): lists every provisioned fingerprint template.</summary>
    public const int EnumerateEnrollments = 0x04;

    /// <summary><c>setFriendlyName</c> (<c>0x05</c>): renames a provisioned template's friendly name.</summary>
    public const int SetFriendlyName = 0x05;

    /// <summary><c>removeEnrollment</c> (<c>0x06</c>): deletes a provisioned template.</summary>
    public const int RemoveEnrollment = 0x06;

    /// <summary>
    /// <c>getFingerprintSensorInfo</c> (<c>0x07</c>): reports the sensor's kind, maximum capture
    /// samples required for enrollment, and maximum accepted friendly-name byte length. Token-free.
    /// </summary>
    public const int GetFingerprintSensorInfo = 0x07;


    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="EnrollBegin"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>enrollBegin</c>.</returns>
    public static bool IsEnrollBegin(int subCommand) => subCommand == EnrollBegin;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="EnrollCaptureNextSample"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>enrollCaptureNextSample</c>.</returns>
    public static bool IsEnrollCaptureNextSample(int subCommand) => subCommand == EnrollCaptureNextSample;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="CancelCurrentEnrollment"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>cancelCurrentEnrollment</c>.</returns>
    public static bool IsCancelCurrentEnrollment(int subCommand) => subCommand == CancelCurrentEnrollment;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="EnumerateEnrollments"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>enumerateEnrollments</c>.</returns>
    public static bool IsEnumerateEnrollments(int subCommand) => subCommand == EnumerateEnrollments;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="SetFriendlyName"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>setFriendlyName</c>.</returns>
    public static bool IsSetFriendlyName(int subCommand) => subCommand == SetFriendlyName;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="RemoveEnrollment"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>removeEnrollment</c>.</returns>
    public static bool IsRemoveEnrollment(int subCommand) => subCommand == RemoveEnrollment;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="GetFingerprintSensorInfo"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>getFingerprintSensorInfo</c>.</returns>
    public static bool IsGetFingerprintSensorInfo(int subCommand) => subCommand == GetFingerprintSensorInfo;
}
