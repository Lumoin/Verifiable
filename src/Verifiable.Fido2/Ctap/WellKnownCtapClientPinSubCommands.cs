namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>subCommand</c> (<c>0x02</c>) values <c>authenticatorClientPIN</c> requests carry.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">
/// CTAP 2.3, section 6.5.5: authenticatorClientPIN (0x06) Command Definition</see>, the "authenticatorClientPIN
/// subCommands" table. This authenticator handles all seven registered values: <see cref="GetPinRetries"/>,
/// <see cref="GetKeyAgreement"/>, <see cref="SetPin"/>, <see cref="ChangePin"/>,
/// <see cref="GetPinToken"/>, <see cref="GetPinUvAuthTokenUsingUvWithPermissions"/>,
/// <see cref="GetUvRetries"/>, and <see cref="GetPinUvAuthTokenUsingPinWithPermissions"/>; any
/// out-of-table value reaches <see cref="WellKnownCtapStatusCodes.InvalidSubcommand"/> per the general
/// unsupported-subcommand step.
/// </remarks>
public static class WellKnownCtapClientPinSubCommands
{
    /// <summary>
    /// <c>getPINRetries</c> (<c>0x01</c>): reports the remaining PIN attempts before lockout. No
    /// parameters; a pure state read.
    /// </summary>
    public const int GetPinRetries = 0x01;

    /// <summary>
    /// <c>getKeyAgreement</c> (<c>0x02</c>): reports the authenticator's key-agreement public key for
    /// the requested <c>pinUvAuthProtocol</c>, so the platform can perform <c>encapsulate</c>.
    /// </summary>
    public const int GetKeyAgreement = 0x02;

    /// <summary>
    /// <c>setPIN</c> (<c>0x03</c>): establishes a PIN for the first time (CTAP 2.3 §6.5.5.5).
    /// </summary>
    public const int SetPin = 0x03;

    /// <summary>
    /// <c>changePIN</c> (<c>0x04</c>): changes an already-established PIN (CTAP 2.3 §6.5.5.6).
    /// </summary>
    public const int ChangePin = 0x04;

    /// <summary>
    /// <c>getPinToken</c> (<c>0x05</c>, superseded): the CTAP2.0-era way to obtain a
    /// <c>pinUvAuthToken</c> (CTAP 2.3 §6.5.5.7.1).
    /// </summary>
    public const int GetPinToken = 0x05;

    /// <summary>
    /// <c>getPinUvAuthTokenUsingUvWithPermissions</c> (<c>0x06</c>): obtains a permissions-scoped
    /// <c>pinUvAuthToken</c> via built-in user verification (CTAP 2.3 §6.5.5.7.3's seventeen-step
    /// algorithm), gated on at least one provisioned fingerprint enrollment
    /// (<see cref="Authenticator.Automata.CtapAuthenticatorState.HasProvisionedBioEnrollments"/>).
    /// </summary>
    public const int GetPinUvAuthTokenUsingUvWithPermissions = 0x06;

    /// <summary>
    /// <c>getUVRetries</c> (<c>0x07</c>): reports the remaining built-in-UV attempts before lockout.
    /// No parameters; a pure state read.
    /// </summary>
    public const int GetUvRetries = 0x07;

    /// <summary>
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c> (<c>0x09</c>): obtains a permissions-scoped
    /// <c>pinUvAuthToken</c> via the PIN (CTAP 2.3 §6.5.5.7.2).
    /// </summary>
    public const int GetPinUvAuthTokenUsingPinWithPermissions = 0x09;


    /// <summary>Gets a value indicating whether <paramref name="subCommand"/> is <see cref="GetPinRetries"/>.</summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>getPINRetries</c>.</returns>
    public static bool IsGetPinRetries(int subCommand) => subCommand == GetPinRetries;

    /// <summary>Gets a value indicating whether <paramref name="subCommand"/> is <see cref="GetKeyAgreement"/>.</summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>getKeyAgreement</c>.</returns>
    public static bool IsGetKeyAgreement(int subCommand) => subCommand == GetKeyAgreement;

    /// <summary>Gets a value indicating whether <paramref name="subCommand"/> is <see cref="SetPin"/>.</summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>setPIN</c>.</returns>
    public static bool IsSetPin(int subCommand) => subCommand == SetPin;

    /// <summary>Gets a value indicating whether <paramref name="subCommand"/> is <see cref="ChangePin"/>.</summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>changePIN</c>.</returns>
    public static bool IsChangePin(int subCommand) => subCommand == ChangePin;

    /// <summary>Gets a value indicating whether <paramref name="subCommand"/> is <see cref="GetPinToken"/>.</summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>getPinToken</c>.</returns>
    public static bool IsGetPinToken(int subCommand) => subCommand == GetPinToken;

    /// <summary>Gets a value indicating whether <paramref name="subCommand"/> is <see cref="GetPinUvAuthTokenUsingUvWithPermissions"/>.</summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>getPinUvAuthTokenUsingUvWithPermissions</c>.</returns>
    public static bool IsGetPinUvAuthTokenUsingUvWithPermissions(int subCommand) => subCommand == GetPinUvAuthTokenUsingUvWithPermissions;

    /// <summary>Gets a value indicating whether <paramref name="subCommand"/> is <see cref="GetUvRetries"/>.</summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>getUVRetries</c>.</returns>
    public static bool IsGetUvRetries(int subCommand) => subCommand == GetUvRetries;

    /// <summary>Gets a value indicating whether <paramref name="subCommand"/> is <see cref="GetPinUvAuthTokenUsingPinWithPermissions"/>.</summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>getPinUvAuthTokenUsingPinWithPermissions</c>.</returns>
    public static bool IsGetPinUvAuthTokenUsingPinWithPermissions(int subCommand) => subCommand == GetPinUvAuthTokenUsingPinWithPermissions;
}
