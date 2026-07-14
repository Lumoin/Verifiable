namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>subCommand</c> (<c>0x01</c>) values <c>authenticatorCredentialManagement</c> requests carry.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8: authenticatorCredentialManagement (0x0A)</see>, the subcommand table (lines
/// 6976-7003). Models all seven spec-defined numbers; every one is implementable against this
/// authenticator's existing credential store, so support is total (unlike
/// <see cref="WellKnownCtapAuthenticatorConfigSubCommands"/>'s partial-support shape) — which of them a
/// given command dispatch actually processes is a transition-level decision, not this vocabulary type's
/// own business.
/// </remarks>
public static class WellKnownCtapCredentialManagementSubCommands
{
    /// <summary>
    /// <c>getCredsMetadata</c> (<c>0x01</c>): reports the existing and estimated-remaining discoverable
    /// credential counts.
    /// </summary>
    public const int GetCredsMetadata = 0x01;

    /// <summary>
    /// <c>enumerateRPsBegin</c> (<c>0x02</c>): begins a stateful enumeration of every RP holding a
    /// discoverable credential.
    /// </summary>
    public const int EnumerateRpsBegin = 0x02;

    /// <summary>
    /// <c>enumerateRPsGetNextRP</c> (<c>0x03</c>): continues the stateful RP enumeration
    /// <see cref="EnumerateRpsBegin"/> started.
    /// </summary>
    public const int EnumerateRpsGetNextRp = 0x03;

    /// <summary>
    /// <c>enumerateCredentialsBegin</c> (<c>0x04</c>): begins a stateful enumeration of every
    /// discoverable credential for one RP.
    /// </summary>
    public const int EnumerateCredentialsBegin = 0x04;

    /// <summary>
    /// <c>enumerateCredentialsGetNextCredential</c> (<c>0x05</c>): continues the stateful credential
    /// enumeration <see cref="EnumerateCredentialsBegin"/> started.
    /// </summary>
    public const int EnumerateCredentialsGetNextCredential = 0x05;

    /// <summary><c>deleteCredential</c> (<c>0x06</c>): removes one credential from the store.</summary>
    public const int DeleteCredential = 0x06;

    /// <summary>
    /// <c>updateUserInformation</c> (<c>0x07</c>): replaces one credential's stored user
    /// <c>name</c>/<c>displayName</c>.
    /// </summary>
    public const int UpdateUserInformation = 0x07;


    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="GetCredsMetadata"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>getCredsMetadata</c>.</returns>
    public static bool IsGetCredsMetadata(int subCommand) => subCommand == GetCredsMetadata;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="EnumerateRpsBegin"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>enumerateRPsBegin</c>.</returns>
    public static bool IsEnumerateRpsBegin(int subCommand) => subCommand == EnumerateRpsBegin;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="EnumerateRpsGetNextRp"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>enumerateRPsGetNextRP</c>.</returns>
    public static bool IsEnumerateRpsGetNextRp(int subCommand) => subCommand == EnumerateRpsGetNextRp;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="EnumerateCredentialsBegin"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>enumerateCredentialsBegin</c>.</returns>
    public static bool IsEnumerateCredentialsBegin(int subCommand) => subCommand == EnumerateCredentialsBegin;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is
    /// <see cref="EnumerateCredentialsGetNextCredential"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>enumerateCredentialsGetNextCredential</c>.</returns>
    public static bool IsEnumerateCredentialsGetNextCredential(int subCommand) => subCommand == EnumerateCredentialsGetNextCredential;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="DeleteCredential"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>deleteCredential</c>.</returns>
    public static bool IsDeleteCredential(int subCommand) => subCommand == DeleteCredential;

    /// <summary>
    /// Gets a value indicating whether <paramref name="subCommand"/> is <see cref="UpdateUserInformation"/>.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value to check.</param>
    /// <returns><see langword="true"/> if <paramref name="subCommand"/> is <c>updateUserInformation</c>.</returns>
    public static bool IsUpdateUserInformation(int subCommand) => subCommand == UpdateUserInformation;
}
