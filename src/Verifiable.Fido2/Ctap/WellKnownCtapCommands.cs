namespace Verifiable.Fido2.Ctap;

/// <summary>
/// CTAP2 authenticator API command bytes: the first byte of every CTAP2 request envelope.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#commands">
/// CTAP 2.3, section 8.1: Command Codes</see> assigns one command byte per authenticator API
/// operation: <see cref="MakeCredential"/>, <see cref="GetAssertion"/>, <see cref="GetInfo"/>,
/// <see cref="ClientPin"/>, <see cref="Reset"/>, <see cref="GetNextAssertion"/>,
/// <see cref="BioEnrollment"/>, <see cref="CredentialManagement"/>, <see cref="LargeBlobs"/>, and
/// <see cref="AuthenticatorConfig"/>. Per
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding">
/// section 8: Message Encoding</see>'s "If an authenticator receives a command code it does not
/// implement, it MUST return CTAP1_ERR_INVALID_COMMAND" rule, the authenticator simulator's
/// catch-all dispatch arm already implements for any command not registered here.
/// </remarks>
public static class WellKnownCtapCommands
{
    /// <summary>
    /// <c>authenticatorMakeCredential</c> (<c>0x01</c>): creates a new public key credential and
    /// returns an attestation statement over it.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
    /// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see>.
    /// </remarks>
    public const byte MakeCredential = 0x01;

    /// <summary>
    /// <c>authenticatorGetAssertion</c> (<c>0x02</c>): produces an authentication assertion for an
    /// existing public key credential.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
    /// CTAP 2.3, section 6.2: authenticatorGetAssertion (0x02)</see>.
    /// </remarks>
    public const byte GetAssertion = 0x02;

    /// <summary>
    /// <c>authenticatorGetInfo</c> (<c>0x04</c>): reports the authenticator's supported versions,
    /// AAGUID, and capabilities. Takes no input parameters.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo">
    /// CTAP 2.3, section 6.4: authenticatorGetInfo (0x04)</see>.
    /// </remarks>
    public const byte GetInfo = 0x04;

    /// <summary>
    /// <c>authenticatorClientPIN</c> (<c>0x06</c>): performs PIN/UV auth protocol key agreement, PIN
    /// establishment/maintenance, and <c>pinUvAuthToken</c> issuance via both the PIN path
    /// (<c>getPinUvAuthTokenUsingPinWithPermissions</c>) and the built-in-UV path
    /// (<c>getPinUvAuthTokenUsingUvWithPermissions</c>). All seven registered subcommands are
    /// implemented; see <see cref="WellKnownCtapClientPinSubCommands"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">
    /// CTAP 2.3, section 6.5: authenticatorClientPIN (0x06)</see>.
    /// </remarks>
    public const byte ClientPin = 0x06;

    /// <summary>
    /// <c>authenticatorReset</c> (<c>0x07</c>): resets the authenticator to a factory default state,
    /// destroying every generated credential and reverting the clientPIN/config state that section
    /// 6.6's own "factory default state" phrase entails. Takes no input parameters — the bare command
    /// byte alone is the whole request.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorReset">
    /// CTAP 2.3, section 6.6: authenticatorReset (0x07)</see>. Line 6326's per-transport MAY is
    /// exercised: this simulator supports the command unconditionally on its one modeled transport.
    /// Line 6327's "at least one transport" SHOULD is followed by the same fact; its USB-HID-specific
    /// SHOULD and line 6328's vendor-alternate MUST both have a false antecedent here (no USB HID
    /// transport is modeled, and the command IS supported), so neither is exercised as live behavior.
    /// </remarks>
    public const byte Reset = 0x07;

    /// <summary>
    /// <c>authenticatorGetNextAssertion</c> (<c>0x08</c>): obtains the next per-credential signature
    /// following an <c>authenticatorGetAssertion</c> response whose <c>numberOfCredentials</c> member
    /// exceeded one. Takes no input parameters. A stateful command (CTAP 2.3, section 6.3).
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetNextAssertion">
    /// CTAP 2.3, section 6.3: authenticatorGetNextAssertion (0x08)</see>.
    /// </remarks>
    public const byte GetNextAssertion = 0x08;

    /// <summary>
    /// <c>authenticatorBioEnrollment</c> (<c>0x09</c>): provisions, enumerates, renames, and deletes
    /// fingerprint enrollments through its seven subcommands, plus the token-free <c>getModality</c>
    /// bio-modality read. Only implemented once <c>bioEnroll</c> is advertised in
    /// <c>authenticatorGetInfo</c> (this simulator always advertises the option, present tri-state on
    /// enrollment count).
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
    /// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>.
    /// </remarks>
    public const byte BioEnrollment = 0x09;

    /// <summary>
    /// <c>authenticatorCredentialManagement</c> (<c>0x0A</c>): manages discoverable credentials on the
    /// authenticator through seven subcommands (metadata, RP/credential enumeration, deletion, user
    /// information update). Only implemented once <c>credMgmt</c> is advertised <see langword="true"/>
    /// in <c>authenticatorGetInfo</c> (this simulator advertises it unconditionally).
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
    /// CTAP 2.3, section 6.8: authenticatorCredentialManagement (0x0A)</see>.
    /// </remarks>
    public const byte CredentialManagement = 0x0A;

    /// <summary>
    /// <c>authenticatorLargeBlobs</c> (<c>0x0C</c>): reads and writes the authenticator's serialized
    /// large-blob array — an opaque, checksum-guarded byte string the authenticator stores and returns
    /// substrings of, never parsing its contents. <c>get</c> is fully served unconditionally (reads are
    /// deliberately public, no <c>pinUvAuthToken</c> is ever accepted on that path); <c>set</c> is a
    /// conditionally-gated, multi-fragment write. Only implemented once <c>largeBlobs</c> is advertised
    /// <see langword="true"/> in <c>authenticatorGetInfo</c> (this simulator advertises it
    /// unconditionally).
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs">
    /// CTAP 2.3, section 6.10: authenticatorLargeBlobs (0x0C)</see>.
    /// </remarks>
    public const byte LargeBlobs = 0x0C;

    /// <summary>
    /// <c>authenticatorConfig</c> (<c>0x0D</c>): configures authenticator features (<c>toggleAlwaysUv</c>,
    /// <c>setMinPINLength</c>) through its subcommands. Only implemented once <c>authnrCfg</c> is
    /// advertised <see langword="true"/> in <c>authenticatorGetInfo</c> (this simulator advertises it
    /// unconditionally).
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorConfig">
    /// CTAP 2.3, section 6.11: authenticatorConfig (0x0D)</see>.
    /// </remarks>
    public const byte AuthenticatorConfig = 0x0D;


    /// <summary>
    /// Gets a value indicating whether <paramref name="commandByte"/> is <see cref="MakeCredential"/>.
    /// </summary>
    /// <param name="commandByte">The CTAP2 command byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="commandByte"/> is <c>authenticatorMakeCredential</c>.</returns>
    public static bool IsMakeCredential(byte commandByte) => commandByte == MakeCredential;

    /// <summary>
    /// Gets a value indicating whether <paramref name="commandByte"/> is <see cref="GetAssertion"/>.
    /// </summary>
    /// <param name="commandByte">The CTAP2 command byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="commandByte"/> is <c>authenticatorGetAssertion</c>.</returns>
    public static bool IsGetAssertion(byte commandByte) => commandByte == GetAssertion;

    /// <summary>
    /// Gets a value indicating whether <paramref name="commandByte"/> is <see cref="GetInfo"/>.
    /// </summary>
    /// <param name="commandByte">The CTAP2 command byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="commandByte"/> is <c>authenticatorGetInfo</c>.</returns>
    public static bool IsGetInfo(byte commandByte) => commandByte == GetInfo;

    /// <summary>
    /// Gets a value indicating whether <paramref name="commandByte"/> is <see cref="ClientPin"/>.
    /// </summary>
    /// <param name="commandByte">The CTAP2 command byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="commandByte"/> is <c>authenticatorClientPIN</c>.</returns>
    public static bool IsClientPin(byte commandByte) => commandByte == ClientPin;

    /// <summary>
    /// Gets a value indicating whether <paramref name="commandByte"/> is <see cref="Reset"/>.
    /// </summary>
    /// <param name="commandByte">The CTAP2 command byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="commandByte"/> is <c>authenticatorReset</c>.</returns>
    public static bool IsReset(byte commandByte) => commandByte == Reset;

    /// <summary>
    /// Gets a value indicating whether <paramref name="commandByte"/> is <see cref="GetNextAssertion"/>.
    /// </summary>
    /// <param name="commandByte">The CTAP2 command byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="commandByte"/> is <c>authenticatorGetNextAssertion</c>.</returns>
    public static bool IsGetNextAssertion(byte commandByte) => commandByte == GetNextAssertion;

    /// <summary>
    /// Gets a value indicating whether <paramref name="commandByte"/> is <see cref="BioEnrollment"/>.
    /// </summary>
    /// <param name="commandByte">The CTAP2 command byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="commandByte"/> is <c>authenticatorBioEnrollment</c>.</returns>
    public static bool IsBioEnrollment(byte commandByte) => commandByte == BioEnrollment;

    /// <summary>
    /// Gets a value indicating whether <paramref name="commandByte"/> is <see cref="CredentialManagement"/>.
    /// </summary>
    /// <param name="commandByte">The CTAP2 command byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="commandByte"/> is <c>authenticatorCredentialManagement</c>.</returns>
    public static bool IsCredentialManagement(byte commandByte) => commandByte == CredentialManagement;

    /// <summary>
    /// Gets a value indicating whether <paramref name="commandByte"/> is <see cref="LargeBlobs"/>.
    /// </summary>
    /// <param name="commandByte">The CTAP2 command byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="commandByte"/> is <c>authenticatorLargeBlobs</c>.</returns>
    public static bool IsLargeBlobs(byte commandByte) => commandByte == LargeBlobs;

    /// <summary>
    /// Gets a value indicating whether <paramref name="commandByte"/> is <see cref="AuthenticatorConfig"/>.
    /// </summary>
    /// <param name="commandByte">The CTAP2 command byte to check.</param>
    /// <returns><see langword="true"/> if <paramref name="commandByte"/> is <c>authenticatorConfig</c>.</returns>
    public static bool IsAuthenticatorConfig(byte commandByte) => commandByte == AuthenticatorConfig;
}
