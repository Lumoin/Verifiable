namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorClientPIN</c> request structure's members.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">
/// CTAP 2.3, section 6.5.5: authenticatorClientPIN (0x06) Command Definition</see>, the request
/// parameter table. Every member is modeled (not just the three this wave's read-only subcommands
/// use) so a later wave's <c>setPIN</c>/<c>changePIN</c>/token-issuing subcommands extend data, not
/// structure.
/// </remarks>
public static class WellKnownCtapClientPinRequestKeys
{
    /// <summary>
    /// The <c>pinUvAuthProtocol</c> parameter (<c>0x01</c>, Optional): the PIN/UV auth protocol
    /// version the platform selected. Contextually Required for <c>getKeyAgreement</c> (selects
    /// which protocol's key-agreement public key to report) and every subcommand that verifies a
    /// <c>pinUvAuthParam</c>.
    /// </summary>
    public const int PinUvAuthProtocol = 0x01;

    /// <summary>The <c>subCommand</c> parameter (<c>0x02</c>, Required): the requested action, one of <see cref="WellKnownCtapClientPinSubCommands"/>.</summary>
    public const int SubCommand = 0x02;

    /// <summary>
    /// The <c>keyAgreement</c> parameter (<c>0x03</c>, Optional): the platform's key-agreement
    /// COSE_Key. MUST carry the optional <c>alg</c> parameter and MUST NOT carry any other optional
    /// parameter.
    /// </summary>
    public const int KeyAgreement = 0x03;

    /// <summary>The <c>pinUvAuthParam</c> parameter (<c>0x04</c>, Optional): the output of calling <c>authenticate</c> on a subcommand-specific context.</summary>
    public const int PinUvAuthParam = 0x04;

    /// <summary>The <c>newPinEnc</c> parameter (<c>0x05</c>, Optional): an encrypted PIN.</summary>
    public const int NewPinEnc = 0x05;

    /// <summary>The <c>pinHashEnc</c> parameter (<c>0x06</c>, Optional): an encrypted proof-of-knowledge of a PIN.</summary>
    public const int PinHashEnc = 0x06;

    /// <summary>The <c>permissions</c> parameter (<c>0x09</c>, Optional): a bitfield of requested permissions. MUST NOT be 0 if present.</summary>
    public const int Permissions = 0x09;

    /// <summary>The <c>rpId</c> parameter (<c>0x0A</c>, Optional): the relying party identifier to assign as the permissions RP ID.</summary>
    public const int RpId = 0x0A;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinUvAuthProtocol"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinUvAuthProtocol</c> key.</returns>
    public static bool IsPinUvAuthProtocol(int key) => key == PinUvAuthProtocol;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="SubCommand"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>subCommand</c> key.</returns>
    public static bool IsSubCommand(int key) => key == SubCommand;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="KeyAgreement"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>keyAgreement</c> key.</returns>
    public static bool IsKeyAgreement(int key) => key == KeyAgreement;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinUvAuthParam"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinUvAuthParam</c> key.</returns>
    public static bool IsPinUvAuthParam(int key) => key == PinUvAuthParam;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="NewPinEnc"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>newPinEnc</c> key.</returns>
    public static bool IsNewPinEnc(int key) => key == NewPinEnc;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinHashEnc"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinHashEnc</c> key.</returns>
    public static bool IsPinHashEnc(int key) => key == PinHashEnc;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Permissions"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>permissions</c> key.</returns>
    public static bool IsPermissions(int key) => key == Permissions;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="RpId"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>rpId</c> key.</returns>
    public static bool IsRpId(int key) => key == RpId;
}
