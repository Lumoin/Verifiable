namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorBioEnrollment</c> request structure's top-level
/// members.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, the input parameter table (snapshot
/// lines 6386-6417). SIX top-level members, every one Optional — a genuinely different numbering from
/// <see cref="WellKnownCtapCredentialManagementRequestKeys"/>'s four keys: a leading <see cref="Modality"/>
/// (<c>0x01</c>) shifts <c>subCommand</c>/<c>subCommandParams</c>/<c>pinUvAuthProtocol</c>/
/// <c>pinUvAuthParam</c> up by one key position each, and a sixth member, <see cref="GetModality"/>
/// (<c>0x06</c>), has no credential-management analogue at all.
/// </remarks>
public static class WellKnownCtapBioEnrollmentRequestKeys
{
    /// <summary>
    /// The <c>modality</c> parameter (<c>0x01</c>): the user verification modality being requested. The
    /// only registered value is <see cref="WellKnownCtapBioEnrollmentModalities.Fingerprint"/>.
    /// </summary>
    public const int Modality = 0x01;

    /// <summary>
    /// The <c>subCommand</c> parameter (<c>0x02</c>): the authenticator user verification sub command
    /// currently being requested, one of <see cref="WellKnownCtapBioEnrollmentSubCommands"/>.
    /// </summary>
    public const int SubCommand = 0x02;

    /// <summary>
    /// The <c>subCommandParams</c> parameter (<c>0x03</c>): a CBOR map of the selected subCommand's own
    /// parameters (snapshot line 6400 — MAY be omitted when the subCommand takes no arguments).
    /// </summary>
    public const int SubCommandParams = 0x03;

    /// <summary>The <c>pinUvAuthProtocol</c> parameter (<c>0x04</c>): the PIN/UV auth protocol version the platform selected.</summary>
    public const int PinUvAuthProtocol = 0x04;

    /// <summary>The <c>pinUvAuthParam</c> parameter (<c>0x05</c>): the output of calling <c>authenticate</c> on a subcommand-specific context.</summary>
    public const int PinUvAuthParam = 0x05;

    /// <summary>
    /// The <c>getModality</c> parameter (<c>0x06</c>): a boolean requesting the bio modality read
    /// (<see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
    /// §6.7.2</see>, snapshot line 6417 — the platform's own send-value MUST be <see langword="true"/>).
    /// The only field this flow sends: no <see cref="Modality"/>, <see cref="SubCommand"/>,
    /// <see cref="PinUvAuthProtocol"/>, or <see cref="PinUvAuthParam"/> accompanies it.
    /// </summary>
    public const int GetModality = 0x06;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Modality"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>modality</c> key.</returns>
    public static bool IsModality(int key) => key == Modality;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="SubCommand"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>subCommand</c> key.</returns>
    public static bool IsSubCommand(int key) => key == SubCommand;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="SubCommandParams"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>subCommandParams</c> key.</returns>
    public static bool IsSubCommandParams(int key) => key == SubCommandParams;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinUvAuthProtocol"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinUvAuthProtocol</c> key.</returns>
    public static bool IsPinUvAuthProtocol(int key) => key == PinUvAuthProtocol;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinUvAuthParam"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinUvAuthParam</c> key.</returns>
    public static bool IsPinUvAuthParam(int key) => key == PinUvAuthParam;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="GetModality"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>getModality</c> key.</returns>
    public static bool IsGetModality(int key) => key == GetModality;
}
