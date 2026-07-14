namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorConfig</c> request structure's top-level members.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorConfig">
/// CTAP 2.3, section 6.11: authenticatorConfig (0x0D)</see>, the input parameter table (lines
/// 7883-7907).
/// </remarks>
public static class WellKnownCtapAuthenticatorConfigRequestKeys
{
    /// <summary>The <c>subCommand</c> parameter (<c>0x01</c>, Required): the subCommand currently being requested, one of <see cref="WellKnownCtapAuthenticatorConfigSubCommands"/>.</summary>
    public const int SubCommand = 0x01;

    /// <summary>The <c>subCommandParams</c> parameter (<c>0x02</c>, Optional): a CBOR map of the selected subCommand's own parameters.</summary>
    public const int SubCommandParams = 0x02;

    /// <summary>The <c>pinUvAuthProtocol</c> parameter (<c>0x03</c>, Optional): the PIN/UV auth protocol version the platform selected.</summary>
    public const int PinUvAuthProtocol = 0x03;

    /// <summary>The <c>pinUvAuthParam</c> parameter (<c>0x04</c>, Optional): the output of calling <c>authenticate</c> on a subcommand-specific context.</summary>
    public const int PinUvAuthParam = 0x04;


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
}
