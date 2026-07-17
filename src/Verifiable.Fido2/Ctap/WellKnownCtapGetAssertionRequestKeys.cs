namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorGetAssertion</c> request structure's members.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2: authenticatorGetAssertion (0x02)</see> assigns each input parameter a
/// small integer key.
/// </remarks>
public static class WellKnownCtapGetAssertionRequestKeys
{
    /// <summary>The <c>rpId</c> parameter (<c>0x01</c>, Required): the relying party identifier string.</summary>
    public const int RpId = 0x01;

    /// <summary>The <c>clientDataHash</c> parameter (<c>0x02</c>, Required): a byte string.</summary>
    public const int ClientDataHash = 0x02;

    /// <summary>
    /// The <c>allowList</c> parameter (<c>0x03</c>, Optional): an array of <c>PublicKeyCredentialDescriptor</c>;
    /// a platform MUST NOT send an empty <c>allowList</c> — it MUST be omitted instead.
    /// </summary>
    public const int AllowList = 0x03;

    /// <summary>The <c>extensions</c> parameter (<c>0x04</c>, Optional): an extension-identifier-keyed CBOR map.</summary>
    public const int Extensions = 0x04;

    /// <summary>
    /// The <c>options</c> parameter (<c>0x05</c>, Optional): a map of boolean-valued authenticator
    /// options; the platform MUST NOT send the <c>rk</c> option key at all here.
    /// </summary>
    public const int Options = 0x05;

    /// <summary>The <c>pinUvAuthParam</c> parameter (<c>0x06</c>, Optional): a byte string, ClientPIN-only.</summary>
    public const int PinUvAuthParam = 0x06;

    /// <summary>The <c>pinUvAuthProtocol</c> parameter (<c>0x07</c>, Optional): an unsigned integer, ClientPIN-only.</summary>
    public const int PinUvAuthProtocol = 0x07;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="RpId"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>rpId</c> key.</returns>
    public static bool IsRpId(int key) => key == RpId;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="ClientDataHash"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>clientDataHash</c> key.</returns>
    public static bool IsClientDataHash(int key) => key == ClientDataHash;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="AllowList"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>allowList</c> key.</returns>
    public static bool IsAllowList(int key) => key == AllowList;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Extensions"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>extensions</c> key.</returns>
    public static bool IsExtensions(int key) => key == Extensions;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Options"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>options</c> key.</returns>
    public static bool IsOptions(int key) => key == Options;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinUvAuthParam"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinUvAuthParam</c> key.</returns>
    public static bool IsPinUvAuthParam(int key) => key == PinUvAuthParam;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinUvAuthProtocol"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinUvAuthProtocol</c> key.</returns>
    public static bool IsPinUvAuthProtocol(int key) => key == PinUvAuthProtocol;
}
