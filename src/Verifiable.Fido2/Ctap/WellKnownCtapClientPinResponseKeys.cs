namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorClientPIN</c> response structure's members.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">
/// CTAP 2.3, section 6.5.5: authenticatorClientPIN (0x06) Command Definition</see>, the response
/// parameter table. Every member is modeled so a later wave's token-issuing subcommands extend data,
/// not structure — this wave's authenticator emits only <see cref="KeyAgreement"/>,
/// <see cref="PinRetries"/>, and <see cref="UvRetries"/>.
/// </remarks>
public static class WellKnownCtapClientPinResponseKeys
{
    /// <summary>
    /// The <c>keyAgreement</c> member (<c>0x01</c>, Optional): the authenticator's key-agreement
    /// COSE_Key, the result of calling <c>getPublicKey</c> for the selected protocol. MUST carry the
    /// optional <c>alg</c> parameter and MUST NOT carry any other optional parameter.
    /// </summary>
    public const int KeyAgreement = 0x01;

    /// <summary>The <c>pinUvAuthToken</c> member (<c>0x02</c>, Optional): the issued token, encrypted under the shared secret.</summary>
    public const int PinUvAuthToken = 0x02;

    /// <summary>The <c>pinRetries</c> member (<c>0x03</c>, Optional): the number of PIN attempts remaining before lockout.</summary>
    public const int PinRetries = 0x03;

    /// <summary>
    /// The <c>powerCycleState</c> member (<c>0x04</c>, Optional): present and <see langword="true"/>
    /// if a power cycle is required before any future PIN operation. Only valid on a
    /// <c>getPINRetries</c> response.
    /// </summary>
    public const int PowerCycleState = 0x04;

    /// <summary>The <c>uvRetries</c> member (<c>0x05</c>, Optional): the number of built-in-UV attempts remaining before lockout.</summary>
    public const int UvRetries = 0x05;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="KeyAgreement"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>keyAgreement</c> key.</returns>
    public static bool IsKeyAgreement(int key) => key == KeyAgreement;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinUvAuthToken"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinUvAuthToken</c> key.</returns>
    public static bool IsPinUvAuthToken(int key) => key == PinUvAuthToken;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinRetries"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinRetries</c> key.</returns>
    public static bool IsPinRetries(int key) => key == PinRetries;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PowerCycleState"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>powerCycleState</c> key.</returns>
    public static bool IsPowerCycleState(int key) => key == PowerCycleState;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="UvRetries"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>uvRetries</c> key.</returns>
    public static bool IsUvRetries(int key) => key == UvRetries;
}
