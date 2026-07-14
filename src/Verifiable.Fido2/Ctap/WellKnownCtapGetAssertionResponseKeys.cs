namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorGetAssertion</c> response structure's members.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2: authenticatorGetAssertion (0x02)</see>'s response structure.
/// <see cref="NumberOfCredentials"/> is present only when more than one applicable credential is found
/// for the RP and the authenticator has no display or both UV and UP are false — this headless
/// simulator's only reachable case is the latter — and is omitted again on every
/// <c>authenticatorGetNextAssertion</c> response that follows.
/// </remarks>
public static class WellKnownCtapGetAssertionResponseKeys
{
    /// <summary>The <c>credential</c> member (<c>0x01</c>, Required): the <c>PublicKeyCredentialDescriptor</c> of the asserted credential.</summary>
    public const int Credential = 0x01;

    /// <summary>The <c>authData</c> member (<c>0x02</c>, Required): the signed-over authenticator data bytes.</summary>
    public const int AuthData = 0x02;

    /// <summary>The <c>signature</c> member (<c>0x03</c>, Required): the assertion signature.</summary>
    public const int Signature = 0x03;

    /// <summary>The <c>user</c> member (<c>0x04</c>, Optional): the <c>PublicKeyCredentialUserEntity</c>; at least <c>id</c> is mandatory for a discoverable credential asserted without <c>allowList</c>.</summary>
    public const int User = 0x04;

    /// <summary>The <c>numberOfCredentials</c> member (<c>0x05</c>, Optional): total applicable-credential count; defaults to one. See remarks for when it is present.</summary>
    public const int NumberOfCredentials = 0x05;

    /// <summary>The <c>userSelected</c> member (<c>0x06</c>, Optional): whether the user selected the credential via direct authenticator interaction. Never emitted by a headless authenticator.</summary>
    public const int UserSelected = 0x06;

    /// <summary>The <c>largeBlobKey</c> member (<c>0x07</c>, Optional): the asserted credential's largeBlobKey extension output (CTAP 2.3 §12.3, line 12867), present iff requested and the credential carries a key.</summary>
    public const int LargeBlobKey = 0x07;

    /// <summary>The <c>unsignedExtensionOutputs</c> member (<c>0x08</c>, Optional): unsigned extension outputs. Not modeled this wave.</summary>
    public const int UnsignedExtensionOutputs = 0x08;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Credential"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>credential</c> key.</returns>
    public static bool IsCredential(int key) => key == Credential;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="AuthData"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>authData</c> key.</returns>
    public static bool IsAuthData(int key) => key == AuthData;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Signature"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>signature</c> key.</returns>
    public static bool IsSignature(int key) => key == Signature;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="User"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>user</c> key.</returns>
    public static bool IsUser(int key) => key == User;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="NumberOfCredentials"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>numberOfCredentials</c> key.</returns>
    public static bool IsNumberOfCredentials(int key) => key == NumberOfCredentials;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="UserSelected"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>userSelected</c> key.</returns>
    public static bool IsUserSelected(int key) => key == UserSelected;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="LargeBlobKey"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>largeBlobKey</c> key.</returns>
    public static bool IsLargeBlobKey(int key) => key == LargeBlobKey;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="UnsignedExtensionOutputs"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>unsignedExtensionOutputs</c> key.</returns>
    public static bool IsUnsignedExtensionOutputs(int key) => key == UnsignedExtensionOutputs;
}
