namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of <c>authenticatorCredentialManagement</c>'s <c>subCommandParams</c> map.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8: authenticatorCredentialManagement (0x0A)</see>, the <c>subCommandParams</c>
/// fields table (lines 7005-7024). Each member is used by a different subset of subcommands:
/// <c>enumerateCredentialsBegin</c> sends <see cref="RpIdHash"/> alone; <c>deleteCredential</c> sends
/// <see cref="CredentialId"/> alone; <c>updateUserInformation</c> sends BOTH <see cref="CredentialId"/>
/// and <see cref="User"/>.
/// </remarks>
public static class WellKnownCtapCredentialManagementSubCommandParamsKeys
{
    /// <summary>The <c>rpIDHash</c> member (<c>0x01</c>): the RP ID SHA-256 hash <c>enumerateCredentialsBegin</c> scopes its enumeration to.</summary>
    public const int RpIdHash = 0x01;

    /// <summary>The <c>credentialID</c> member (<c>0x02</c>): the <c>PublicKeyCredentialDescriptor</c> of the credential being addressed.</summary>
    public const int CredentialId = 0x02;

    /// <summary>The <c>user</c> member (<c>0x03</c>): the <c>PublicKeyCredentialUserEntity</c> carrying <c>updateUserInformation</c>'s replacement <c>name</c>/<c>displayName</c>.</summary>
    public const int User = 0x03;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="RpIdHash"/>.</summary>
    /// <param name="key">The subCommandParams map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>rpIDHash</c> key.</returns>
    public static bool IsRpIdHash(int key) => key == RpIdHash;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="CredentialId"/>.</summary>
    /// <param name="key">The subCommandParams map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>credentialID</c> key.</returns>
    public static bool IsCredentialId(int key) => key == CredentialId;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="User"/>.</summary>
    /// <param name="key">The subCommandParams map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>user</c> key.</returns>
    public static bool IsUser(int key) => key == User;
}
