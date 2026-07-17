namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorCredentialManagement</c> response structure.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8: authenticatorCredentialManagement (0x0A)</see>, the response structure table
/// (lines 7026-7081). Every constant from <c>0x01</c> through <c>0x0C</c> is modeled for wire
/// completeness. <see cref="CredProtect"/> IS emitted, carrying the enumerated credential's real
/// persisted level (R11) — <c>CtapCredentialManagementResponse.CredProtect</c> is the corresponding
/// field. <see cref="LargeBlobKey"/> IS emitted, carrying the enumerated credential's real stored
/// largeBlobKey when present (wavelb R8) — <c>CtapCredentialManagementResponse.LargeBlobKey</c> is the
/// corresponding field. <see cref="ThirdPartyPayment"/> remains NEVER emitted by this profile (no
/// third-party payment state is modeled, mirroring how
/// <c>WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.PinComplexityPolicy</c> models a key this
/// authenticator never emits), so <c>CtapCredentialManagementResponse</c> carries no field for it.
/// </remarks>
public static class WellKnownCtapCredentialManagementResponseKeys
{
    /// <summary>The <c>existingResidentCredentialsCount</c> member (<c>0x01</c>): the total number of discoverable credentials on the authenticator.</summary>
    public const int ExistingResidentCredentialsCount = 0x01;

    /// <summary>The <c>maxPossibleRemainingResidentCredentialsCount</c> member (<c>0x02</c>): the estimated number of additional discoverable credentials that can still be created.</summary>
    public const int MaxPossibleRemainingResidentCredentialsCount = 0x02;

    /// <summary>The <c>rp</c> member (<c>0x03</c>): the <c>PublicKeyCredentialRpEntity</c> an enumeration step reports.</summary>
    public const int Rp = 0x03;

    /// <summary>The <c>rpIDHash</c> member (<c>0x04</c>): the RP ID SHA-256 hash paired with <see cref="Rp"/>.</summary>
    public const int RpIdHash = 0x04;

    /// <summary>The <c>totalRPs</c> member (<c>0x05</c>): the total number of RPs holding a discoverable credential, reported once by <c>enumerateRPsBegin</c>.</summary>
    public const int TotalRps = 0x05;

    /// <summary>The <c>user</c> member (<c>0x06</c>): the <c>PublicKeyCredentialUserEntity</c> an enumeration step reports.</summary>
    public const int User = 0x06;

    /// <summary>The <c>credentialID</c> member (<c>0x07</c>): the <c>PublicKeyCredentialDescriptor</c> an enumeration step reports.</summary>
    public const int CredentialId = 0x07;

    /// <summary>The <c>publicKey</c> member (<c>0x08</c>): the credential's public key in COSE_Key form.</summary>
    public const int PublicKey = 0x08;

    /// <summary>The <c>totalCredentials</c> member (<c>0x09</c>): the total number of credentials for the enumerated RP, reported once by <c>enumerateCredentialsBegin</c>.</summary>
    public const int TotalCredentials = 0x09;

    /// <summary>
    /// The <c>credProtect</c> member (<c>0x0A</c>): the credential's credential protection policy.
    /// Emitted with the credential's real persisted level (CTAP 2.3 §12.1, R11).
    /// </summary>
    public const int CredProtect = 0x0A;

    /// <summary>
    /// The <c>largeBlobKey</c> member (<c>0x0B</c>): the credential's large blob encryption key, if
    /// any (CTAP 2.3 §12.3, lines 7312/7341). Emitted with the credential's real stored key when one
    /// exists (wavelb R8).
    /// </summary>
    public const int LargeBlobKey = 0x0B;

    /// <summary>
    /// The <c>thirdPartyPayment</c> member (<c>0x0C</c>): whether the credential is third-party
    /// payment enabled. NEVER emitted by this profile (the <c>thirdPartyPayment</c> extension is not
    /// modeled).
    /// </summary>
    public const int ThirdPartyPayment = 0x0C;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="ExistingResidentCredentialsCount"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>existingResidentCredentialsCount</c> key.</returns>
    public static bool IsExistingResidentCredentialsCount(int key) => key == ExistingResidentCredentialsCount;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="MaxPossibleRemainingResidentCredentialsCount"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>maxPossibleRemainingResidentCredentialsCount</c> key.</returns>
    public static bool IsMaxPossibleRemainingResidentCredentialsCount(int key) => key == MaxPossibleRemainingResidentCredentialsCount;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Rp"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>rp</c> key.</returns>
    public static bool IsRp(int key) => key == Rp;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="RpIdHash"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>rpIDHash</c> key.</returns>
    public static bool IsRpIdHash(int key) => key == RpIdHash;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="TotalRps"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>totalRPs</c> key.</returns>
    public static bool IsTotalRps(int key) => key == TotalRps;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="User"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>user</c> key.</returns>
    public static bool IsUser(int key) => key == User;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="CredentialId"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>credentialID</c> key.</returns>
    public static bool IsCredentialId(int key) => key == CredentialId;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PublicKey"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>publicKey</c> key.</returns>
    public static bool IsPublicKey(int key) => key == PublicKey;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="TotalCredentials"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>totalCredentials</c> key.</returns>
    public static bool IsTotalCredentials(int key) => key == TotalCredentials;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="CredProtect"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>credProtect</c> key.</returns>
    public static bool IsCredProtect(int key) => key == CredProtect;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="LargeBlobKey"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>largeBlobKey</c> key.</returns>
    public static bool IsLargeBlobKey(int key) => key == LargeBlobKey;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="ThirdPartyPayment"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>thirdPartyPayment</c> key.</returns>
    public static bool IsThirdPartyPayment(int key) => key == ThirdPartyPayment;
}
