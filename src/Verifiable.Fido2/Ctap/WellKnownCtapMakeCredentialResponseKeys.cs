namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorMakeCredential</c> response structure's members.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see>'s response structure. Note this
/// integer-keyed CTAP envelope is a distinct wire shape from the text-keyed WebAuthn
/// <c>attestationObject</c> (<c>fmt</c>/<c>attStmt</c>/<c>authData</c> only) a client translates it
/// into; the two share member names but not key types or member sets.
/// </remarks>
public static class WellKnownCtapMakeCredentialResponseKeys
{
    /// <summary>The <c>fmt</c> member (<c>0x01</c>, Required): the attestation statement format identifier.</summary>
    public const int Fmt = 0x01;

    /// <summary>The <c>authData</c> member (<c>0x02</c>, Required): the raw authenticator data bytes.</summary>
    public const int AuthData = 0x02;

    /// <summary>The <c>attStmt</c> member (<c>0x03</c>, Optional): the format-specific attestation statement map.</summary>
    public const int AttStmt = 0x03;

    /// <summary>
    /// The <c>epAtt</c> member (<c>0x04</c>, Optional): whether an enterprise attestation was returned
    /// (CTAP 2.3 §7.1, waveep R6/R9). Set to <see langword="true"/> exactly when mc Step 9 grants an
    /// enterprise attestation; this authenticator never emits an explicit <see langword="false"/> for
    /// this member (trap 18), though the writer faithfully round-trips one if given it.
    /// </summary>
    public const int EpAtt = 0x04;

    /// <summary>The <c>largeBlobKey</c> member (<c>0x05</c>, Optional): the freshly minted credential's largeBlobKey extension output (CTAP 2.3 §12.3, line 12853), present iff requested and <c>rk</c> is true.</summary>
    public const int LargeBlobKey = 0x05;

    /// <summary>The <c>unsignedExtensionOutputs</c> member (<c>0x06</c>, Optional): unsigned extension outputs. Not modeled this wave.</summary>
    public const int UnsignedExtensionOutputs = 0x06;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Fmt"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>fmt</c> key.</returns>
    public static bool IsFmt(int key) => key == Fmt;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="AuthData"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>authData</c> key.</returns>
    public static bool IsAuthData(int key) => key == AuthData;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="AttStmt"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>attStmt</c> key.</returns>
    public static bool IsAttStmt(int key) => key == AttStmt;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="EpAtt"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>epAtt</c> key.</returns>
    public static bool IsEpAtt(int key) => key == EpAtt;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="LargeBlobKey"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>largeBlobKey</c> key.</returns>
    public static bool IsLargeBlobKey(int key) => key == LargeBlobKey;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="UnsignedExtensionOutputs"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>unsignedExtensionOutputs</c> key.</returns>
    public static bool IsUnsignedExtensionOutputs(int key) => key == UnsignedExtensionOutputs;
}
