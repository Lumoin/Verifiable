namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>hmac-secret</c>/<c>hmac-secret-mc</c> extension's compound
/// authenticator input map.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-extension">
/// CTAP 2.3, section 12.7: HMAC Secret Extension (hmac-secret)</see>, snapshot lines 13228-13248: the
/// <c>authenticatorGetAssertion</c> request's <c>"hmac-secret"</c> extension value is itself a CBOR map
/// keyed by these four small integers, not a scalar — the SAME shape section 12.8 (snapshot line
/// 13402) reuses verbatim for <c>"hmac-secret-mc"</c>'s own <c>authenticatorMakeCredential</c> input.
/// </remarks>
public static class WellKnownCtapHmacSecretExtensionKeys
{
    /// <summary>The <c>keyAgreement</c> member (<c>0x01</c>, Required): the platform's key-agreement COSE_Key.</summary>
    public const int KeyAgreement = 0x01;

    /// <summary>
    /// The <c>saltEnc</c> member (<c>0x02</c>, Required): <c>encrypt(sharedSecret, salt1)</c> (one salt)
    /// or <c>encrypt(sharedSecret, salt1 || salt2)</c> (two salts).
    /// </summary>
    public const int SaltEnc = 0x02;

    /// <summary>The <c>saltAuth</c> member (<c>0x03</c>, Required): <c>authenticate(sharedSecret, saltEnc)</c>.</summary>
    public const int SaltAuth = 0x03;

    /// <summary>
    /// The <c>pinUvAuthProtocol</c> member (<c>0x04</c>, Optional): the PIN/UV auth protocol the shared
    /// secret was established under. Snapshot line 13246: platforms MUST include it whenever the
    /// selected protocol is not protocol one; absence defaults to protocol one (snapshot line 13279).
    /// </summary>
    public const int PinUvAuthProtocol = 0x04;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="KeyAgreement"/>.</summary>
    /// <param name="key">The extension input map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>keyAgreement</c> key.</returns>
    public static bool IsKeyAgreement(int key) => key == KeyAgreement;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="SaltEnc"/>.</summary>
    /// <param name="key">The extension input map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>saltEnc</c> key.</returns>
    public static bool IsSaltEnc(int key) => key == SaltEnc;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="SaltAuth"/>.</summary>
    /// <param name="key">The extension input map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>saltAuth</c> key.</returns>
    public static bool IsSaltAuth(int key) => key == SaltAuth;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinUvAuthProtocol"/>.</summary>
    /// <param name="key">The extension input map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinUvAuthProtocol</c> key.</returns>
    public static bool IsPinUvAuthProtocol(int key) => key == PinUvAuthProtocol;
}
