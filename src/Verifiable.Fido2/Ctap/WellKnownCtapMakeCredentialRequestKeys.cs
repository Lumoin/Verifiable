namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorMakeCredential</c> request structure's members.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see> assigns each input parameter a
/// small integer key (the CTAP2 wire representation is a top-level integer-keyed CBOR map, distinct
/// from the text-string keys the nested <c>rp</c>/<c>user</c>/<c>options</c> maps and WebAuthn-level
/// structures such as <c>attestationObject</c> use).
/// </remarks>
public static class WellKnownCtapMakeCredentialRequestKeys
{
    /// <summary>The <c>clientDataHash</c> parameter (<c>0x01</c>, Required): a byte string.</summary>
    public const int ClientDataHash = 0x01;

    /// <summary>The <c>rp</c> parameter (<c>0x02</c>, Required): a <c>PublicKeyCredentialRpEntity</c> map.</summary>
    public const int Rp = 0x02;

    /// <summary>The <c>user</c> parameter (<c>0x03</c>, Required): a <c>PublicKeyCredentialUserEntity</c> map.</summary>
    public const int User = 0x03;

    /// <summary>The <c>pubKeyCredParams</c> parameter (<c>0x04</c>, Required): an ordered array of <c>PublicKeyCredentialParameters</c>.</summary>
    public const int PubKeyCredParams = 0x04;

    /// <summary>The <c>excludeList</c> parameter (<c>0x05</c>, Optional): an array of <c>PublicKeyCredentialDescriptor</c>; MUST NOT be empty if present.</summary>
    public const int ExcludeList = 0x05;

    /// <summary>The <c>extensions</c> parameter (<c>0x06</c>, Optional): an extension-identifier-keyed CBOR map.</summary>
    public const int Extensions = 0x06;

    /// <summary>The <c>options</c> parameter (<c>0x07</c>, Optional): a map of boolean-valued authenticator options.</summary>
    public const int Options = 0x07;

    /// <summary>The <c>pinUvAuthParam</c> parameter (<c>0x08</c>, Optional): a byte string, ClientPIN-only.</summary>
    public const int PinUvAuthParam = 0x08;

    /// <summary>The <c>pinUvAuthProtocol</c> parameter (<c>0x09</c>, Optional): an unsigned integer, ClientPIN-only.</summary>
    public const int PinUvAuthProtocol = 0x09;

    /// <summary>The <c>enterpriseAttestation</c> parameter (<c>0x0A</c>, Optional): an unsigned integer, enterprise-attestation-capable authenticators only.</summary>
    public const int EnterpriseAttestation = 0x0A;

    /// <summary>The <c>attestationFormatsPreference</c> parameter (<c>0x0B</c>, Optional): an array of attestation statement format identifiers.</summary>
    public const int AttestationFormatsPreference = 0x0B;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="ClientDataHash"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>clientDataHash</c> key.</returns>
    public static bool IsClientDataHash(int key) => key == ClientDataHash;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Rp"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>rp</c> key.</returns>
    public static bool IsRp(int key) => key == Rp;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="User"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>user</c> key.</returns>
    public static bool IsUser(int key) => key == User;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PubKeyCredParams"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pubKeyCredParams</c> key.</returns>
    public static bool IsPubKeyCredParams(int key) => key == PubKeyCredParams;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="ExcludeList"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>excludeList</c> key.</returns>
    public static bool IsExcludeList(int key) => key == ExcludeList;

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

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="EnterpriseAttestation"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>enterpriseAttestation</c> key.</returns>
    public static bool IsEnterpriseAttestation(int key) => key == EnterpriseAttestation;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="AttestationFormatsPreference"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>attestationFormatsPreference</c> key.</returns>
    public static bool IsAttestationFormatsPreference(int key) => key == AttestationFormatsPreference;
}
