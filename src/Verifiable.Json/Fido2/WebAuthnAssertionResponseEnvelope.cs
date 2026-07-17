using System;
using Verifiable.Cryptography;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// The decoded pieces of a W3C WebAuthn Level 3 <c>AuthenticationResponseJSON</c> document, ready for
/// <see cref="Fido2AssertionVerifier.VerifyAsync"/> to consume.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson">W3C Web
/// Authentication Level 3, section 5.1's <c>toJSON()</c> serialization — dictionary <c>AuthenticationResponseJSON</c></see>.
/// Produced by <see cref="AuthenticationResponseJsonReader.Read"/>; the caller owns and disposes the
/// returned instance, which in turn owns and disposes every non-null carrier below.
/// </para>
/// <para>
/// <see cref="RawId"/> identifies the stored <see cref="Fido2CredentialRecord"/> the assertion is
/// against; <see cref="ClientDataJson"/>, <see cref="AuthenticatorData"/>, and <see cref="Signature"/>
/// are the exact bytes <see cref="Fido2AssertionVerifier.VerifyAsync"/> verifies the signature over.
/// <see cref="UserHandle"/> is present only when the client reported one — the discoverable-credential
/// path requires it, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">section 7.2, step 6</see>.
/// </para>
/// </remarks>
public sealed class WebAuthnAssertionResponseEnvelope: IDisposable
{
    /// <summary>Guards against redundant disposal.</summary>
    private bool disposed;

    /// <summary>
    /// The credential identifier (<c>id</c>/<c>rawId</c> — verified identical on the wire by
    /// <see cref="AuthenticationResponseJsonReader"/>), decoded from base64url. Owned by this envelope.
    /// </summary>
    public CredentialId RawId { get; }

    /// <summary>
    /// The raw <c>response.clientDataJSON</c> bytes, decoded from base64url. Owned by this envelope.
    /// </summary>
    public PooledMemory ClientDataJson { get; }

    /// <summary>
    /// The raw <c>response.authenticatorData</c> bytes, decoded from base64url. Owned by this
    /// envelope.
    /// </summary>
    public PooledMemory AuthenticatorData { get; }

    /// <summary>
    /// The raw <c>response.signature</c> bytes, decoded from base64url. Owned by this envelope.
    /// </summary>
    public Signature Signature { get; }

    /// <summary>
    /// The raw <c>response.userHandle</c> bytes, decoded from base64url, or <see langword="null"/>
    /// when the client omitted the member. Owned by this envelope when present.
    /// </summary>
    public UserHandle? UserHandle { get; }

    /// <summary>
    /// The <c>authenticatorAttachment</c> member's raw value, or <see langword="null"/> when the
    /// client omitted it.
    /// </summary>
    public string? AuthenticatorAttachment { get; }


    /// <summary>
    /// Initializes an envelope from its already-decoded, already-validated parts.
    /// </summary>
    /// <param name="rawId">The decoded credential identifier. Ownership transfers to this instance.</param>
    /// <param name="clientDataJson">The decoded <c>clientDataJSON</c> bytes. Ownership transfers to this instance.</param>
    /// <param name="authenticatorData">The decoded <c>authenticatorData</c> bytes. Ownership transfers to this instance.</param>
    /// <param name="signature">The decoded <c>signature</c> bytes. Ownership transfers to this instance.</param>
    /// <param name="userHandle">The decoded <c>userHandle</c> bytes, or <see langword="null"/>. Ownership transfers to this instance when present.</param>
    /// <param name="authenticatorAttachment">The raw <c>authenticatorAttachment</c> value, or <see langword="null"/>.</param>
    public WebAuthnAssertionResponseEnvelope(
        CredentialId rawId,
        PooledMemory clientDataJson,
        PooledMemory authenticatorData,
        Signature signature,
        UserHandle? userHandle,
        string? authenticatorAttachment)
    {
        ArgumentNullException.ThrowIfNull(rawId);
        ArgumentNullException.ThrowIfNull(clientDataJson);
        ArgumentNullException.ThrowIfNull(authenticatorData);
        ArgumentNullException.ThrowIfNull(signature);

        RawId = rawId;
        ClientDataJson = clientDataJson;
        AuthenticatorData = authenticatorData;
        Signature = signature;
        UserHandle = userHandle;
        AuthenticatorAttachment = authenticatorAttachment;
    }


    /// <summary>
    /// Releases <see cref="RawId"/>, <see cref="ClientDataJson"/>, <see cref="AuthenticatorData"/>,
    /// <see cref="Signature"/>, and <see cref="UserHandle"/> when present.
    /// </summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;

        RawId.Dispose();
        ClientDataJson.Dispose();
        AuthenticatorData.Dispose();
        Signature.Dispose();
        UserHandle?.Dispose();
    }
}
