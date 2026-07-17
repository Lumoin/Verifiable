using System;
using Verifiable.Cryptography;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// The decoded pieces of a W3C WebAuthn Level 3 <c>RegistrationResponseJSON</c> document, ready for
/// <see cref="Fido2RegistrationVerifier.VerifyAsync"/> to consume.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson">W3C Web
/// Authentication Level 3, section 5.1's <c>toJSON()</c> serialization — dictionary <c>RegistrationResponseJSON</c></see>.
/// Produced by <see cref="RegistrationResponseJsonReader.Read"/>; the caller owns and disposes the
/// returned instance, which in turn owns and disposes every carrier below.
/// </para>
/// <para>
/// <see cref="RawId"/> is the identifier a relying party looks credentials up by
/// (<see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">section 7.1,
/// step 27</see>'s credential record <c>id</c>); <see cref="ClientDataJson"/> and
/// <see cref="AttestationObject"/> are the exact bytes
/// <see cref="Verifiable.Cbor.Fido2.AttestationObjectCborReader.Parse"/> and the verifier's
/// <c>clientDataHash</c> computation consume. <see cref="AuthenticatorAttachment"/> is carried
/// verbatim for <see cref="Fido2RegistrationVerifier.VerifyAsync"/>'s own parameter of the same
/// name.
/// </para>
/// </remarks>
public sealed class WebAuthnRegistrationResponseEnvelope: IDisposable
{
    /// <summary>Guards against redundant disposal.</summary>
    private bool disposed;

    /// <summary>
    /// The credential identifier (<c>id</c>/<c>rawId</c> — verified identical on the wire by
    /// <see cref="RegistrationResponseJsonReader"/>), decoded from base64url. Owned by this envelope.
    /// </summary>
    public CredentialId RawId { get; }

    /// <summary>
    /// The raw <c>response.clientDataJSON</c> bytes, decoded from base64url. Owned by this envelope.
    /// </summary>
    public PooledMemory ClientDataJson { get; }

    /// <summary>
    /// The raw <c>response.attestationObject</c> bytes, decoded from base64url — split into its
    /// <c>fmt</c>/<c>attStmt</c>/<c>authData</c> parts by
    /// <see cref="Verifiable.Cbor.Fido2.AttestationObjectCborReader.Parse"/>. Owned by this envelope.
    /// </summary>
    public PooledMemory AttestationObject { get; }

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
    /// <param name="attestationObject">The decoded <c>attestationObject</c> bytes. Ownership transfers to this instance.</param>
    /// <param name="authenticatorAttachment">The raw <c>authenticatorAttachment</c> value, or <see langword="null"/>.</param>
    public WebAuthnRegistrationResponseEnvelope(
        CredentialId rawId, PooledMemory clientDataJson, PooledMemory attestationObject, string? authenticatorAttachment)
    {
        ArgumentNullException.ThrowIfNull(rawId);
        ArgumentNullException.ThrowIfNull(clientDataJson);
        ArgumentNullException.ThrowIfNull(attestationObject);

        RawId = rawId;
        ClientDataJson = clientDataJson;
        AttestationObject = attestationObject;
        AuthenticatorAttachment = authenticatorAttachment;
    }


    /// <summary>
    /// Releases <see cref="RawId"/>, <see cref="ClientDataJson"/>, and <see cref="AttestationObject"/>.
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
        AttestationObject.Dispose();
    }
}
