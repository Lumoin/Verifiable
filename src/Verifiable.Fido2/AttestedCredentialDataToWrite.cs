using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The attested credential data <see cref="AuthenticatorDataWriter.Write"/> embeds when its <c>flags</c>
/// argument carries <see cref="AuthenticatorDataFlags.AttestedCredentialDataIncluded"/>.
/// </summary>
/// <param name="Aaguid">
/// The authenticator AAGUID to embed, per <see cref="AttestedCredentialData.Aaguid"/>.
/// </param>
/// <param name="CredentialId">
/// The credential identifier to embed, per <see cref="AttestedCredentialData.CredentialId"/>. Borrowed,
/// not owned — <see cref="AuthenticatorDataWriter.Write"/> reads its bytes and does not dispose it; the
/// caller retains ownership and disposal responsibility.
/// </param>
/// <param name="CredentialPublicKey">
/// The already CBOR-encoded COSE_Key <c>credentialPublicKey</c> bytes, spliced in verbatim. Opaque at
/// this layer: <see cref="AuthenticatorDataWriter"/> has no CBOR codec dependency (see its own remarks),
/// so the caller encodes the COSE_Key first — for example via
/// <c>Verifiable.Cbor.Fido2.CredentialPublicKeyCborWriter</c> — and passes the resulting bytes here.
/// </param>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication
/// Level 3, section 6.5.1: Attested Credential Data.</see> The wire layout is <c>aaguid</c> (16 bytes) |
/// <c>credentialIdLength</c> (2 bytes, big-endian) | <c>credentialId</c> | <c>credentialPublicKey</c>.
/// </remarks>
[DebuggerDisplay("AttestedCredentialDataToWrite(Aaguid={Aaguid}, CredentialId={CredentialId}, CredentialPublicKey={CredentialPublicKey.Length} bytes)")]
public sealed record AttestedCredentialDataToWrite(Guid Aaguid, CredentialId CredentialId, ReadOnlyMemory<byte> CredentialPublicKey);
