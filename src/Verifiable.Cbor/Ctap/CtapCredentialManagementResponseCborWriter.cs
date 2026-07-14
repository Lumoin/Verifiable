using System;
using System.Formats.Cbor;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapCredentialManagementResponseDelegate"/>: encodes an
/// <c>authenticatorCredentialManagement</c> response model into its CTAP2-canonical CBOR payload bytes —
/// the authenticator-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8: authenticatorCredentialManagement (0x0A)</see>, the response structure table
/// (lines 7026-7081). The response map's keys (<c>existingResidentCredentialsCount</c>=1 ..
/// <c>totalCredentials</c>=9) are already in ascending numeric order, so writing any present member in
/// that fixed order is sufficient — no run-time sort is needed, mirroring
/// <see cref="CtapClientPinResponseCborWriter"/>'s convention. <c>rp</c>/<c>user</c>/<c>credentialID</c>
/// reuse the SHARED <see cref="CtapCommandEntityCborCodec"/> writers; <c>publicKey</c> reuses the SAME
/// <see cref="CredentialPublicKeyCborWriter"/> <c>authenticatorMakeCredential</c>'s
/// <c>attestedCredentialData</c> already uses (R11) — no new public-key codec. <c>credProtect</c>
/// (<c>0x0A</c>) is emitted with the REAL persisted level (R11). <c>largeBlobKey</c> (<c>0x0B</c>) is
/// emitted with the credential's REAL stored key when one exists (wavelb R8). <c>thirdPartyPayment</c>
/// (<c>0x0C</c>) is NEVER emitted: this authenticator models no third-party payment extension — the
/// overclaim R8's own convention exists to prevent.
/// </remarks>
public static class CtapCredentialManagementResponseCborWriter
{
    /// <summary>
    /// Encodes <paramref name="response"/> into its CTAP2-canonical CBOR payload bytes.
    /// Method-group-compatible with <see cref="EncodeCtapCredentialManagementResponseDelegate"/>.
    /// </summary>
    /// <param name="response">The response model to encode.</param>
    /// <returns>The encoded payload, tagged <see cref="Fido2BufferTags.CtapCredentialManagementResponsePayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="response"/> is <see langword="null"/>.</exception>
    public static TaggedMemory<byte> Write(CtapCredentialManagementResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = (response.ExistingResidentCredentialsCount is not null ? 1 : 0)
            + (response.MaxPossibleRemainingResidentCredentialsCount is not null ? 1 : 0)
            + (response.Rp is not null ? 1 : 0)
            + (response.RpIdHash is not null ? 1 : 0)
            + (response.TotalRps is not null ? 1 : 0)
            + (response.User is not null ? 1 : 0)
            + (response.CredentialId is not null ? 1 : 0)
            + (response.PublicKey is not null ? 1 : 0)
            + (response.TotalCredentials is not null ? 1 : 0)
            + (response.CredProtect is not null ? 1 : 0)
            + (response.LargeBlobKey is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(response.ExistingResidentCredentialsCount is int existingResidentCredentialsCount)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementResponseKeys.ExistingResidentCredentialsCount);
            writer.WriteInt32(existingResidentCredentialsCount);
        }

        if(response.MaxPossibleRemainingResidentCredentialsCount is int maxPossibleRemainingResidentCredentialsCount)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementResponseKeys.MaxPossibleRemainingResidentCredentialsCount);
            writer.WriteInt32(maxPossibleRemainingResidentCredentialsCount);
        }

        if(response.Rp is CtapPublicKeyCredentialRpEntity rp)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementResponseKeys.Rp);
            CtapCommandEntityCborCodec.WriteRpEntity(writer, rp);
        }

        if(response.RpIdHash is ReadOnlyMemory<byte> rpIdHash)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementResponseKeys.RpIdHash);
            writer.WriteByteString(rpIdHash.Span);
        }

        if(response.TotalRps is int totalRps)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementResponseKeys.TotalRps);
            writer.WriteInt32(totalRps);
        }

        if(response.User is CtapPublicKeyCredentialUserEntity user)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementResponseKeys.User);
            CtapCommandEntityCborCodec.WriteUserEntity(writer, user);
        }

        if(response.CredentialId is PublicKeyCredentialDescriptor credentialId)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementResponseKeys.CredentialId);
            CtapCommandEntityCborCodec.WriteDescriptor(writer, credentialId);
        }

        if(response.PublicKey is CoseKey publicKey)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementResponseKeys.PublicKey);
            writer.WriteEncodedValue(CredentialPublicKeyCborWriter.Write(publicKey).Span);
        }

        if(response.TotalCredentials is int totalCredentials)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementResponseKeys.TotalCredentials);
            writer.WriteInt32(totalCredentials);
        }

        if(response.CredProtect is int credProtect)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementResponseKeys.CredProtect);
            writer.WriteInt32(credProtect);
        }

        if(response.LargeBlobKey is ReadOnlyMemory<byte> largeBlobKey)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementResponseKeys.LargeBlobKey);
            writer.WriteByteString(largeBlobKey.Span);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapCredentialManagementResponsePayload);
    }
}
