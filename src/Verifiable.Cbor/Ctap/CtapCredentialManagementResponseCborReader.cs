using System;
using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapCredentialManagementResponseDelegate"/>: decodes an
/// <c>authenticatorCredentialManagement</c> response's CTAP2-canonical CBOR payload into its typed
/// model — the RP/platform-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8: authenticatorCredentialManagement (0x0A)</see>. Read with
/// <see cref="CborConformanceMode.Ctap2Canonical"/>, mirroring <see cref="CtapClientPinResponseCborReader"/>.
/// <c>credProtect</c> (<c>0x0A</c>) is modeled (R11); <c>largeBlobKey</c> (<c>0x0B</c>) is modeled
/// (wavelb R8); per section 8's forward-compatibility rule, any OTHER member key this reader does not
/// model (<c>thirdPartyPayment</c>) is skipped rather than rejected. <c>rp</c>/<c>user</c>/<c>credentialID</c>
/// reuse the SHARED <see cref="CtapCommandEntityCborCodec"/> readers; <c>publicKey</c>'s nested COSE_Key
/// reuses <see cref="CredentialPublicKeyCborReader"/> rather than a second COSE_Key reader.
/// </remarks>
public static class CtapCredentialManagementResponseCborReader
{
    /// <summary>
    /// Decodes <paramref name="payload"/> into a <see cref="CtapCredentialManagementResponse"/>.
    /// Method-group-compatible with <see cref="DecodeCtapCredentialManagementResponseDelegate"/>.
    /// </summary>
    /// <param name="payload">The CBOR-encoded response payload.</param>
    /// <param name="pool">The memory pool the decoded <c>credentialID</c>/<c>user</c> carriers rent from.</param>
    /// <returns>The decoded response model.</returns>
    /// <exception cref="Fido2FormatException"><paramref name="payload"/> is not valid CTAP2 canonical CBOR.</exception>
    public static CtapCredentialManagementResponse Read(ReadOnlyMemory<byte> payload, MemoryPool<byte> pool)
    {
        try
        {
            var reader = new CborReader(payload, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            int? existingResidentCredentialsCount = null;
            int? maxPossibleRemainingResidentCredentialsCount = null;
            CtapPublicKeyCredentialRpEntity? rp = null;
            ReadOnlyMemory<byte>? rpIdHash = null;
            int? totalRps = null;
            CtapPublicKeyCredentialUserEntity? user = null;
            PublicKeyCredentialDescriptor? credentialId = null;
            CoseKey? publicKey = null;
            int? totalCredentials = null;
            int? credProtect = null;
            ReadOnlyMemory<byte>? largeBlobKey = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                int key = checked((int)reader.ReadInt64());
                entriesRead++;

                if(key == WellKnownCtapCredentialManagementResponseKeys.ExistingResidentCredentialsCount)
                {
                    existingResidentCredentialsCount = checked((int)reader.ReadInt64());
                }
                else if(key == WellKnownCtapCredentialManagementResponseKeys.MaxPossibleRemainingResidentCredentialsCount)
                {
                    maxPossibleRemainingResidentCredentialsCount = checked((int)reader.ReadInt64());
                }
                else if(key == WellKnownCtapCredentialManagementResponseKeys.Rp)
                {
                    rp = CtapCommandEntityCborCodec.ReadRpEntity(reader);
                }
                else if(key == WellKnownCtapCredentialManagementResponseKeys.RpIdHash)
                {
                    rpIdHash = reader.ReadByteString();
                }
                else if(key == WellKnownCtapCredentialManagementResponseKeys.TotalRps)
                {
                    totalRps = checked((int)reader.ReadInt64());
                }
                else if(key == WellKnownCtapCredentialManagementResponseKeys.User)
                {
                    user = CtapCommandEntityCborCodec.ReadUserEntity(reader, pool);
                }
                else if(key == WellKnownCtapCredentialManagementResponseKeys.CredentialId)
                {
                    credentialId = CtapCommandEntityCborCodec.ReadDescriptor(reader, pool);
                }
                else if(key == WellKnownCtapCredentialManagementResponseKeys.PublicKey)
                {
                    publicKey = CredentialPublicKeyCborReader.Read(reader.ReadEncodedValue()).CoseKey;
                }
                else if(key == WellKnownCtapCredentialManagementResponseKeys.TotalCredentials)
                {
                    totalCredentials = checked((int)reader.ReadInt64());
                }
                else if(key == WellKnownCtapCredentialManagementResponseKeys.CredProtect)
                {
                    credProtect = checked((int)reader.ReadInt64());
                }
                else if(key == WellKnownCtapCredentialManagementResponseKeys.LargeBlobKey)
                {
                    largeBlobKey = reader.ReadByteString();
                }
                else
                {
                    reader.SkipValue();
                }
            }

            reader.ReadEndMap();

            return new CtapCredentialManagementResponse(
                existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount, rp, rpIdHash, totalRps,
                user, credentialId, publicKey, totalCredentials, credProtect, largeBlobKey);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException("The authenticatorCredentialManagement response bytes are not valid CTAP2 canonical CBOR.", exception);
        }
    }
}
