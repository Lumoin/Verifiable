using System;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapMakeCredentialResponseDelegate"/>: decodes an
/// <c>authenticatorMakeCredential</c> response's CTAP2-canonical CBOR payload into its typed model —
/// the client/RP-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see>. Read with
/// <see cref="CborConformanceMode.Ctap2Canonical"/>, mirroring
/// <see cref="CtapGetInfoResponseCborReader"/>. Per
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding">
/// section 8: Message Encoding</see>'s forward-compatibility rule, any member key this reader does not
/// model (<c>unsignedExtensionOutputs</c>, or any unrecognized key) is skipped rather than rejected.
/// <c>largeBlobKey</c> (<c>0x05</c>) IS modeled (wavelb R8); <c>epAtt</c> (<c>0x04</c>) IS modeled
/// (waveep R9) — required for the wire capstone to observe an enterprise attestation grant.
/// </remarks>
public static class CtapMakeCredentialResponseCborReader
{
    /// <summary>
    /// Decodes <paramref name="payload"/> into a <see cref="CtapMakeCredentialResponse"/>.
    /// Method-group-compatible with <see cref="DecodeCtapMakeCredentialResponseDelegate"/>.
    /// </summary>
    /// <param name="payload">The CBOR-encoded response payload.</param>
    /// <returns>The decoded response model.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="payload"/> is not valid CTAP2 canonical CBOR, or omits a Required member
    /// (<c>fmt</c> or <c>authData</c>).
    /// </exception>
    public static CtapMakeCredentialResponse Read(ReadOnlyMemory<byte> payload)
    {
        try
        {
            var reader = new CborReader(payload, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            string? fmt = null;
            ReadOnlyMemory<byte>? authData = null;
            ReadOnlyMemory<byte>? attStmt = null;
            bool? epAtt = null;
            ReadOnlyMemory<byte>? largeBlobKey = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                int key = checked((int)reader.ReadInt64());
                entriesRead++;

                switch(key)
                {
                    case(WellKnownCtapMakeCredentialResponseKeys.Fmt):
                    {
                        fmt = reader.ReadTextString();
                        break;
                    }
                    case(WellKnownCtapMakeCredentialResponseKeys.AuthData):
                    {
                        authData = reader.ReadByteString();
                        break;
                    }
                    case(WellKnownCtapMakeCredentialResponseKeys.AttStmt):
                    {
                        attStmt = reader.ReadEncodedValue().ToArray();
                        break;
                    }
                    case(WellKnownCtapMakeCredentialResponseKeys.EpAtt):
                    {
                        epAtt = reader.ReadBoolean();
                        break;
                    }
                    case(WellKnownCtapMakeCredentialResponseKeys.LargeBlobKey):
                    {
                        largeBlobKey = reader.ReadByteString();
                        break;
                    }
                    default:
                    {
                        reader.SkipValue();
                        break;
                    }
                }
            }

            reader.ReadEndMap();

            if(fmt is null)
            {
                throw new Fido2FormatException("The authenticatorMakeCredential response is missing the required 'fmt' (0x01) member.");
            }

            if(authData is not ReadOnlyMemory<byte> resolvedAuthData)
            {
                throw new Fido2FormatException("The authenticatorMakeCredential response is missing the required 'authData' (0x02) member.");
            }

            return new CtapMakeCredentialResponse(fmt, resolvedAuthData, attStmt, epAtt, largeBlobKey);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException("The authenticatorMakeCredential response bytes are not valid CTAP2 canonical CBOR.", exception);
        }
    }
}
