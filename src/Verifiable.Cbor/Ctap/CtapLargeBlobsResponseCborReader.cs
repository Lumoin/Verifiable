using System;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapLargeBlobsResponseDelegate"/>: decodes an
/// <c>authenticatorLargeBlobs</c> <c>get</c> response's CTAP2-canonical CBOR payload into its typed model
/// — the RP/platform-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs">
/// CTAP 2.3, section 6.10.2: Reading and writing serialised data</see>. Read with
/// <see cref="CborConformanceMode.Ctap2Canonical"/>, mirroring <see cref="CtapCredentialManagementResponseCborReader"/>.
/// Per section 8's forward-compatibility rule, any member key this reader does not model is skipped
/// rather than rejected — future map elements beyond <c>config</c> stay decodable. This is a TEST-SIDE
/// inverse codec: no authenticator-side production code consumes <see cref="DecodeCtapLargeBlobsResponseDelegate"/>.
/// </remarks>
public static class CtapLargeBlobsResponseCborReader
{
    /// <summary>
    /// Decodes <paramref name="payload"/> into a <see cref="CtapLargeBlobsResponse"/>.
    /// Method-group-compatible with <see cref="DecodeCtapLargeBlobsResponseDelegate"/>.
    /// </summary>
    /// <param name="payload">The CBOR-encoded response payload.</param>
    /// <returns>The decoded response model.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="payload"/> is not valid CTAP2 canonical CBOR, or omits the Required <c>config</c>
    /// (<c>0x01</c>) member.
    /// </exception>
    public static CtapLargeBlobsResponse Read(ReadOnlyMemory<byte> payload)
    {
        try
        {
            var reader = new CborReader(payload, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            ReadOnlyMemory<byte>? config = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                int key = checked((int)reader.ReadInt64());
                entriesRead++;

                if(key == WellKnownCtapLargeBlobsResponseKeys.Config)
                {
                    config = reader.ReadByteString();
                }
                else
                {
                    reader.SkipValue();
                }
            }

            reader.ReadEndMap();

            if(config is not ReadOnlyMemory<byte> resolvedConfig)
            {
                throw new Fido2FormatException("The authenticatorLargeBlobs get response is missing the required 'config' (0x01) member.");
            }

            return new CtapLargeBlobsResponse(resolvedConfig);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException("The authenticatorLargeBlobs response bytes are not valid CTAP2 canonical CBOR.", exception);
        }
    }
}
