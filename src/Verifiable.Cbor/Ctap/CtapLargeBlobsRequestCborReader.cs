using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapLargeBlobsRequestDelegate"/>: decodes an
/// <c>authenticatorLargeBlobs</c> request's CTAP2-canonical CBOR parameter map into its typed model — the
/// authenticator-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs">
/// CTAP 2.3, section 6.10.2: Reading and writing serialised data</see>. Uses
/// <see cref="CtapParameterMapReader"/> to capture every top-level key's still-encoded value in one pass,
/// mirroring <see cref="CtapAuthenticatorConfigRequestCborReader"/> — no <c>subCommandParams</c> recursion
/// exists here at all, the simplest reader this library ships. <see cref="CtapLargeBlobsRequest.Offset"/>'s
/// absence is NOT rejected here (unlike config/credMgmt's Required <c>subCommand</c> member): it decodes
/// to <see langword="null"/> and reaches the pure transition, which maps it to
/// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/> (line 7590) rather than the decode-boundary
/// <see cref="Fido2FormatException"/> catch config/credMgmt use for their own Required member.
/// </remarks>
public static class CtapLargeBlobsRequestCborReader
{
    /// <summary>
    /// Decodes <paramref name="parametersCbor"/> into a <see cref="CtapLargeBlobsRequest"/>.
    /// Method-group-compatible with <see cref="DecodeCtapLargeBlobsRequestDelegate"/>.
    /// </summary>
    /// <param name="parametersCbor">The CBOR-encoded parameter map.</param>
    /// <returns>The decoded request model.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR (classified
    /// <see cref="Fido2FormatFailureKind.MalformedCbor"/>), or carries a member of the wrong CBOR type
    /// (classified <see cref="Fido2FormatFailureKind.UnexpectedStructure"/>).
    /// </exception>
    public static CtapLargeBlobsRequest Read(ReadOnlyMemory<byte> parametersCbor)
    {
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters = CtapParameterMapReader.Read(parametersCbor);

        try
        {
            int? get = ReadOptionalInt32(parameters, WellKnownCtapLargeBlobsRequestKeys.Get);
            ReadOnlyMemory<byte>? set = ReadOptionalByteString(parameters, WellKnownCtapLargeBlobsRequestKeys.Set);
            int? offset = ReadOptionalInt32(parameters, WellKnownCtapLargeBlobsRequestKeys.Offset);
            int? length = ReadOptionalInt32(parameters, WellKnownCtapLargeBlobsRequestKeys.Length);
            ReadOnlyMemory<byte>? pinUvAuthParam = ReadOptionalByteString(parameters, WellKnownCtapLargeBlobsRequestKeys.PinUvAuthParam);
            int? pinUvAuthProtocol = ReadOptionalInt32(parameters, WellKnownCtapLargeBlobsRequestKeys.PinUvAuthProtocol);

            return new CtapLargeBlobsRequest(get, set, offset, length, pinUvAuthParam, pinUvAuthProtocol);
        }
        catch(CborContentException exception)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.MalformedCbor, "The authenticatorLargeBlobs request parameter bytes are not valid CTAP2 canonical CBOR.", exception);
        }
        catch(Exception exception) when(exception is InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The authenticatorLargeBlobs request carries a member of an unexpected CBOR type.", exception);
        }

        //Looks up an Optional unsigned-integer member and decodes it, or returns null when the member is
        //absent — shared by get/offset/length/pinUvAuthProtocol.
        static int? ReadOptionalInt32(IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters, int key)
        {
            if(parameters.TryGetValue(key, out ReadOnlyMemory<byte> valueCbor))
            {
                return checked((int)new CborReader(valueCbor, CborConformanceMode.Ctap2Canonical).ReadInt64());
            }

            return null;
        }

        //Looks up an Optional byte-string member and decodes it, or returns null when the member is
        //absent — the if/else shape avoids the documented Nullable<ReadOnlyMemory<byte>> ternary trap
        //(CtapAuthenticatorConfigRequestCborReader's own remarks), since CborReader.ReadByteString()
        //returns byte[], not ReadOnlyMemory<byte>.
        static ReadOnlyMemory<byte>? ReadOptionalByteString(IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters, int key)
        {
            if(parameters.TryGetValue(key, out ReadOnlyMemory<byte> valueCbor))
            {
                return new CborReader(valueCbor, CborConformanceMode.Ctap2Canonical).ReadByteString();
            }

            return null;
        }
    }
}
