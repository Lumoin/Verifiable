using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapAuthenticatorConfigRequestDelegate"/>: decodes an
/// <c>authenticatorConfig</c> request's CTAP2-canonical CBOR parameter map into its typed model — the
/// authenticator-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorConfig">
/// CTAP 2.3, section 6.11: authenticatorConfig (0x0D)</see>. Uses <see cref="CtapParameterMapReader"/>
/// to capture every top-level key's still-encoded value in one pass, mirroring
/// <see cref="CtapClientPinRequestCborReader"/>. <c>subCommandParams</c> (<c>0x02</c>)'s still-encoded
/// bytes are captured as <see cref="CtapAuthenticatorConfigRequest.SubCommandParams"/> UNCHANGED (a
/// slice of <paramref name="parametersCbor"/> itself, via <see cref="CborReader.ReadEncodedValue"/> —
/// never re-encoded) and, when present, decoded a second time through the same
/// <see cref="CtapParameterMapReader"/> for its own four members.
/// </remarks>
public static class CtapAuthenticatorConfigRequestCborReader
{
    /// <summary>
    /// Decodes <paramref name="parametersCbor"/> into a <see cref="CtapAuthenticatorConfigRequest"/>.
    /// Method-group-compatible with <see cref="DecodeCtapAuthenticatorConfigRequestDelegate"/>.
    /// </summary>
    /// <param name="parametersCbor">The CBOR-encoded parameter map.</param>
    /// <returns>The decoded request model.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR (classified
    /// <see cref="Fido2FormatFailureKind.MalformedCbor"/>), omits the Required <c>subCommand</c>
    /// (<c>0x01</c>) member (classified <see cref="Fido2FormatFailureKind.MissingRequiredParameter"/>,
    /// snapshot line 7953's MUST), or carries a member of the wrong CBOR type (classified
    /// <see cref="Fido2FormatFailureKind.UnexpectedStructure"/>).
    /// </exception>
    public static CtapAuthenticatorConfigRequest Read(ReadOnlyMemory<byte> parametersCbor)
    {
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters = CtapParameterMapReader.Read(parametersCbor);

        try
        {
            if(!parameters.TryGetValue(WellKnownCtapAuthenticatorConfigRequestKeys.SubCommand, out ReadOnlyMemory<byte> subCommandCbor))
            {
                throw new Fido2FormatException(Fido2FormatFailureKind.MissingRequiredParameter, "The authenticatorConfig request is missing the required 'subCommand' (0x01) member.");
            }

            int subCommand = checked((int)new CborReader(subCommandCbor, CborConformanceMode.Ctap2Canonical).ReadInt64());

            ReadOnlyMemory<byte>? subCommandParams = ReadOptionalRawValue(parameters, WellKnownCtapAuthenticatorConfigRequestKeys.SubCommandParams);

            (int? newMinPinLength, IReadOnlyList<string>? minPinLengthRpIds, bool? forceChangePin, bool? pinComplexityPolicy) =
                subCommandParams is ReadOnlyMemory<byte> paramsCbor ? ReadSubCommandParams(paramsCbor) : (null, null, null, null);

            int? pinUvAuthProtocol = parameters.TryGetValue(WellKnownCtapAuthenticatorConfigRequestKeys.PinUvAuthProtocol, out ReadOnlyMemory<byte> pinUvAuthProtocolCbor)
                ? checked((int)new CborReader(pinUvAuthProtocolCbor, CborConformanceMode.Ctap2Canonical).ReadInt64())
                : null;

            ReadOnlyMemory<byte>? pinUvAuthParam = ReadOptionalByteString(parameters, WellKnownCtapAuthenticatorConfigRequestKeys.PinUvAuthParam);

            return new CtapAuthenticatorConfigRequest(
                subCommand, subCommandParams, newMinPinLength, minPinLengthRpIds, forceChangePin, pinComplexityPolicy, pinUvAuthProtocol, pinUvAuthParam);
        }
        catch(CborContentException exception)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.MalformedCbor, "The authenticatorConfig request parameter bytes are not valid CTAP2 canonical CBOR.", exception);
        }
        catch(Exception exception) when(exception is InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The authenticatorConfig request carries a member of an unexpected CBOR type.", exception);
        }

        //Looks up an Optional member's still-encoded bytes verbatim (no further CBOR interpretation), or
        //returns null when the member is absent. An explicit if/else (never a ternary): a ternary whose
        //two branches are a ReadOnlyMemory<byte> value and the null literal resolves, via the type's own
        //implicit byte[]-to-ReadOnlyMemory<byte> conversion operator, to ReadOnlyMemory<byte> (not
        //ReadOnlyMemory<byte>?) as its natural type — silently producing a Nullable<ReadOnlyMemory<byte>>
        //with HasValue=true wrapping an EMPTY memory on the "absent" branch, rather than HasValue=false.
        static ReadOnlyMemory<byte>? ReadOptionalRawValue(IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters, int key)
        {
            if(parameters.TryGetValue(key, out ReadOnlyMemory<byte> valueCbor))
            {
                return valueCbor;
            }

            return null;
        }

        //Looks up an Optional byte-string member and decodes it, or returns null when the member is
        //absent — mirrors ReadOptionalRawValue's own if/else shape (see its remarks) for the identical
        //Nullable<ReadOnlyMemory<byte>> trap, since CborReader.ReadByteString() also returns byte[], not
        //ReadOnlyMemory<byte>.
        static ReadOnlyMemory<byte>? ReadOptionalByteString(IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters, int key)
        {
            if(parameters.TryGetValue(key, out ReadOnlyMemory<byte> valueCbor))
            {
                return new CborReader(valueCbor, CborConformanceMode.Ctap2Canonical).ReadByteString();
            }

            return null;
        }
    }


    /// <summary>
    /// Decodes <c>setMinPINLength</c>'s own <c>subCommandParams</c> map (CTAP 2.3 §6.11.4, lines
    /// 8087-8116): all four members, including <c>pinComplexityPolicy</c> (<c>0x04</c>) — decoded for
    /// wire completeness even though this profile ignores its value (line 8442's MUST).
    /// </summary>
    /// <param name="subCommandParamsCbor">The still-encoded <c>subCommandParams</c> map bytes.</param>
    /// <returns>The four decoded members, each <see langword="null"/> when its own key is absent.</returns>
    private static (int? NewMinPinLength, IReadOnlyList<string>? MinPinLengthRpIds, bool? ForceChangePin, bool? PinComplexityPolicy) ReadSubCommandParams(
        ReadOnlyMemory<byte> subCommandParamsCbor)
    {
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> members = CtapParameterMapReader.Read(subCommandParamsCbor);

        int? newMinPinLength = members.TryGetValue(WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.NewMinPinLength, out ReadOnlyMemory<byte> newMinPinLengthCbor)
            ? checked((int)new CborReader(newMinPinLengthCbor, CborConformanceMode.Ctap2Canonical).ReadInt64())
            : null;

        IReadOnlyList<string>? minPinLengthRpIds = members.TryGetValue(WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.MinPinLengthRpIds, out ReadOnlyMemory<byte> minPinLengthRpIdsCbor)
            ? ReadStringArray(new CborReader(minPinLengthRpIdsCbor, CborConformanceMode.Ctap2Canonical))
            : null;

        bool? forceChangePin = members.TryGetValue(WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.ForceChangePin, out ReadOnlyMemory<byte> forceChangePinCbor)
            ? new CborReader(forceChangePinCbor, CborConformanceMode.Ctap2Canonical).ReadBoolean()
            : null;

        bool? pinComplexityPolicy = members.TryGetValue(WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.PinComplexityPolicy, out ReadOnlyMemory<byte> pinComplexityPolicyCbor)
            ? new CborReader(pinComplexityPolicyCbor, CborConformanceMode.Ctap2Canonical).ReadBoolean()
            : null;

        return (newMinPinLength, minPinLengthRpIds, forceChangePin, pinComplexityPolicy);
    }


    /// <summary>Reads a definite-length CBOR array of text strings — <c>minPinLengthRPIDs</c>'s own shape.</summary>
    /// <param name="reader">A reader positioned at the array's start.</param>
    /// <returns>The decoded strings, in wire order.</returns>
    private static List<string> ReadStringArray(CborReader reader)
    {
        int? count = reader.ReadStartArray();
        var values = new List<string>();

        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndArray : read < count.Value)
        {
            values.Add(reader.ReadTextString());
            read++;
        }

        reader.ReadEndArray();

        return values;
    }
}
