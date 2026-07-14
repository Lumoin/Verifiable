using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapClientPinRequestDelegate"/>: decodes an
/// <c>authenticatorClientPIN</c> request's CTAP2-canonical CBOR parameter map into its typed model —
/// the authenticator-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">
/// CTAP 2.3, section 6.5.5: authenticatorClientPIN (0x06) Command Definition</see>. Uses
/// <see cref="CtapParameterMapReader"/> to capture every top-level key's still-encoded value in one
/// pass, mirroring <see cref="CtapMakeCredentialRequestCborReader"/>. Per section 8's
/// forward-compatibility rule, any top-level key this reader does not model is ignored (it simply has
/// no dictionary lookup performed against it). <c>keyAgreement</c>'s nested COSE_Key reuses
/// <see cref="CredentialPublicKeyCborReader"/> rather than a second COSE_Key reader.
/// </remarks>
public static class CtapClientPinRequestCborReader
{
    /// <summary>
    /// Decodes <paramref name="parametersCbor"/> into a <see cref="CtapClientPinRequest"/>.
    /// Method-group-compatible with <see cref="DecodeCtapClientPinRequestDelegate"/>.
    /// </summary>
    /// <param name="parametersCbor">The CBOR-encoded parameter map.</param>
    /// <returns>The decoded request model.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR (classified
    /// <see cref="Fido2FormatFailureKind.MalformedCbor"/>), omits the Required <c>subCommand</c>
    /// (<c>0x02</c>) member (classified <see cref="Fido2FormatFailureKind.MissingRequiredParameter"/>),
    /// or carries a member of the wrong CBOR type (classified
    /// <see cref="Fido2FormatFailureKind.UnexpectedStructure"/>).
    /// </exception>
    public static CtapClientPinRequest Read(ReadOnlyMemory<byte> parametersCbor)
    {
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters = CtapParameterMapReader.Read(parametersCbor);

        try
        {
            if(!parameters.TryGetValue(WellKnownCtapClientPinRequestKeys.SubCommand, out ReadOnlyMemory<byte> subCommandCbor))
            {
                throw new Fido2FormatException(Fido2FormatFailureKind.MissingRequiredParameter, "The authenticatorClientPIN request is missing the required 'subCommand' (0x02) member.");
            }

            int subCommand = checked((int)new CborReader(subCommandCbor, CborConformanceMode.Ctap2Canonical).ReadInt64());

            int? pinUvAuthProtocol = parameters.TryGetValue(WellKnownCtapClientPinRequestKeys.PinUvAuthProtocol, out ReadOnlyMemory<byte> pinUvAuthProtocolCbor)
                ? checked((int)new CborReader(pinUvAuthProtocolCbor, CborConformanceMode.Ctap2Canonical).ReadInt64())
                : null;

            CoseKey? keyAgreement = parameters.TryGetValue(WellKnownCtapClientPinRequestKeys.KeyAgreement, out ReadOnlyMemory<byte> keyAgreementCbor)
                ? CredentialPublicKeyCborReader.Read(keyAgreementCbor).CoseKey
                : null;

            ReadOnlyMemory<byte>? pinUvAuthParam = ReadOptionalByteString(parameters, WellKnownCtapClientPinRequestKeys.PinUvAuthParam);
            ReadOnlyMemory<byte>? newPinEnc = ReadOptionalByteString(parameters, WellKnownCtapClientPinRequestKeys.NewPinEnc);
            ReadOnlyMemory<byte>? pinHashEnc = ReadOptionalByteString(parameters, WellKnownCtapClientPinRequestKeys.PinHashEnc);

            int? permissions = parameters.TryGetValue(WellKnownCtapClientPinRequestKeys.Permissions, out ReadOnlyMemory<byte> permissionsCbor)
                ? checked((int)new CborReader(permissionsCbor, CborConformanceMode.Ctap2Canonical).ReadInt64())
                : null;

            string? rpId = parameters.TryGetValue(WellKnownCtapClientPinRequestKeys.RpId, out ReadOnlyMemory<byte> rpIdCbor)
                ? new CborReader(rpIdCbor, CborConformanceMode.Ctap2Canonical).ReadTextString()
                : null;

            return new CtapClientPinRequest(subCommand, pinUvAuthProtocol, keyAgreement, pinUvAuthParam, newPinEnc, pinHashEnc, permissions, rpId);
        }
        catch(CborContentException exception)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.MalformedCbor, "The authenticatorClientPIN request parameter bytes are not valid CTAP2 canonical CBOR.", exception);
        }
        catch(Exception exception) when(exception is InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The authenticatorClientPIN request carries a member of an unexpected CBOR type.", exception);
        }

        //Looks up an Optional byte-string member's still-encoded bytes and decodes it, or returns null
        //when the member is absent. An explicit if/else (not a ternary) so an absent member assigns
        //the null literal directly to the Nullable<ReadOnlyMemory<byte>> variable, mirroring
        //CtapMakeCredentialRequestCborReader's own "extensions"/"pinUvAuthParam" convention.
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
