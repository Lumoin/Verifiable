using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapCredentialManagementRequestDelegate"/>: decodes an
/// <c>authenticatorCredentialManagement</c> request's CTAP2-canonical CBOR parameter map into its typed
/// model — the authenticator-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8: authenticatorCredentialManagement (0x0A)</see>. Uses
/// <see cref="CtapParameterMapReader"/> to capture every top-level key's still-encoded value in one
/// pass, mirroring <see cref="CtapAuthenticatorConfigRequestCborReader"/>. <c>subCommandParams</c>
/// (<c>0x02</c>)'s still-encoded bytes are captured as
/// <see cref="CtapCredentialManagementRequest.SubCommandParams"/> UNCHANGED (a slice of
/// <paramref name="parametersCbor"/> itself, via <see cref="CborReader.ReadEncodedValue"/> — never
/// re-encoded) and, when present, decoded a second time for <c>rpIDHash</c>/<c>credentialID</c>/<c>user</c>
/// via the SHARED <see cref="CtapCommandEntityCborCodec"/> readers. The optional-raw-value local function
/// uses the identical if/else shape <see cref="CtapAuthenticatorConfigRequestCborReader"/> documents (the
/// <c>cond ? readOnlyMemoryExpr : null</c> ternary trap applies here identically).
/// </remarks>
public static class CtapCredentialManagementRequestCborReader
{
    /// <summary>
    /// Decodes <paramref name="parametersCbor"/> into a <see cref="CtapCredentialManagementRequest"/>.
    /// Method-group-compatible with <see cref="DecodeCtapCredentialManagementRequestDelegate"/>.
    /// </summary>
    /// <param name="parametersCbor">The CBOR-encoded parameter map.</param>
    /// <param name="pool">The memory pool the decoded <c>credentialID</c>/<c>user</c> carriers rent from.</param>
    /// <returns>The decoded request model.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR (classified
    /// <see cref="Fido2FormatFailureKind.MalformedCbor"/>), omits the Required <c>subCommand</c>
    /// (<c>0x01</c>) member (classified <see cref="Fido2FormatFailureKind.MissingRequiredParameter"/>),
    /// or carries a member of the wrong CBOR type, including a nested <c>subCommandParams</c> entity's
    /// own missing required member (classified
    /// <see cref="Fido2FormatFailureKind.UnexpectedStructure"/>).
    /// </exception>
    public static CtapCredentialManagementRequest Read(ReadOnlyMemory<byte> parametersCbor, MemoryPool<byte> pool)
    {
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters = CtapParameterMapReader.Read(parametersCbor);

        try
        {
            if(!parameters.TryGetValue(WellKnownCtapCredentialManagementRequestKeys.SubCommand, out ReadOnlyMemory<byte> subCommandCbor))
            {
                throw new Fido2FormatException(Fido2FormatFailureKind.MissingRequiredParameter, "The authenticatorCredentialManagement request is missing the required 'subCommand' (0x01) member.");
            }

            int subCommand = checked((int)new CborReader(subCommandCbor, CborConformanceMode.Ctap2Canonical).ReadInt64());

            ReadOnlyMemory<byte>? subCommandParams = ReadOptionalRawValue(parameters, WellKnownCtapCredentialManagementRequestKeys.SubCommandParams);

            (ReadOnlyMemory<byte>? rpIdHash, PublicKeyCredentialDescriptor? credentialId, CtapPublicKeyCredentialUserEntity? user) =
                subCommandParams is ReadOnlyMemory<byte> paramsCbor ? ReadSubCommandParams(paramsCbor, pool) : (null, null, null);

            int? pinUvAuthProtocol = parameters.TryGetValue(WellKnownCtapCredentialManagementRequestKeys.PinUvAuthProtocol, out ReadOnlyMemory<byte> pinUvAuthProtocolCbor)
                ? checked((int)new CborReader(pinUvAuthProtocolCbor, CborConformanceMode.Ctap2Canonical).ReadInt64())
                : null;

            ReadOnlyMemory<byte>? pinUvAuthParam = ReadOptionalByteString(parameters, WellKnownCtapCredentialManagementRequestKeys.PinUvAuthParam);

            return new CtapCredentialManagementRequest(subCommand, subCommandParams, rpIdHash, credentialId, user, pinUvAuthProtocol, pinUvAuthParam);
        }
        catch(CborContentException exception)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.MalformedCbor, "The authenticatorCredentialManagement request parameter bytes are not valid CTAP2 canonical CBOR.", exception);
        }
        catch(Exception exception) when(exception is InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The authenticatorCredentialManagement request carries a member of an unexpected CBOR type.", exception);
        }

        //Looks up an Optional member's still-encoded bytes verbatim, or returns null when the member is
        //absent — the if/else shape avoids the documented ternary trap on ReadOnlyMemory<byte>?.
        static ReadOnlyMemory<byte>? ReadOptionalRawValue(IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters, int key)
        {
            if(parameters.TryGetValue(key, out ReadOnlyMemory<byte> valueCbor))
            {
                return valueCbor;
            }

            return null;
        }

        //Looks up an Optional byte-string member and decodes it, or returns null when the member is
        //absent — mirrors ReadOptionalRawValue's own if/else shape for the identical trap, since
        //CborReader.ReadByteString() also returns byte[], not ReadOnlyMemory<byte>.
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
    /// Decodes <c>subCommandParams</c>'s own three members (CTAP 2.3 §6.8, lines 7005-7024):
    /// <c>rpIDHash</c> (<c>0x01</c>) via a plain byte-string read; <c>credentialID</c> (<c>0x02</c>) and
    /// <c>user</c> (<c>0x03</c>) via the SHARED <see cref="CtapCommandEntityCborCodec"/> readers.
    /// </summary>
    /// <param name="subCommandParamsCbor">The still-encoded <c>subCommandParams</c> map bytes.</param>
    /// <param name="pool">The memory pool <c>credentialID</c>/<c>user</c>'s own carriers rent from.</param>
    /// <returns>The three decoded members, each <see langword="null"/> when its own key is absent.</returns>
    private static (ReadOnlyMemory<byte>? RpIdHash, PublicKeyCredentialDescriptor? CredentialId, CtapPublicKeyCredentialUserEntity? User) ReadSubCommandParams(
        ReadOnlyMemory<byte> subCommandParamsCbor, MemoryPool<byte> pool)
    {
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> members = CtapParameterMapReader.Read(subCommandParamsCbor);

        ReadOnlyMemory<byte>? rpIdHash = null;
        if(members.TryGetValue(WellKnownCtapCredentialManagementSubCommandParamsKeys.RpIdHash, out ReadOnlyMemory<byte> rpIdHashCbor))
        {
            rpIdHash = new CborReader(rpIdHashCbor, CborConformanceMode.Ctap2Canonical).ReadByteString();
        }

        PublicKeyCredentialDescriptor? credentialId = null;
        if(members.TryGetValue(WellKnownCtapCredentialManagementSubCommandParamsKeys.CredentialId, out ReadOnlyMemory<byte> credentialIdCbor))
        {
            credentialId = CtapCommandEntityCborCodec.ReadDescriptor(new CborReader(credentialIdCbor, CborConformanceMode.Ctap2Canonical), pool);
        }

        CtapPublicKeyCredentialUserEntity? user = null;
        if(members.TryGetValue(WellKnownCtapCredentialManagementSubCommandParamsKeys.User, out ReadOnlyMemory<byte> userCbor))
        {
            user = CtapCommandEntityCborCodec.ReadUserEntity(new CborReader(userCbor, CborConformanceMode.Ctap2Canonical), pool);
        }

        return (rpIdHash, credentialId, user);
    }
}
