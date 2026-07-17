using System;
using System.Formats.Cbor;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapClientPinResponseDelegate"/>: decodes an
/// <c>authenticatorClientPIN</c> response's CTAP2-canonical CBOR payload into its typed model — the
/// RP/platform-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">
/// CTAP 2.3, section 6.5.5: authenticatorClientPIN (0x06) Command Definition</see>. Read with
/// <see cref="CborConformanceMode.Ctap2Canonical"/>, mirroring <see cref="CtapGetInfoResponseCborReader"/>.
/// Per section 8's forward-compatibility rule, any member key this reader does not model is skipped
/// rather than rejected. <c>keyAgreement</c>'s nested COSE_Key reuses
/// <see cref="CredentialPublicKeyCborReader"/> rather than a second COSE_Key reader.
/// </remarks>
public static class CtapClientPinResponseCborReader
{
    /// <summary>
    /// Decodes <paramref name="payload"/> into a <see cref="CtapClientPinResponse"/>.
    /// Method-group-compatible with <see cref="DecodeCtapClientPinResponseDelegate"/>.
    /// </summary>
    /// <param name="payload">The CBOR-encoded response payload.</param>
    /// <returns>The decoded response model.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="payload"/> is not valid CTAP2 canonical CBOR.
    /// </exception>
    public static CtapClientPinResponse Read(ReadOnlyMemory<byte> payload)
    {
        try
        {
            var reader = new CborReader(payload, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            //pinUvAuthToken is declared as the Nullable<ReadOnlyMemory<byte>> the record's constructor
            //takes, not byte[]?: passing a null byte[] to a ReadOnlyMemory<byte>? parameter converts
            //the array to ReadOnlyMemory<byte> BEFORE wrapping in Nullable<T>, turning "absent" into a
            //non-null EMPTY memory instead of an absent member (the same footgun
            //CtapMakeCredentialRequestCborReader's own "extensions"/"pinUvAuthParam" remarks document).
            CoseKey? keyAgreement = null;
            ReadOnlyMemory<byte>? pinUvAuthToken = null;
            int? pinRetries = null;
            bool? powerCycleState = null;
            int? uvRetries = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                int key = checked((int)reader.ReadInt64());
                entriesRead++;

                //A switch over WellKnownCtapClientPinResponseKeys is not available: its members are
                //static getters (the wave-2 wire-key convention for request/response member tables),
                //not compile-time constants, so membership is tested with ordinary equality instead.
                if(key == WellKnownCtapClientPinResponseKeys.KeyAgreement)
                {
                    keyAgreement = CredentialPublicKeyCborReader.Read(reader.ReadEncodedValue()).CoseKey;
                }
                else if(key == WellKnownCtapClientPinResponseKeys.PinUvAuthToken)
                {
                    pinUvAuthToken = reader.ReadByteString();
                }
                else if(key == WellKnownCtapClientPinResponseKeys.PinRetries)
                {
                    pinRetries = checked((int)reader.ReadInt64());
                }
                else if(key == WellKnownCtapClientPinResponseKeys.PowerCycleState)
                {
                    powerCycleState = reader.ReadBoolean();
                }
                else if(key == WellKnownCtapClientPinResponseKeys.UvRetries)
                {
                    uvRetries = checked((int)reader.ReadInt64());
                }
                else
                {
                    reader.SkipValue();
                }
            }

            reader.ReadEndMap();

            return new CtapClientPinResponse(keyAgreement, pinUvAuthToken, pinRetries, powerCycleState, uvRetries);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException("The authenticatorClientPIN response bytes are not valid CTAP2 canonical CBOR.", exception);
        }
    }
}
