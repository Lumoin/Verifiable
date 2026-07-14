using System;
using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapGetAssertionResponseDelegate"/>: decodes an
/// <c>authenticatorGetAssertion</c> response's CTAP2-canonical CBOR payload into its typed model — the
/// client/RP-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2: authenticatorGetAssertion (0x02)</see>. Read with
/// <see cref="CborConformanceMode.Ctap2Canonical"/>, mirroring
/// <see cref="CtapGetInfoResponseCborReader"/>. Per section 8's forward-compatibility rule, any member
/// key this reader does not model (<c>unsignedExtensionOutputs</c>, or any unrecognized key) is skipped
/// rather than rejected. <c>largeBlobKey</c> (<c>0x07</c>) IS modeled (wavelb R8). The <c>credential</c>
/// identifier and, when present, the <c>user</c> handle are tracked outside the parse block and disposed
/// if a later member fails to decode, so a rejected response never leaks pooled memory — mirrors
/// <see cref="Verifiable.Cbor.Ctap.CtapMakeCredentialRequestCborReader"/>'s own convention.
/// </remarks>
public static class CtapGetAssertionResponseCborReader
{
    /// <summary>
    /// Decodes <paramref name="payload"/> into a <see cref="CtapGetAssertionResponse"/>.
    /// Method-group-compatible with <see cref="DecodeCtapGetAssertionResponseDelegate"/>.
    /// </summary>
    /// <param name="payload">The CBOR-encoded response payload.</param>
    /// <param name="pool">
    /// The memory pool the decoded <c>credential</c> identifier and, when present, the <c>user</c>
    /// handle rent from.
    /// </param>
    /// <returns>The decoded response model.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="payload"/> is not valid CTAP2 canonical CBOR, or omits a Required member
    /// (<c>credential</c>, <c>authData</c>, or <c>signature</c>).
    /// </exception>
    public static CtapGetAssertionResponse Read(ReadOnlyMemory<byte> payload, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //Tracked outside the try block so a failure decoding a later member can dispose the credential
        //identifier and user handle already constructed, mirroring
        //CtapMakeCredentialRequestCborReader's disposal-on-failure convention.
        PublicKeyCredentialDescriptor? credential = null;
        CtapPublicKeyCredentialUserEntity? user = null;
        try
        {
            var reader = new CborReader(payload, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            ReadOnlyMemory<byte>? authData = null;
            ReadOnlyMemory<byte>? signature = null;
            int? numberOfCredentials = null;
            bool? userSelected = null;
            ReadOnlyMemory<byte>? largeBlobKey = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                int key = checked((int)reader.ReadInt64());
                entriesRead++;

                switch(key)
                {
                    case(WellKnownCtapGetAssertionResponseKeys.Credential):
                    {
                        credential = CtapCommandEntityCborCodec.ReadDescriptor(reader, pool);
                        break;
                    }
                    case(WellKnownCtapGetAssertionResponseKeys.AuthData):
                    {
                        authData = reader.ReadByteString();
                        break;
                    }
                    case(WellKnownCtapGetAssertionResponseKeys.Signature):
                    {
                        signature = reader.ReadByteString();
                        break;
                    }
                    case(WellKnownCtapGetAssertionResponseKeys.User):
                    {
                        user = CtapCommandEntityCborCodec.ReadUserEntity(reader, pool);
                        break;
                    }
                    case(WellKnownCtapGetAssertionResponseKeys.NumberOfCredentials):
                    {
                        numberOfCredentials = checked((int)reader.ReadInt64());
                        break;
                    }
                    case(WellKnownCtapGetAssertionResponseKeys.UserSelected):
                    {
                        userSelected = reader.ReadBoolean();
                        break;
                    }
                    case(WellKnownCtapGetAssertionResponseKeys.LargeBlobKey):
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

            if(credential is null)
            {
                throw new Fido2FormatException("The authenticatorGetAssertion response is missing the required 'credential' (0x01) member.");
            }

            if(authData is not ReadOnlyMemory<byte> resolvedAuthData)
            {
                throw new Fido2FormatException("The authenticatorGetAssertion response is missing the required 'authData' (0x02) member.");
            }

            if(signature is not ReadOnlyMemory<byte> resolvedSignature)
            {
                throw new Fido2FormatException("The authenticatorGetAssertion response is missing the required 'signature' (0x03) member.");
            }

            return new CtapGetAssertionResponse(credential, resolvedAuthData, resolvedSignature, user, numberOfCredentials, userSelected, largeBlobKey);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException)
        {
            DisposeAll(credential, user);
            throw new Fido2FormatException("The authenticatorGetAssertion response bytes are not valid CTAP2 canonical CBOR.", exception);
        }
        catch
        {
            DisposeAll(credential, user);
            throw;
        }

        //Disposes the credential identifier and user handle already constructed before a later member
        //failed to decode, so a rejected response never leaks pooled memory.
        static void DisposeAll(PublicKeyCredentialDescriptor? credential, CtapPublicKeyCredentialUserEntity? user)
        {
            credential?.Id.Dispose();
            user?.Id.Dispose();
        }
    }
}
