using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapMakeCredentialRequestDelegate"/>: decodes an
/// <c>authenticatorMakeCredential</c> request's CTAP2-canonical CBOR parameter map into its typed model
/// — the authenticator-side operation, and the first production caller of
/// <see cref="CtapParameterMapReader"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see>. Per
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding">
/// section 8: Message Encoding</see>'s forward-compatibility rule ("If map keys are present that an
/// implementation does not understand, they MUST be ignored"), any top-level key this reader does not
/// model is skipped rather than rejected — <see cref="CtapParameterMapReader"/> already captures every
/// top-level key, so a key this reader has no case for simply has no dictionary lookup performed
/// against it. The <c>clientDataHash</c> digest is the one <c>SensitiveMemory</c> carrier deferred until
/// every other member has decoded successfully; the <c>user</c> handle and any <c>excludeList</c>
/// credential identifiers are constructed earlier (their own required sub-members must be validated as
/// they decode), so this reader tracks both outside its parse block and disposes whichever were already
/// constructed if a later member fails, mirroring <c>PackedAttestationStatementCborReader</c>'s
/// disposal-on-failure convention for its <c>x5c</c> chain.
/// </remarks>
public static class CtapMakeCredentialRequestCborReader
{
    /// <summary>
    /// Decodes <paramref name="parametersCbor"/> into a <see cref="CtapMakeCredentialRequest"/>.
    /// Method-group-compatible with <see cref="DecodeCtapMakeCredentialRequestDelegate"/>.
    /// </summary>
    /// <param name="parametersCbor">The CBOR-encoded parameter map.</param>
    /// <param name="pool">
    /// The memory pool the decoded <c>clientDataHash</c>, <c>user.id</c>, and any <c>excludeList</c>
    /// credential identifiers rent from.
    /// </param>
    /// <returns>The decoded request model.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR (classified
    /// <see cref="Fido2FormatFailureKind.MalformedCbor"/>), omits a Required top-level member
    /// (<c>clientDataHash</c>, <c>rp</c>, <c>user</c>, or <c>pubKeyCredParams</c>; classified
    /// <see cref="Fido2FormatFailureKind.MissingRequiredParameter"/>), or carries a member of the wrong
    /// CBOR type, including a nested entity's own missing required member (classified
    /// <see cref="Fido2FormatFailureKind.UnexpectedStructure"/>).
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The clientDataHash digest's ownership transfers to the returned CtapMakeCredentialRequest on success and is explicitly disposed (alongside user/excludeList) in the surrounding catch blocks on failure — the CA2000 flag is a false positive.")]
    public static CtapMakeCredentialRequest Read(ReadOnlyMemory<byte> parametersCbor, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters = CtapParameterMapReader.Read(parametersCbor);

        //Tracked outside the try block so a failure decoding a LATER member can dispose the pooled
        //carriers an EARLIER member already constructed successfully, mirroring
        //PackedAttestationStatementCborReader's x5c disposal-on-failure convention.
        CtapPublicKeyCredentialUserEntity? user = null;
        List<PublicKeyCredentialDescriptor>? excludeList = null;
        try
        {
            byte[] clientDataHashBytes = new CborReader(
                RequireMember(parameters, WellKnownCtapMakeCredentialRequestKeys.ClientDataHash, "clientDataHash"), CborConformanceMode.Ctap2Canonical).ReadByteString();

            CtapPublicKeyCredentialRpEntity rp = CtapCommandEntityCborCodec.ReadRpEntity(
                new CborReader(RequireMember(parameters, WellKnownCtapMakeCredentialRequestKeys.Rp, "rp"), CborConformanceMode.Ctap2Canonical));

            user = CtapCommandEntityCborCodec.ReadUserEntity(
                new CborReader(RequireMember(parameters, WellKnownCtapMakeCredentialRequestKeys.User, "user"), CborConformanceMode.Ctap2Canonical),
                pool);

            List<PublicKeyCredentialParameters> pubKeyCredParams = CtapCommandEntityCborCodec.ReadParametersArray(
                new CborReader(RequireMember(parameters, WellKnownCtapMakeCredentialRequestKeys.PubKeyCredParams, "pubKeyCredParams"), CborConformanceMode.Ctap2Canonical));

            excludeList = parameters.TryGetValue(WellKnownCtapMakeCredentialRequestKeys.ExcludeList, out ReadOnlyMemory<byte> excludeListCbor)
                ? CtapCommandEntityCborCodec.ReadDescriptorArray(new CborReader(excludeListCbor, CborConformanceMode.Ctap2Canonical), pool)
                : null;

            //Assigned via an explicit if/else rather than a ternary: a ternary whose "present" branch is
            //a byte[] and whose "absent" branch is the null literal infers a byte[]-typed conditional
            //expression, and byte[]'s implicit conversion to ReadOnlyMemory<byte> turns even a null array
            //into a non-null (empty) ReadOnlyMemory<byte>, so the outer Nullable<ReadOnlyMemory<byte>>
            //would end up HasValue=true for an absent member. An explicit if/else keeps the null literal
            //assigned directly to the Nullable<ReadOnlyMemory<byte>> variable, with no array in between.
            ReadOnlyMemory<byte>? extensions;
            int? credProtect;
            bool? minPinLength;
            bool? largeBlobKey;
            bool? hmacSecret;
            CtapGetAssertionHmacSecretInput? hmacSecretMc;
            if(parameters.TryGetValue(WellKnownCtapMakeCredentialRequestKeys.Extensions, out ReadOnlyMemory<byte> extensionsCbor))
            {
                extensions = extensionsCbor.ToArray();
                (credProtect, minPinLength, largeBlobKey, hmacSecret, hmacSecretMc) = ReadExtensionValues(extensionsCbor);
            }
            else
            {
                extensions = null;
                credProtect = null;
                minPinLength = null;
                largeBlobKey = null;
                hmacSecret = null;
                hmacSecretMc = null;
            }

            CtapCommandOptions? options = parameters.TryGetValue(WellKnownCtapMakeCredentialRequestKeys.Options, out ReadOnlyMemory<byte> optionsCbor)
                ? CtapCommandEntityCborCodec.ReadOptions(new CborReader(optionsCbor, CborConformanceMode.Ctap2Canonical))
                : null;

            //See the remarks on the extensions member above for why this is an if/else, not a ternary.
            ReadOnlyMemory<byte>? pinUvAuthParam;
            if(parameters.TryGetValue(WellKnownCtapMakeCredentialRequestKeys.PinUvAuthParam, out ReadOnlyMemory<byte> pinUvAuthParamCbor))
            {
                pinUvAuthParam = new CborReader(pinUvAuthParamCbor, CborConformanceMode.Ctap2Canonical).ReadByteString();
            }
            else
            {
                pinUvAuthParam = null;
            }

            int? pinUvAuthProtocol = parameters.TryGetValue(WellKnownCtapMakeCredentialRequestKeys.PinUvAuthProtocol, out ReadOnlyMemory<byte> pinUvAuthProtocolCbor)
                ? checked((int)new CborReader(pinUvAuthProtocolCbor, CborConformanceMode.Ctap2Canonical).ReadInt64())
                : null;

            int? enterpriseAttestation = parameters.TryGetValue(WellKnownCtapMakeCredentialRequestKeys.EnterpriseAttestation, out ReadOnlyMemory<byte> enterpriseAttestationCbor)
                ? checked((int)new CborReader(enterpriseAttestationCbor, CborConformanceMode.Ctap2Canonical).ReadInt64())
                : null;

            List<string>? attestationFormatsPreference = parameters.TryGetValue(WellKnownCtapMakeCredentialRequestKeys.AttestationFormatsPreference, out ReadOnlyMemory<byte> attestationFormatsPreferenceCbor)
                ? CtapCommandEntityCborCodec.ReadStringArray(new CborReader(attestationFormatsPreferenceCbor, CborConformanceMode.Ctap2Canonical))
                : null;

            //DigestValue.Create is deferred to this final step (every other member already decoded
            //successfully) so no disposal-on-failure path is needed for it.
            IMemoryOwner<byte> clientDataHashOwner = pool.Rent(clientDataHashBytes.Length);
            clientDataHashBytes.AsSpan().CopyTo(clientDataHashOwner.Memory.Span);

            return new CtapMakeCredentialRequest(
                new DigestValue(clientDataHashOwner, CryptoTags.Sha256Digest),
                rp,
                user,
                pubKeyCredParams,
                excludeList,
                extensions,
                options,
                pinUvAuthParam,
                pinUvAuthProtocol,
                enterpriseAttestation,
                attestationFormatsPreference,
                credProtect,
                minPinLength,
                largeBlobKey,
                hmacSecret,
                hmacSecretMc);
        }
        catch(CborContentException exception)
        {
            DisposeAll(user, excludeList);
            throw new Fido2FormatException(Fido2FormatFailureKind.MalformedCbor, "The authenticatorMakeCredential request parameter bytes are not valid CTAP2 canonical CBOR.", exception);
        }
        catch(Exception exception) when(exception is InvalidOperationException or OverflowException)
        {
            DisposeAll(user, excludeList);
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The authenticatorMakeCredential request carries a member of an unexpected CBOR type.", exception);
        }
        catch
        {
            DisposeAll(user, excludeList);
            throw;
        }

        //Looks up a Required top-level member's still-encoded bytes, failing closed with the member's
        //wire name if absent — classified MissingRequiredParameter (R7's third bucket), distinct from
        //a nested structure's own missing member (UnexpectedStructure).
        static ReadOnlyMemory<byte> RequireMember(IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters, int key, string memberName)
        {
            if(!parameters.TryGetValue(key, out ReadOnlyMemory<byte> value))
            {
                throw new Fido2FormatException(Fido2FormatFailureKind.MissingRequiredParameter, $"The authenticatorMakeCredential request is missing the required '{memberName}' member.");
            }

            return value;
        }

        //Disposes the user handle and any excludeList credential identifiers already constructed before
        //a later member failed to decode, so a rejected request never leaks pooled memory.
        static void DisposeAll(CtapPublicKeyCredentialUserEntity? user, List<PublicKeyCredentialDescriptor>? excludeList)
        {
            user?.Id.Dispose();

            if(excludeList is not null)
            {
                foreach(PublicKeyCredentialDescriptor descriptor in excludeList)
                {
                    descriptor.Id.Dispose();
                }
            }
        }

        //Decodes the extensions map's five known keys ("credProtect", "minPinLength", "largeBlobKey",
        //"hmac-secret", "hmac-secret-mc") into pre-decoded convenience values, mirroring
        //CtapAuthenticatorConfigRequestCborReader's own ReadSubCommandParams shape for "small decoded
        //sub-map, unknown members simply have no case". Any other top-level key is skipped rather than
        //rejected, per CTAP 2.3 section 6.1.2 line 3553's "process any extensions that this authenticator
        //supports, ignoring any that it does not support" rule. A member whose value has the wrong CBOR
        //type for its known key (e.g. credProtect as a text string) throws the same way every other
        //wrong-typed known top-level member in this reader does — ReadInt64/ReadBoolean throw
        //InvalidOperationException/CborContentException, caught by this method's own surrounding catch and
        //rethrown as Fido2FormatException; no bespoke leniency for extension-map members the rest of this
        //reader does not also grant its own known members. Value-range validation (credProtect's own
        //{1, 2, 3} legal set, largeBlobKey's own true-only legal set, hmac-secret's own literal-true gate,
        //hmac-secret-mc's own pairing gate against hmac-secret) is a transition-level concern, not this
        //reader's: it reports whatever value arrived on the wire, including an explicit false.
        static (int? CredProtect, bool? MinPinLength, bool? LargeBlobKey, bool? HmacSecret, CtapGetAssertionHmacSecretInput? HmacSecretMc) ReadExtensionValues(ReadOnlyMemory<byte> extensionsCbor)
        {
            var reader = new CborReader(extensionsCbor, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            int? credProtect = null;
            bool? minPinLength = null;
            bool? largeBlobKey = null;
            bool? hmacSecret = null;
            CtapGetAssertionHmacSecretInput? hmacSecretMc = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                string identifier = reader.ReadTextString();
                entriesRead++;

                //WellKnownWebAuthnExtensionIdentifiers members are static readonly interned strings (so
                //IsXxx's ReferenceEquals fast path applies), not const, so this is a guarded switch over
                //a pattern variable rather than constant case labels.
                switch(identifier)
                {
                    case var name when WellKnownWebAuthnExtensionIdentifiers.IsCredProtect(name):
                    {
                        credProtect = checked((int)reader.ReadInt64());
                        break;
                    }
                    case var name when WellKnownWebAuthnExtensionIdentifiers.IsMinPinLength(name):
                    {
                        minPinLength = reader.ReadBoolean();
                        break;
                    }
                    case var name when WellKnownWebAuthnExtensionIdentifiers.IsLargeBlobKey(name):
                    {
                        largeBlobKey = reader.ReadBoolean();
                        break;
                    }
                    case var name when WellKnownWebAuthnExtensionIdentifiers.IsHmacSecret(name):
                    {
                        hmacSecret = reader.ReadBoolean();
                        break;
                    }
                    case var name when WellKnownWebAuthnExtensionIdentifiers.IsHmacSecretMc(name):
                    {
                        hmacSecretMc = ReadHmacSecretMcCompoundValue(reader);
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

            return (credProtect, minPinLength, largeBlobKey, hmacSecret, hmacSecretMc);
        }

        //Decodes the "hmac-secret-mc" extension value's own nested map (CTAP 2.3 §12.8, snapshot line
        //13402: "the same as the hmac secret extension's getAssertion input") — the IDENTICAL
        //keyAgreement/saltEnc/saltAuth/pinUvAuthProtocol shape
        //CtapGetAssertionRequestCborReader.ReadHmacSecretCompoundValue decodes for ga's own "hmac-secret"
        //input, duplicated here rather than shared: each CTAP request reader owns its own local decode
        //functions, mirroring this reader's own ReadExtensionValues/ga's own independently-shaped one.
        //`reader` is already positioned immediately after the "hmac-secret-mc" text-string key.
        static CtapGetAssertionHmacSecretInput ReadHmacSecretMcCompoundValue(CborReader reader)
        {
            int? entryCount = reader.ReadStartMap();

            CoseKey? keyAgreement = null;
            ReadOnlyMemory<byte>? saltEnc = null;
            ReadOnlyMemory<byte>? saltAuth = null;
            int? pinUvAuthProtocol = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                int key = checked((int)reader.ReadInt64());
                entriesRead++;

                switch(key)
                {
                    case(WellKnownCtapHmacSecretExtensionKeys.KeyAgreement):
                    {
                        ReadOnlyMemory<byte> keyAgreementCbor = reader.ReadEncodedValue();
                        keyAgreement = CredentialPublicKeyCborReader.Read(keyAgreementCbor).CoseKey;
                        break;
                    }
                    case(WellKnownCtapHmacSecretExtensionKeys.SaltEnc):
                    {
                        saltEnc = reader.ReadByteString();
                        break;
                    }
                    case(WellKnownCtapHmacSecretExtensionKeys.SaltAuth):
                    {
                        saltAuth = reader.ReadByteString();
                        break;
                    }
                    case(WellKnownCtapHmacSecretExtensionKeys.PinUvAuthProtocol):
                    {
                        pinUvAuthProtocol = checked((int)reader.ReadInt64());
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

            if(keyAgreement is null || saltEnc is null || saltAuth is null)
            {
                throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure,
                    "The authenticatorMakeCredential request's 'hmac-secret-mc' extension map is missing a required member ('keyAgreement', 'saltEnc', or 'saltAuth').");
            }

            return new CtapGetAssertionHmacSecretInput(keyAgreement, saltEnc.Value, saltAuth.Value, pinUvAuthProtocol);
        }
    }
}
