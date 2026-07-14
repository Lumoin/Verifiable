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
/// The shipped default for <see cref="DecodeCtapGetAssertionRequestDelegate"/>: decodes an
/// <c>authenticatorGetAssertion</c> request's CTAP2-canonical CBOR parameter map into its typed model —
/// the authenticator-side operation, composing <see cref="CtapParameterMapReader"/> exactly as
/// <see cref="CtapMakeCredentialRequestCborReader"/> does.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2: authenticatorGetAssertion (0x02)</see>. Per section 8's forward-compatibility
/// rule, any top-level key this reader does not model is skipped rather than rejected. The
/// <c>clientDataHash</c> digest and any <c>allowList</c> credential identifiers are both tracked outside
/// their parse block and disposed if a later member fails to decode, so a rejected request never leaks
/// pooled memory — mirrors <see cref="CtapMakeCredentialRequestCborReader"/>'s own convention. When
/// present, <c>Extensions</c> is additionally scanned for its <c>largeBlobKey</c> key (CTAP 2.3 §12.3),
/// decoded into <see cref="CtapGetAssertionRequest.LargeBlobKey"/> (wavelb R8), and its <c>hmac-secret</c>
/// key (CTAP 2.3 §12.7, snapshot lines 13228-13248), decoded into
/// <see cref="CtapGetAssertionRequest.HmacSecret"/> — this request type's first COMPOUND (nested-map)
/// extension value; <c>keyAgreement</c>'s nested COSE_Key reuses <see cref="CredentialPublicKeyCborReader"/>,
/// mirroring <see cref="CtapClientPinRequestCborReader"/>'s own convention.
/// </remarks>
public static class CtapGetAssertionRequestCborReader
{
    /// <summary>
    /// Decodes <paramref name="parametersCbor"/> into a <see cref="CtapGetAssertionRequest"/>.
    /// Method-group-compatible with <see cref="DecodeCtapGetAssertionRequestDelegate"/>.
    /// </summary>
    /// <param name="parametersCbor">The CBOR-encoded parameter map.</param>
    /// <param name="pool">
    /// The memory pool the decoded <c>clientDataHash</c> and any <c>allowList</c> credential
    /// identifiers rent from.
    /// </param>
    /// <returns>The decoded request model.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR (classified
    /// <see cref="Fido2FormatFailureKind.MalformedCbor"/>), omits a Required top-level member
    /// (<c>rpId</c> or <c>clientDataHash</c>; classified
    /// <see cref="Fido2FormatFailureKind.MissingRequiredParameter"/>), or carries a member of the wrong
    /// CBOR type, including the <c>hmac-secret</c> compound value's own missing required member
    /// (classified <see cref="Fido2FormatFailureKind.UnexpectedStructure"/>).
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "clientDataHash's ownership transfers to the returned CtapGetAssertionRequest on success and is explicitly disposed in the surrounding catch block on failure — the CA2000 flag is a false positive; the analyzer cannot see across the local ReadDigest function boundary.")]
    public static CtapGetAssertionRequest Read(ReadOnlyMemory<byte> parametersCbor, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters = CtapParameterMapReader.Read(parametersCbor);

        try
        {
            string rpId = new CborReader(
                RequireMember(parameters, WellKnownCtapGetAssertionRequestKeys.RpId, "rpId"), CborConformanceMode.Ctap2Canonical).ReadTextString();

            DigestValue clientDataHash = ReadDigest(
                RequireMember(parameters, WellKnownCtapGetAssertionRequestKeys.ClientDataHash, "clientDataHash"), pool);

            //Tracked outside the inner try so a failure decoding a later member can dispose the allowList
            //credential identifiers already constructed, alongside clientDataHash — mirrors
            //CtapMakeCredentialRequestCborReader's disposal-on-failure convention.
            List<PublicKeyCredentialDescriptor>? allowList = null;
            try
            {
                allowList = parameters.TryGetValue(WellKnownCtapGetAssertionRequestKeys.AllowList, out ReadOnlyMemory<byte> allowListCbor)
                    ? CtapCommandEntityCborCodec.ReadDescriptorArray(new CborReader(allowListCbor, CborConformanceMode.Ctap2Canonical), pool)
                    : null;

                //Assigned via an explicit if/else rather than a ternary: a ternary whose "present" branch
                //is a byte[] and whose "absent" branch is the null literal infers a byte[]-typed
                //conditional expression, and byte[]'s implicit conversion to ReadOnlyMemory<byte> turns
                //even a null array into a non-null (empty) ReadOnlyMemory<byte>, so the outer
                //Nullable<ReadOnlyMemory<byte>> would end up HasValue=true for an absent member. An
                //explicit if/else keeps the null literal assigned directly to the
                //Nullable<ReadOnlyMemory<byte>> variable, with no array in between.
                ReadOnlyMemory<byte>? extensions;
                bool? largeBlobKey;
                CtapGetAssertionHmacSecretInput? hmacSecret;
                if(parameters.TryGetValue(WellKnownCtapGetAssertionRequestKeys.Extensions, out ReadOnlyMemory<byte> extensionsCbor))
                {
                    extensions = extensionsCbor.ToArray();
                    (largeBlobKey, hmacSecret) = ReadExtensionValues(extensionsCbor);
                }
                else
                {
                    extensions = null;
                    largeBlobKey = null;
                    hmacSecret = null;
                }

                CtapCommandOptions? options = parameters.TryGetValue(WellKnownCtapGetAssertionRequestKeys.Options, out ReadOnlyMemory<byte> optionsCbor)
                    ? CtapCommandEntityCborCodec.ReadOptions(new CborReader(optionsCbor, CborConformanceMode.Ctap2Canonical))
                    : null;

                //See the remarks on the extensions member above for why this is an if/else, not a ternary.
                ReadOnlyMemory<byte>? pinUvAuthParam;
                if(parameters.TryGetValue(WellKnownCtapGetAssertionRequestKeys.PinUvAuthParam, out ReadOnlyMemory<byte> pinUvAuthParamCbor))
                {
                    pinUvAuthParam = new CborReader(pinUvAuthParamCbor, CborConformanceMode.Ctap2Canonical).ReadByteString();
                }
                else
                {
                    pinUvAuthParam = null;
                }

                int? pinUvAuthProtocol = parameters.TryGetValue(WellKnownCtapGetAssertionRequestKeys.PinUvAuthProtocol, out ReadOnlyMemory<byte> pinUvAuthProtocolCbor)
                    ? checked((int)new CborReader(pinUvAuthProtocolCbor, CborConformanceMode.Ctap2Canonical).ReadInt64())
                    : null;

                return new CtapGetAssertionRequest(
                    rpId,
                    clientDataHash,
                    allowList,
                    extensions,
                    options,
                    pinUvAuthParam,
                    pinUvAuthProtocol,
                    largeBlobKey,
                    hmacSecret);
            }
            catch
            {
                clientDataHash.Dispose();
                DisposeAllowList(allowList);
                throw;
            }
        }
        catch(CborContentException exception)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.MalformedCbor, "The authenticatorGetAssertion request parameter bytes are not valid CTAP2 canonical CBOR.", exception);
        }
        catch(Exception exception) when(exception is InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The authenticatorGetAssertion request carries a member of an unexpected CBOR type.", exception);
        }

        //Looks up a Required top-level member's still-encoded bytes, failing closed with the member's
        //wire name if absent — classified MissingRequiredParameter (R7's third bucket), distinct from
        //a nested structure's own missing member (UnexpectedStructure).
        static ReadOnlyMemory<byte> RequireMember(IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters, int key, string memberName)
        {
            if(!parameters.TryGetValue(key, out ReadOnlyMemory<byte> value))
            {
                throw new Fido2FormatException(Fido2FormatFailureKind.MissingRequiredParameter, $"The authenticatorGetAssertion request is missing the required '{memberName}' member.");
            }

            return value;
        }

        //Decodes the required clientDataHash byte string into a pooled, SHA-256-tagged carrier.
        static DigestValue ReadDigest(ReadOnlyMemory<byte> encodedValue, MemoryPool<byte> pool)
        {
            var nestedReader = new CborReader(encodedValue, CborConformanceMode.Ctap2Canonical);
            byte[] bytes = nestedReader.ReadByteString();

            IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
            try
            {
                bytes.AsSpan().CopyTo(owner.Memory.Span);

                return new DigestValue(owner, CryptoTags.Sha256Digest);
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }

        //Disposes any allowList credential identifiers already constructed before a later member failed
        //to decode, so a rejected request never leaks pooled memory.
        static void DisposeAllowList(List<PublicKeyCredentialDescriptor>? allowList)
        {
            if(allowList is not null)
            {
                foreach(PublicKeyCredentialDescriptor descriptor in allowList)
                {
                    descriptor.Id.Dispose();
                }
            }
        }

        //Decodes the extensions map's two known keys this request pre-decodes ("largeBlobKey", CTAP 2.3
        //§12.3, scalar; "hmac-secret", CTAP 2.3 §12.7, compound), mirroring
        //CtapMakeCredentialRequestCborReader's own ReadExtensionValues shape. Any other top-level key is
        //skipped rather than rejected, per section 8's forward-compatibility rule. Value-range validation
        //(largeBlobKey's own true-only legal set, hmac-secret's own protocol defaulting/support checks)
        //is a transition-level concern, not this reader's.
        static (bool? LargeBlobKey, CtapGetAssertionHmacSecretInput? HmacSecret) ReadExtensionValues(ReadOnlyMemory<byte> extensionsCbor)
        {
            var reader = new CborReader(extensionsCbor, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            bool? largeBlobKey = null;
            CtapGetAssertionHmacSecretInput? hmacSecret = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                string identifier = reader.ReadTextString();
                entriesRead++;

                _ = identifier switch
                {
                    var id when WellKnownWebAuthnExtensionIdentifiers.IsLargeBlobKey(id) => AssignLargeBlobKey(reader, ref largeBlobKey),
                    var id when WellKnownWebAuthnExtensionIdentifiers.IsHmacSecret(id) => AssignHmacSecret(reader, ref hmacSecret),
                    _ => SkipExtensionValue(reader)
                };
            }

            reader.ReadEndMap();

            return (largeBlobKey, hmacSecret);

            //Assigns the decoded largeBlobKey flag.
            static bool AssignLargeBlobKey(CborReader reader, ref bool? largeBlobKey)
            {
                largeBlobKey = reader.ReadBoolean();

                return true;
            }

            //Assigns the decoded hmac-secret compound value.
            static bool AssignHmacSecret(CborReader reader, ref CtapGetAssertionHmacSecretInput? hmacSecret)
            {
                hmacSecret = ReadHmacSecretCompoundValue(reader);

                return true;
            }

            //Skips an unrecognised extension identifier's value, per section 8's forward-compatibility rule.
            static bool SkipExtensionValue(CborReader reader)
            {
                reader.SkipValue();

                return true;
            }
        }

        //Decodes the "hmac-secret" extension value's own nested map (CTAP 2.3 §12.7, snapshot lines
        //13228-13248): keyAgreement/saltEnc/saltAuth Required, pinUvAuthProtocol Optional. `reader` is
        //already positioned immediately after the "hmac-secret" text-string key, so this call decodes
        //the nested map value in place — the identical "small decoded sub-map" shape
        //CtapAuthenticatorConfigRequestCborReader.ReadSubCommandParams uses for its own nested maps.
        static CtapGetAssertionHmacSecretInput ReadHmacSecretCompoundValue(CborReader reader)
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

                _ = key switch
                {
                    WellKnownCtapHmacSecretExtensionKeys.KeyAgreement => AssignKeyAgreement(reader, ref keyAgreement),
                    WellKnownCtapHmacSecretExtensionKeys.SaltEnc => AssignSaltEnc(reader, ref saltEnc),
                    WellKnownCtapHmacSecretExtensionKeys.SaltAuth => AssignSaltAuth(reader, ref saltAuth),
                    WellKnownCtapHmacSecretExtensionKeys.PinUvAuthProtocol => AssignPinUvAuthProtocol(reader, ref pinUvAuthProtocol),
                    _ => SkipHmacSecretValue(reader)
                };
            }

            reader.ReadEndMap();

            if(keyAgreement is null || saltEnc is null || saltAuth is null)
            {
                throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure,
                    "The authenticatorGetAssertion request's 'hmac-secret' extension map is missing a required member ('keyAgreement', 'saltEnc', or 'saltAuth').");
            }

            return new CtapGetAssertionHmacSecretInput(keyAgreement, saltEnc.Value, saltAuth.Value, pinUvAuthProtocol);

            //Assigns the decoded keyAgreement COSE_Key.
            static bool AssignKeyAgreement(CborReader reader, ref CoseKey? keyAgreement)
            {
                ReadOnlyMemory<byte> keyAgreementCbor = reader.ReadEncodedValue();
                keyAgreement = CredentialPublicKeyCborReader.Read(keyAgreementCbor).CoseKey;

                return true;
            }

            //Assigns the decoded saltEnc byte string.
            static bool AssignSaltEnc(CborReader reader, ref ReadOnlyMemory<byte>? saltEnc)
            {
                saltEnc = reader.ReadByteString();

                return true;
            }

            //Assigns the decoded saltAuth byte string.
            static bool AssignSaltAuth(CborReader reader, ref ReadOnlyMemory<byte>? saltAuth)
            {
                saltAuth = reader.ReadByteString();

                return true;
            }

            //Assigns the decoded pinUvAuthProtocol identifier.
            static bool AssignPinUvAuthProtocol(CborReader reader, ref int? pinUvAuthProtocol)
            {
                pinUvAuthProtocol = checked((int)reader.ReadInt64());

                return true;
            }

            //Skips an unrecognised hmac-secret map member's value, per section 8's forward-compatibility rule.
            static bool SkipHmacSecretValue(CborReader reader)
            {
                reader.SkipValue();

                return true;
            }
        }
    }
}
