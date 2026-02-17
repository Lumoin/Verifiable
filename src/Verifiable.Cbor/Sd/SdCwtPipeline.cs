using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Sd;

namespace Verifiable.Cbor.Sd;

/// <summary>
/// Internal implementation of <see cref="RedactPayloadDelegate"/> and
/// <see cref="SignPayloadDelegate"/> for SD-CWT per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt</see>.
/// </summary>
internal static class SdCwtPipeline
{
    /// <summary>
    /// Redacts selectively disclosable claims from a CBOR-encoded CWT claims set.
    /// </summary>
    internal static (ReadOnlyMemory<byte> RedactedPayload, IReadOnlyList<SdDisclosure> Disclosures) Redact(
        ReadOnlyMemory<byte> payload,
        IReadOnlySet<CredentialPath> disclosablePaths,
        SaltFactoryDelegate saltFactory,
        string hashAlgorithm)
    {
        byte[] payloadArray = payload.ToArray();

        var (cwtPayload, disclosures) = SdCwtClaimRedaction.Redact(
            payloadArray, disclosablePaths, saltFactory, hashAlgorithm);

        byte[] redactedBytes = SerializeCwtPayload(cwtPayload);
        return (redactedBytes, disclosures);
    }


    /// <summary>
    /// Signs a redacted CBOR payload as a COSE_Sign1 message.
    /// </summary>
    internal static async ValueTask<ReadOnlyMemory<byte>> Sign(
        ReadOnlyMemory<byte> redactedPayload,
        string hashAlgorithm,
        string mediaType,
        PrivateKeyMemory privateKey,
        string keyId,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        string resolvedMediaType = string.IsNullOrEmpty(mediaType)
            ? WellKnownMediaTypes.Application.SdCwt
            : mediaType;

        int coseAlgorithm = CryptoFormatConversions.DefaultTagToCoseConverter(privateKey.Tag);
        int sdAlg = SdCwtConstants.GetSdAlgFromIanaName(hashAlgorithm);

        //Build protected header as CBOR map.
        byte[] protectedHeaderBytes = BuildProtectedHeader(coseAlgorithm, keyId, resolvedMediaType, sdAlg);

        //Build Sig_structure per RFC 9052 Section 4.4.
        byte[] sigStructure = BuildSigStructure(protectedHeaderBytes, redactedPayload.Span);

        //Sign via the crypto registry.
        CryptoAlgorithm cryptoAlgorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(cryptoAlgorithm, purpose);

        Signature signature = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            sigStructure,
            memoryPool,
            context: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        //Serialize COSE_Sign1 = #6.18([protected, unprotected, payload, signature]).
        byte[] coseSign1 = SerializeCoseSign1(
            protectedHeaderBytes, redactedPayload.Span, signature.AsReadOnlyMemory().Span);

        return coseSign1;
    }


    /// <summary>
    /// Builds the COSE protected header containing <c>alg</c>, <c>kid</c>, <c>typ</c>, and <c>sd_alg</c>.
    /// </summary>
    private static byte[] BuildProtectedHeader(int algorithm, string keyId, string mediaType, int sdAlg)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(4);
        writer.WriteInt32(CoseHeaderParameters.Alg);
        writer.WriteInt32(algorithm);
        writer.WriteInt32(CoseHeaderParameters.Kid);
        writer.WriteTextString(keyId);
        writer.WriteInt32(CoseHeaderParameters.Typ);
        writer.WriteTextString(mediaType);
        writer.WriteInt32(SdCwtConstants.SdAlgHeaderKey);
        writer.WriteInt32(sdAlg);
        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>
    /// Builds the <c>Sig_structure</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.4">RFC 9052 Section 4.4</see>.
    /// </summary>
    private static byte[] BuildSigStructure(byte[] protectedHeader, ReadOnlySpan<byte> payload)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(4);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(protectedHeader);
        writer.WriteByteString([]);
        writer.WriteByteString(payload);
        writer.WriteEndArray();
        return writer.Encode();
    }


    /// <summary>
    /// Serializes COSE_Sign1 as <c>#6.18([protected, unprotected, payload, signature])</c>.
    /// </summary>
    private static byte[] SerializeCoseSign1(
        byte[] protectedHeader, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)CoseTags.Sign1);
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedHeader);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString(payload);
        writer.WriteByteString(signature);
        writer.WriteEndArray();
        return writer.Encode();
    }


    /// <summary>
    /// Serializes a <see cref="CwtPayload"/> to CBOR bytes, mapping the
    /// <see cref="CwtDigestPlacement.RedactedClaimKeysSentinel"/> to <c>simple(59)</c>.
    /// </summary>
    private static byte[] SerializeCwtPayload(CwtPayload payload)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(payload.Count);

        foreach(KeyValuePair<int, object> entry in payload)
        {
            if(entry.Key == CwtDigestPlacement.RedactedClaimKeysSentinel)
            {
                writer.WriteSimpleValue((CborSimpleValue)SdCwtConstants.RedactedClaimKeysSimpleValue);
                var digests = (List<byte[]>)entry.Value;
                writer.WriteStartArray(digests.Count);
                foreach(byte[] digest in digests)
                {
                    writer.WriteByteString(digest);
                }

                writer.WriteEndArray();
            }
            else
            {
                writer.WriteInt32(entry.Key);
                CborValueConverter.WriteValue(writer, entry.Value);
            }
        }

        writer.WriteEndMap();
        return writer.Encode();
    }
}