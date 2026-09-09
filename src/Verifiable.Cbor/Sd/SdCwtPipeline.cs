using System;
using System.Buffers;
using System.Collections.Generic;
using Lumoin.Veritas.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;

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
        GenerateDisclosureSaltDelegate generateSalt,
        string hashAlgorithm,
        BaseMemoryPool pool,
        DecoyDigestOptions decoyOptions)
    {
        byte[] payloadArray = payload.ToArray();

        var (cwtPayload, disclosures) = SdCwtClaimRedaction.Redact(
            payloadArray, disclosablePaths, generateSalt, hashAlgorithm, pool, decoyOptions);

        byte[] redactedBytes = SerializeCwtPayload(cwtPayload);
        return (redactedBytes, disclosures);
    }


    /// <summary>
    /// Signs a redacted CBOR payload as a COSE_Sign1 message using an explicit
    /// <see cref="SigningDelegate"/>. Registry resolution is the caller's concern
    /// (<see cref="SdCwtIssuance"/> resolves the function from the key's tag and
    /// forwards here); this keeps the pipeline a pure parameter-taking body. Matches
    /// <see cref="SignPayloadDelegate"/> exactly — that delegate type (and its method-group
    /// wiring throughout <c>Verifiable.Core</c>'s <c>SdCwtIssuanceExtensions</c> and every
    /// caller of <see cref="SdCwtIssuance.IssueVerboseAsync"/>) has no <c>CryptoEventSink</c>
    /// slot, so unlike the sink-threaded JOSE/COSE sites this one routes unconditionally to
    /// <see cref="CryptographicKeyEvents.DefaultSink"/> rather than accepting a per-call
    /// override — see <see cref="CryptoEventSink"/> for the two-route rationale.
    /// </summary>
    internal static async ValueTask<ReadOnlyMemory<byte>> Sign(
        SigningDelegate signingDelegate,
        ReadOnlyMemory<byte> redactedPayload,
        string hashAlgorithm,
        string mediaType,
        PrivateKeyMemory privateKey,
        string keyId,
        BaseMemoryPool memoryPool,
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

        (Signature signature, CryptoEvent? evt) = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            sigStructure,
            memoryPool,
            context: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if(evt is not null)
        {
            CryptographicKeyEvents.DefaultSink(evt);
        }

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
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
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
        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Builds the <c>Sig_structure</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.4">RFC 9052 Section 4.4</see>.
    /// </summary>
    private static byte[] BuildSigStructure(byte[] protectedHeader, ReadOnlySpan<byte> payload)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(4);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(protectedHeader);
        writer.WriteByteString([]);
        writer.WriteByteString(payload);
        writer.WriteEndArray();
        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Serializes COSE_Sign1 as <c>#6.18([protected, unprotected, payload, signature])</c>.
    /// </summary>
    private static byte[] SerializeCoseSign1(
        byte[] protectedHeader, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteTag(new CborTag((ulong)CoseTags.Sign1));
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedHeader);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString(payload);
        writer.WriteByteString(signature);
        writer.WriteEndArray();
        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Serializes a <see cref="CwtPayload"/> to CBOR bytes, mapping every
    /// <see cref="CwtDigestPlacement.RedactedClaimKeysSentinel"/> entry to <c>simple(59)</c>
    /// through <see cref="WriteRedactedMap"/>.
    /// </summary>
    private static byte[] SerializeCwtPayload(CwtPayload payload)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        WriteRedactedMap(writer, payload);

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Writes an integer-keyed CWT claims map, mapping <see cref="CwtDigestPlacement.RedactedClaimKeysSentinel"/>
    /// to <c>simple(59)</c> at THIS level and recursing into every other value through
    /// <see cref="WriteRedactedValue"/> so a sentinel placed under a nested disclosable object
    /// (RFC 9901 §4.2.6 recursive disclosures — a digest array can sit at any level, not only the
    /// root) reaches the wire the same way as one at the root.
    /// </summary>
    private static void WriteRedactedMap(CborWriter writer, IDictionary<int, object> map)
    {
        writer.WriteStartMap(map.Count);

        foreach(KeyValuePair<int, object> entry in map)
        {
            if(entry.Key == CwtDigestPlacement.RedactedClaimKeysSentinel)
            {
                writer.WriteSimpleValue(SdCwtConstants.RedactedClaimKeysSimpleValue);
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
                WriteRedactedValue(writer, entry.Value);
            }
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes a single CWT claim value, recursing into a nested claims map through
    /// <see cref="WriteRedactedMap"/> and into an array element by element (a nested disclosable
    /// map can sit inside an array), and delegating every other shape — the leaves the SD-CWT
    /// redaction vocabulary has no opinion on — to <see cref="CborValueConverter.WriteValue(CborWriter, object)"/>,
    /// which stays unaware of the sentinel because it is SD-CWT vocabulary, not a general CBOR concept.
    /// </summary>
    private static void WriteRedactedValue(CborWriter writer, object? value)
    {
        switch(value)
        {
            case IDictionary<int, object> nestedMap:
            {
                WriteRedactedMap(writer, nestedMap);
                break;
            }
            case IEnumerable<object?> items:
            {
                IReadOnlyList<object?> list = items as IReadOnlyList<object?> ?? [.. items];
                writer.WriteStartArray(list.Count);
                foreach(object? item in list)
                {
                    WriteRedactedValue(writer, item);
                }

                writer.WriteEndArray();
                break;
            }
            default:
            {
                CborValueConverter.WriteValue(writer, value);
                break;
            }
        }
    }
}
