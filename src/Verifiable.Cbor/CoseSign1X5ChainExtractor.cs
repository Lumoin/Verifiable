using Lumoin.Veritas.Cbor;
using System.Buffers;
using System.Globalization;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cbor;

/// <summary>
/// Extracts the <c>x5chain</c> COSE unprotected header parameter (label 33) from any COSE_Sign1's
/// wire bytes, returning the certificates as a chain-ordered list of
/// <see cref="PkiCertificateMemory"/>.
/// </summary>
/// <remarks>
/// <para>
/// Per RFC 9360 §2 the value is either a single bstr (one certificate) or an array of bstrs
/// (multiple certificates, leaf first). The extractor accepts both shapes and normalises to a list.
/// Ownership of the returned <see cref="PkiCertificateMemory"/> instances transfers to the caller —
/// dispose them after use.
/// </para>
/// <para>
/// COSE-generic: it reads any COSE_Sign1's unprotected header, not only an mdoc IssuerAuth's — the
/// mdoc verify path and the SD-CWT verify path (through
/// <see cref="Verifiable.Core.Model.SelectiveDisclosure.ExtractCoseSign1X5ChainDelegate"/>) both wire
/// this same reader.
/// </para>
/// </remarks>
public static class CoseSign1X5ChainExtractor
{
    /// <summary>
    /// Reads the <c>x5chain</c> from the supplied COSE_Sign1 wire bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every label of the unprotected bucket is read as RFC 9052 Section 1.5 defines it, any CBOR integer read whole
    /// or a text string, and judged for a repeat on its decoded value; a well-formed label other than 33 is passed
    /// over with its value, and a second label 33 is refused, never merged into the first.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "When processing
    /// messages, if a label appears multiple times, the message MUST be rejected as malformed."
    /// </para>
    /// <para>
    /// This is a seam-boundary method: an application wires it as the verifier's <c>x5chain</c> reader, so input it
    /// refuses is answered as <see cref="FormatException"/>, the failure the verifier answers as a malformed
    /// presentation, rather than left to a caller who cannot name the CBOR reader's own exceptions. Every
    /// certificate read before the refusal is returned to the pool first.
    /// </para>
    /// </remarks>
    /// <param name="encodedCoseSign1">The COSE_Sign1 wire bytes (Tag 18 array).</param>
    /// <param name="pool">Memory pool for DER allocations.</param>
    /// <returns>
    /// Chain-ordered certificates (leaf first) when the header is present;
    /// an empty list when the header is absent. Caller disposes each entry.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="FormatException">
    /// Thrown when the COSE_Sign1 wire shape is malformed, when the <c>x5chain</c> value is neither a bstr nor an
    /// array of bstrs, when a label appears twice in the unprotected bucket, or when the bucket carries a map key
    /// that is neither an integer nor a text string; the CBOR reader's exception rides as the
    /// <see cref="Exception.InnerException"/>.
    /// </exception>
    public static IReadOnlyList<PkiCertificateMemory> Extract(
        ReadOnlyMemory<byte> encodedCoseSign1,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            var reader = new CborReader(encodedCoseSign1.ToArray(), CborOptions.Lax);

            //COSE_Sign1 = #6.18([protected, unprotected, payload, signature])
            CborTag tag = reader.ReadTag();
            if(tag.Value != 18)
            {
                throw new CborContentException($"Expected COSE_Sign1 Tag 18; got Tag {tag.Value}.");
            }

            int? arrayLength = reader.ReadStartArray();
            if(arrayLength != 4)
            {
                throw new CborContentException($"COSE_Sign1 array must have 4 elements; got {arrayLength}.");
            }

            //Skip protected header (bstr): x5chain is in the unprotected header
            //per RFC 9360 Section 2.
            reader.SkipValue();

            //Unprotected header: a CBOR map of labels. Don't bother walking the rest of the COSE_Sign1;
            //the chain is what is read.
            return ReadUnprotectedHeaderX5Chain(reader, pool);
        }
        catch(Exception exception) when(exception is not FormatException && CoseSerialization.IsMalformedInputException(exception))
        {
            throw new FormatException(
                "The COSE_Sign1's unprotected bucket does not carry a well-formed x5chain, or carries one label twice (RFC 9052 Section 3).",
                exception);
        }
    }


    /// <summary>
    /// Reads the unprotected bucket whole and answers the certificates of its <c>x5chain</c> (label 33), refusing a
    /// label the bucket carries twice; on any failure every certificate already read is returned to the pool before
    /// the failure leaves.
    /// </summary>
    /// <param name="reader">The reader, positioned at the unprotected bucket.</param>
    /// <param name="pool">Memory pool for DER allocations.</param>
    /// <returns>The chain-ordered certificates; empty when the bucket carries no <c>x5chain</c>.</returns>
    /// <exception cref="CborContentException">A label appears twice, a map key is neither an integer nor a text string, or the value is malformed.</exception>
    private static List<PkiCertificateMemory> ReadUnprotectedHeaderX5Chain(
        CborReader reader,
        BaseMemoryPool pool)
    {
        if(reader.PeekState() != CborReaderState.StartMap)
        {
            //Unprotected header should be a map; if not, no x5chain.
            return [];
        }

        int? entryCount = reader.ReadStartMap();

        List<PkiCertificateMemory> chain = [];
        HashSet<(Int128 Number, string? Text)> seenLabels = [];
        int entriesRead = 0;

        try
        {
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                (Int128 Number, string? Text) label = ReadLabel(reader);
                entriesRead++;

                //RFC 9052 Section 3: a label that appears twice in one map makes the message malformed;
                //a second x5chain is refused, never merged into the first.
                if(!seenLabels.Add(label))
                {
                    throw new CborContentException(
                        $"COSE header label {label.Text ?? label.Number.ToString(CultureInfo.InvariantCulture)} appears more than once in the unprotected bucket; the message is malformed (RFC 9052 Section 3).");
                }

                if(label is { Text: null } && label.Number == MdocCoseHeaderLabels.X5Chain)
                {
                    ReadX5ChainValue(reader, pool, chain);
                }
                else
                {
                    reader.SkipValue();
                }
            }

            reader.ReadEndMap();

            return chain;
        }
        catch
        {
            foreach(PkiCertificateMemory cert in chain)
            {
                cert.Dispose();
            }

            throw;
        }
    }


    /// <summary>
    /// Reads one COSE header-map label as RFC 9052 Section 1.5 defines it: any CBOR integer, negative or unsigned,
    /// read whole and never cast down, or a text string. Two labels are the same when their decoded values are
    /// equal; an integer and a text string are never the same. This is the one label read of this file.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "label = int / tstr"
    /// and "In a CBOR map defined by this specification, the presence a label that is neither a text string nor an
    /// integer is an error." This reader fails processing.
    /// </remarks>
    /// <param name="reader">The reader, positioned at a header-map label.</param>
    /// <returns>The decoded label: its integer value, or its text when it is a text string.</returns>
    /// <exception cref="CborContentException">The map key is neither an integer nor a text string.</exception>
    private static (Int128 Number, string? Text) ReadLabel(CborReader reader)
    {
        return reader.PeekState() switch
        {
            CborReaderState.UnsignedInteger => ((Int128)reader.ReadUInt64(), null),
            CborReaderState.NegativeInteger => (-1 - (Int128)reader.ReadCborNegativeIntegerRepresentation(), null),
            CborReaderState.TextString => (Int128.Zero, reader.ReadTextString()),
            CborReaderState otherState => throw new CborContentException(
                $"A COSE header label is an integer or a text string; the unprotected bucket carries a {otherState} map key (RFC 9052 Section 1.5).")
        };
    }


    /// <summary>Reads an <c>x5chain</c> value, a single bstr or an array of bstrs (RFC 9360 Section 2), into the chain.</summary>
    /// <param name="reader">The reader, positioned at the value.</param>
    /// <param name="pool">Memory pool for DER allocations.</param>
    /// <param name="chain">The chain the certificates are appended to.</param>
    /// <exception cref="CborContentException">The value is neither a bstr nor an array of bstrs.</exception>
    private static void ReadX5ChainValue(CborReader reader, BaseMemoryPool pool, List<PkiCertificateMemory> chain)
    {
        CborReaderState state = reader.PeekState();
        if(state == CborReaderState.ByteString)
        {
            //RFC 9360 §2 single-certificate form.
            chain.Add(CopyToPkiCertificate(reader.ReadByteString(), pool));
        }
        else if(state == CborReaderState.StartArray)
        {
            //RFC 9360 §2 multi-certificate form.
            int? certCount = reader.ReadStartArray();
            int certsRead = 0;

            while(certCount is null ? reader.PeekState() != CborReaderState.EndArray : certsRead < certCount.Value)
            {
                chain.Add(CopyToPkiCertificate(reader.ReadByteString(), pool));
                certsRead++;
            }

            reader.ReadEndArray();
        }
        else
        {
            throw new CborContentException(
                $"x5chain (label {MdocCoseHeaderLabels.X5Chain}) value must be a bstr or an array of bstrs per RFC 9360 §2; got CborReaderState.{state}.");
        }
    }


    /// <summary>Copies one DER certificate into a pool-rented certificate carrier.</summary>
    /// <param name="derBytes">The certificate's DER bytes.</param>
    /// <param name="pool">Memory pool the carrier rents from.</param>
    /// <returns>The certificate carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory CopyToPkiCertificate(byte[] derBytes, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }
}
