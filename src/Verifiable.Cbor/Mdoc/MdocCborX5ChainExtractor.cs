using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Extracts the <c>x5chain</c> COSE unprotected header parameter (label 33)
/// from an <see cref="MdocIssuerAuth"/>'s COSE_Sign1 wire bytes, returning
/// the certificates as a chain-ordered list of
/// <see cref="PkiCertificateMemory"/>.
/// </summary>
/// <remarks>
/// <para>
/// Per RFC 9360 §2 the value is either a single bstr (one certificate) or
/// an array of bstrs (multiple certificates, leaf first). The extractor
/// accepts both shapes and normalises to a list. Ownership of the returned
/// <see cref="PkiCertificateMemory"/> instances transfers to the caller —
/// dispose them after chain validation completes.
/// </para>
/// </remarks>
public static class MdocCborX5ChainExtractor
{
    /// <summary>
    /// Reads the <c>x5chain</c> from the supplied IssuerAuth COSE_Sign1
    /// wire bytes.
    /// </summary>
    /// <param name="encodedCoseSign1">The COSE_Sign1 wire bytes (Tag 18 array).</param>
    /// <param name="pool">Memory pool for DER allocations.</param>
    /// <returns>
    /// Chain-ordered certificates (leaf first) when the header is present;
    /// an empty list when the header is absent. Caller disposes each entry.
    /// </returns>
    /// <exception cref="CborContentException">
    /// Thrown when the COSE_Sign1 wire shape is malformed or the
    /// <c>x5chain</c> value is neither a bstr nor an array of bstrs.
    /// </exception>
    public static IReadOnlyList<PkiCertificateMemory> Extract(
        ReadOnlyMemory<byte> encodedCoseSign1,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new CborReader(encodedCoseSign1.ToArray(), CborConformanceMode.Lax);

        //COSE_Sign1 = #6.18([protected, unprotected, payload, signature])
        CborTag tag = reader.ReadTag();
        if((int)tag != 18)
        {
            throw new CborContentException($"Expected COSE_Sign1 Tag 18; got Tag {(int)tag}.");
        }

        int? arrayLength = reader.ReadStartArray();
        if(arrayLength != 4)
        {
            throw new CborContentException($"COSE_Sign1 array must have 4 elements; got {arrayLength}.");
        }

        //Skip protected header (bstr) — x5chain is in the unprotected header
        //per RFC 9360 §2.
        reader.SkipValue();

        //Unprotected header: integer-keyed CBOR map.
        IReadOnlyList<PkiCertificateMemory> chain = ReadUnprotectedHeaderX5Chain(reader, pool);

        //Don't bother walking the rest of the COSE_Sign1; we've got what we need.
        return chain;
    }


    private static List<PkiCertificateMemory> ReadUnprotectedHeaderX5Chain(
        CborReader reader,
        MemoryPool<byte> pool)
    {
        if(reader.PeekState() != CborReaderState.StartMap)
        {
            //Unprotected header should be a map; if not, no x5chain.
            return [];
        }

        int? entryCount = reader.ReadStartMap();

        List<PkiCertificateMemory> chain = [];
        int entriesRead = 0;

        try
        {
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                int label = (int)reader.ReadInt64();
                entriesRead++;

                if(label == MdocCoseHeaderLabels.X5Chain)
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


    private static void ReadX5ChainValue(CborReader reader, MemoryPool<byte> pool, List<PkiCertificateMemory> chain)
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


    private static PkiCertificateMemory CopyToPkiCertificate(byte[] derBytes, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }
}
