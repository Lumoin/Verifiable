using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The parsed LDS Security Object — the signed content of an ICAO Doc 9303 eMRTD EF.SOD: the hash
/// algorithm and the expected hash of each data group present on the chip.
/// </summary>
/// <remarks>
/// <para>
/// The LDS Security Object is the <c>eContent</c> of the EF.SOD CMS SignedData. Its ASN.1 structure
/// is a SEQUENCE of the version, a <c>DigestAlgorithmIdentifier</c>, and a SEQUENCE OF
/// <c>DataGroupHash</c> (each a data-group number and the hash of that data group's file). Passive
/// Authentication recomputes each read data group's hash and compares it against the value here,
/// after the SignedData signature has been verified and the signer chained to a CSCA.
/// </para>
/// <para>
/// The expected hashes are <see cref="DigestValue"/> carriers tagged with the security object's hash
/// algorithm; this object owns them and is disposed by the caller.
/// </para>
/// </remarks>
public sealed class LdsSecurityObject: IDisposable
{
    private const byte SequenceTag = 0x30;
    private const byte IntegerTag = 0x02;
    private const byte ObjectIdentifierTag = 0x06;
    private const byte OctetStringTag = 0x04;

    //DER value bytes (after the OID tag and length) of the supported digest algorithm identifiers.
    private static readonly byte[] Sha1Oid = [0x2B, 0x0E, 0x03, 0x02, 0x1A];
    private static readonly byte[] Sha256Oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    private static readonly byte[] Sha384Oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    private static readonly byte[] Sha512Oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

    private readonly IReadOnlyDictionary<int, DigestValue> dataGroupHashes;
    private bool disposed;


    private LdsSecurityObject(HashAlgorithmName hashAlgorithm, IReadOnlyDictionary<int, DigestValue> dataGroupHashes)
    {
        HashAlgorithm = hashAlgorithm;
        this.dataGroupHashes = dataGroupHashes;
    }


    /// <summary>Gets the hash algorithm the data-group hashes were computed under.</summary>
    public HashAlgorithmName HashAlgorithm { get; }

    /// <summary>Gets the expected hash of each data group, keyed by data-group number.</summary>
    public IReadOnlyDictionary<int, DigestValue> DataGroupHashes => dataGroupHashes;


    /// <summary>
    /// Parses an LDS Security Object from its DER bytes, copying each data-group hash into a
    /// <see cref="DigestValue"/> carrier.
    /// </summary>
    /// <param name="content">The LDS Security Object DER (the EF.SOD CMS encapsulated content).</param>
    /// <param name="pool">The memory pool for the hash carriers.</param>
    /// <returns>The parsed <see cref="LdsSecurityObject"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is malformed or uses an unsupported hash algorithm.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the DigestValue carriers transfers to the returned LdsSecurityObject; the catch disposes them on a partial parse failure.")]
    public static LdsSecurityObject Parse(ReadOnlyMemory<byte> content, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new ApduReader(content.Span);

        ExpectTag(ref reader, SequenceTag, "LDS Security Object");
        _ = reader.ReadTlvLength();

        SkipElement(ref reader, IntegerTag, "version");

        HashAlgorithmName hashAlgorithm = ReadDigestAlgorithm(ref reader);
        Tag digestTag = DigestTag(hashAlgorithm);

        ExpectTag(ref reader, SequenceTag, "data-group hash values");
        int listLength = reader.ReadTlvLength();
        int listEnd = reader.Consumed + listLength;

        var dataGroupHashes = new Dictionary<int, DigestValue>();
        try
        {
            while(reader.Consumed < listEnd)
            {
                ExpectTag(ref reader, SequenceTag, "data-group hash");
                int entryLength = reader.ReadTlvLength();
                int entryEnd = reader.Consumed + entryLength;

                int dataGroupNumber = ReadInteger(ref reader);

                ExpectTag(ref reader, OctetStringTag, "data-group hash value");
                int hashLength = reader.ReadTlvLength();
                ReadOnlySpan<byte> hash = reader.ReadBytes(hashLength);
                dataGroupHashes[dataGroupNumber] = ToDigest(hash, digestTag, pool);

                if(reader.Consumed < entryEnd)
                {
                    reader.Skip(entryEnd - reader.Consumed);
                }
            }

            return new LdsSecurityObject(hashAlgorithm, dataGroupHashes);
        }
        catch
        {
            foreach(DigestValue digest in dataGroupHashes.Values)
            {
                digest.Dispose();
            }

            throw;
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            foreach(DigestValue digest in dataGroupHashes.Values)
            {
                digest.Dispose();
            }

            disposed = true;
        }
    }


    /// <summary>
    /// Copies a hash value into a pooled <see cref="DigestValue"/> carrying the digest algorithm tag.
    /// </summary>
    private static DigestValue ToDigest(ReadOnlySpan<byte> hash, Tag digestTag, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(hash.Length);
        try
        {
            hash.CopyTo(owner.Memory.Span);

            return new DigestValue(owner, digestTag);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// The digest tag for a hash algorithm. SHA-1 is composed inline; the convenience tags omit it.
    /// </summary>
    private static Tag DigestTag(HashAlgorithmName hashAlgorithm)
    {
        if(hashAlgorithm == HashAlgorithmName.SHA256) { return CryptoTags.Sha256Digest; }
        if(hashAlgorithm == HashAlgorithmName.SHA384) { return CryptoTags.Sha384Digest; }
        if(hashAlgorithm == HashAlgorithmName.SHA512) { return CryptoTags.Sha512Digest; }

        return Tag.Create(
            (typeof(HashAlgorithmName), hashAlgorithm),
            (typeof(Purpose), Purpose.Digest),
            (typeof(EncodingScheme), EncodingScheme.Raw));
    }


    /// <summary>
    /// Reads the DigestAlgorithmIdentifier SEQUENCE and maps its algorithm OID to a <see cref="HashAlgorithmName"/>.
    /// </summary>
    private static HashAlgorithmName ReadDigestAlgorithm(ref ApduReader reader)
    {
        ExpectTag(ref reader, SequenceTag, "digest algorithm identifier");
        int algorithmLength = reader.ReadTlvLength();
        int algorithmEnd = reader.Consumed + algorithmLength;

        ExpectTag(ref reader, ObjectIdentifierTag, "algorithm");
        int oidLength = reader.ReadTlvLength();
        ReadOnlySpan<byte> oid = reader.ReadBytes(oidLength);

        //Skip any optional parameters following the OID.
        if(reader.Consumed < algorithmEnd)
        {
            reader.Skip(algorithmEnd - reader.Consumed);
        }

        if(oid.SequenceEqual(Sha256Oid)) { return HashAlgorithmName.SHA256; }
        if(oid.SequenceEqual(Sha384Oid)) { return HashAlgorithmName.SHA384; }
        if(oid.SequenceEqual(Sha512Oid)) { return HashAlgorithmName.SHA512; }
        if(oid.SequenceEqual(Sha1Oid)) { return HashAlgorithmName.SHA1; }

        throw new InvalidOperationException("The LDS Security Object uses an unsupported digest algorithm.");
    }


    /// <summary>
    /// Reads and checks the expected tag, throwing when it does not match.
    /// </summary>
    private static void ExpectTag(ref ApduReader reader, byte expectedTag, string elementName)
    {
        if(reader.ReadByte() != expectedTag)
        {
            throw new InvalidOperationException($"Expected a {elementName} element (tag 0x{expectedTag:X2}).");
        }
    }


    /// <summary>
    /// Skips an element of the expected tag.
    /// </summary>
    private static void SkipElement(ref ApduReader reader, byte expectedTag, string elementName)
    {
        ExpectTag(ref reader, expectedTag, elementName);
        reader.Skip(reader.ReadTlvLength());
    }


    /// <summary>
    /// Reads a small non-negative INTEGER (a data-group number).
    /// </summary>
    private static int ReadInteger(ref ApduReader reader)
    {
        ExpectTag(ref reader, IntegerTag, "data-group number");
        int length = reader.ReadTlvLength();
        ReadOnlySpan<byte> value = reader.ReadBytes(length);

        int result = 0;
        foreach(byte b in value)
        {
            result = (result << 8) | b;
        }

        return result;
    }
}
