using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The key type of an EF.DG15 Active Authentication public key.
/// </summary>
public enum ActiveAuthenticationKeyType
{
    /// <summary>An elliptic-curve (ECDSA) Active Authentication key.</summary>
    EllipticCurve,

    /// <summary>An RSA (ISO/IEC 9796-2) Active Authentication key.</summary>
    Rsa
}


/// <summary>
/// The parsed EF.DG15 (Data Group 15) of an ICAO Doc 9303 eMRTD: the chip's Active Authentication public
/// key. A terminal reads it to verify the signature the chip returns to an INTERNAL AUTHENTICATE challenge,
/// proving the chip holds the matching private key (anti-cloning, Doc 9303 Part 11 §6.1).
/// </summary>
/// <remarks>
/// <para>
/// DG15 (file identifier <c>0x010F</c>, BER-TLV template tag <c>0x6F</c>) wraps a single
/// <c>SubjectPublicKeyInfo</c> — the same structure DG14 carries for Chip Authentication, but bare (no
/// SecurityInfos SET, no protocol OID, no key identifier). The key is either elliptic-curve
/// (<c>id-ecPublicKey</c>, signed with ECDSA) or RSA (<c>rsaEncryption</c>, signed with ISO/IEC 9796-2);
/// <see cref="KeyType"/> distinguishes them. An elliptic-curve key is copied into an
/// <see cref="EncodedEcPoint"/> tagged with the curve resolved from the SubjectPublicKeyInfo (named-curve
/// OID or explicit parameters); an RSA key is copied as its DER <c>RSAPublicKey</c> into a
/// <see cref="RsaPublicKey"/>.
/// </para>
/// </remarks>
public sealed class DataGroup15: IDisposable
{
    /// <summary>The eMRTD elementary file identifier of EF.DG15.</summary>
    public const ushort FileIdentifier = 0x010F;

    private const int DataGroupTemplateTag = 0x6F;
    private const int SequenceTag = 0x30;
    private const int ObjectIdentifierTag = 0x06;
    private const int IntegerTag = 0x02;
    private const int BitStringTag = 0x03;
    private const int NullTag = 0x05;

    private readonly EncodedEcPoint? ellipticCurvePublicKey;
    private readonly RsaPublicKey? rsaPublicKey;
    private bool disposed;


    private DataGroup15(EncodedEcPoint ellipticCurvePublicKey)
    {
        this.ellipticCurvePublicKey = ellipticCurvePublicKey;
        KeyType = ActiveAuthenticationKeyType.EllipticCurve;
    }


    private DataGroup15(RsaPublicKey rsaPublicKey)
    {
        this.rsaPublicKey = rsaPublicKey;
        KeyType = ActiveAuthenticationKeyType.Rsa;
    }


    /// <summary>Gets the Active Authentication key type this DG15 carries.</summary>
    public ActiveAuthenticationKeyType KeyType { get; }

    /// <summary>Gets the chip's elliptic-curve Active Authentication public key (SEC1 uncompressed, tagged with its curve). Owned by this data group.</summary>
    /// <exception cref="InvalidOperationException">Thrown when <see cref="KeyType"/> is not <see cref="ActiveAuthenticationKeyType.EllipticCurve"/>.</exception>
    public EncodedEcPoint EllipticCurvePublicKey =>
        ellipticCurvePublicKey ?? throw new InvalidOperationException("DG15 does not carry an elliptic-curve Active Authentication public key.");

    /// <summary>Gets the chip's RSA Active Authentication public key (DER <c>RSAPublicKey</c>). Owned by this data group.</summary>
    /// <exception cref="InvalidOperationException">Thrown when <see cref="KeyType"/> is not <see cref="ActiveAuthenticationKeyType.Rsa"/>.</exception>
    public RsaPublicKey RsaPublicKey =>
        rsaPublicKey ?? throw new InvalidOperationException("DG15 does not carry an RSA Active Authentication public key.");


    /// <summary>
    /// Parses an EF.DG15 file, extracting its Active Authentication public key (elliptic-curve or RSA).
    /// </summary>
    /// <param name="dataGroup15">The DG15 file bytes (the BER-TLV structure beginning with tag <c>0x6F</c>).</param>
    /// <param name="pool">The memory pool for the public-key carrier.</param>
    /// <returns>The parsed <see cref="DataGroup15"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed DG15 or uses an unsupported key or curve.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the public-key carrier transfers to the returned DataGroup15, which the caller disposes.")]
    public static DataGroup15 Parse(ReadOnlySpan<byte> dataGroup15, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new ApduReader(dataGroup15);
        ApduReader template = ReadConstructed(ref reader, DataGroupTemplateTag, "DG15 template");
        ApduReader subjectPublicKeyInfo = ReadConstructed(ref template, SequenceTag, "SubjectPublicKeyInfo");
        ApduReader algorithm = ReadConstructed(ref subjectPublicKeyInfo, SequenceTag, "AlgorithmIdentifier");
        ReadOnlySpan<byte> algorithmOid = ReadObjectIdentifier(ref algorithm);

        if(algorithmOid.SequenceEqual(WellKnownOids.EcPublicKeyDerValue))
        {
            Tag curve = ResolveCurve(ref algorithm);
            ReadOnlySpan<byte> point = ReadPublicKeyPoint(ref subjectPublicKeyInfo);

            return new DataGroup15(EncodedEcPoint.FromBytes(point, curve, pool));
        }

        if(algorithmOid.SequenceEqual(WellKnownOids.RsaEncryptionDerValue))
        {
            ReadOnlySpan<byte> derRsaPublicKey = ReadSubjectPublicKeyBitString(ref subjectPublicKeyInfo);

            return new DataGroup15(RsaPublicKey.FromBytes(derRsaPublicKey, pool));
        }

        throw new InvalidOperationException("DG15 does not carry a supported (elliptic-curve or RSA) Active Authentication public key.");
    }


    /// <summary>
    /// Writes an EF.DG15 file carrying an elliptic-curve Active Authentication public key — the inverse of
    /// <see cref="Parse"/>. The SubjectPublicKeyInfo is encoded with the key's curve as a named-curve OID.
    /// </summary>
    /// <param name="publicKey">The chip's Active Authentication public key (SEC1 uncompressed), tagged with its curve.</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.DG15 <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the public-key tag carries no curve algorithm.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ElementaryFile, which the caller disposes; the catch disposes it on failure.")]
    public static ElementaryFile Write(EncodedEcPoint publicKey, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(pool);

        if(!publicKey.Tag.TryGet(out CryptoAlgorithm algorithm))
        {
            throw new InvalidOperationException("The Active Authentication public key tag must carry a curve algorithm.");
        }

        ReadOnlySpan<byte> curveOid = EllipticCurveUtilities.CurveOidDerValue(EllipticCurveUtilities.CurveTypeFor(algorithm));
        ReadOnlySpan<byte> point = publicKey.AsReadOnlySpan();

        int algorithmContent =
            BerTlvWriter.ElementSize(ObjectIdentifierTag, WellKnownOids.EcPublicKeyDerValue.Length)
            + BerTlvWriter.ElementSize(ObjectIdentifierTag, curveOid.Length);
        int subjectPublicKeyInfoContent =
            BerTlvWriter.ElementSize(SequenceTag, algorithmContent)
            + BerTlvWriter.ElementSize(BitStringTag, 1 + point.Length);
        int templateContent = BerTlvWriter.ElementSize(SequenceTag, subjectPublicKeyInfoContent);
        int total = BerTlvWriter.ElementSize(DataGroupTemplateTag, templateContent);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteHeader(DataGroupTemplateTag, templateContent);
            writer.WriteHeader(SequenceTag, subjectPublicKeyInfoContent);
            writer.WriteHeader(SequenceTag, algorithmContent);
            writer.WriteElement(ObjectIdentifierTag, WellKnownOids.EcPublicKeyDerValue);
            writer.WriteElement(ObjectIdentifierTag, curveOid);
            writer.WriteHeader(BitStringTag, 1 + point.Length);
            writer.WriteValue([0x00]);
            writer.WriteValue(point);

            return new ElementaryFile(owner, FileIdentifier);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Writes an EF.DG15 file carrying an RSA Active Authentication public key — the inverse of
    /// <see cref="Parse"/>. The SubjectPublicKeyInfo is encoded with the <c>rsaEncryption</c> OID and NULL
    /// parameters, the BIT STRING wrapping the DER <c>RSAPublicKey</c>.
    /// </summary>
    /// <param name="publicKey">The chip's RSA Active Authentication public key (DER <c>RSAPublicKey</c>).</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.DG15 <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ElementaryFile, which the caller disposes; the catch disposes it on failure.")]
    public static ElementaryFile Write(RsaPublicKey publicKey, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> derRsaPublicKey = publicKey.AsReadOnlySpan();

        int algorithmContent =
            BerTlvWriter.ElementSize(ObjectIdentifierTag, WellKnownOids.RsaEncryptionDerValue.Length)
            + BerTlvWriter.ElementSize(NullTag, 0);
        int subjectPublicKeyInfoContent =
            BerTlvWriter.ElementSize(SequenceTag, algorithmContent)
            + BerTlvWriter.ElementSize(BitStringTag, 1 + derRsaPublicKey.Length);
        int templateContent = BerTlvWriter.ElementSize(SequenceTag, subjectPublicKeyInfoContent);
        int total = BerTlvWriter.ElementSize(DataGroupTemplateTag, templateContent);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteHeader(DataGroupTemplateTag, templateContent);
            writer.WriteHeader(SequenceTag, subjectPublicKeyInfoContent);
            writer.WriteHeader(SequenceTag, algorithmContent);
            writer.WriteElement(ObjectIdentifierTag, WellKnownOids.RsaEncryptionDerValue);
            writer.WriteElement(NullTag, ReadOnlySpan<byte>.Empty);
            writer.WriteHeader(BitStringTag, 1 + derRsaPublicKey.Length);
            writer.WriteValue([0x00]);
            writer.WriteValue(derRsaPublicKey);

            return new ElementaryFile(owner, FileIdentifier);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            ellipticCurvePublicKey?.Dispose();
            rsaPublicKey?.Dispose();
            disposed = true;
        }
    }


    /// <summary>
    /// Reads the EC point from a SubjectPublicKeyInfo's subjectPublicKey BIT STRING, requiring the
    /// byte-aligned, SEC1 uncompressed form (<c>0x04 || X || Y</c>).
    /// </summary>
    private static ReadOnlySpan<byte> ReadPublicKeyPoint(ref ApduReader subjectPublicKeyInfo)
    {
        ReadOnlySpan<byte> bitStringContent = ReadSubjectPublicKeyBitString(ref subjectPublicKeyInfo);
        if(bitStringContent.Length < 1 || bitStringContent[0] != 0x04)
        {
            throw new InvalidOperationException("DG15 does not carry an uncompressed elliptic-curve point.");
        }

        return bitStringContent;
    }


    /// <summary>
    /// Reads a SubjectPublicKeyInfo's subjectPublicKey BIT STRING and returns its content (the bytes after
    /// the byte-aligned unused-bits prefix, which must be zero).
    /// </summary>
    private static ReadOnlySpan<byte> ReadSubjectPublicKeyBitString(ref ApduReader subjectPublicKeyInfo)
    {
        ExpectTag(ref subjectPublicKeyInfo, BitStringTag, "subjectPublicKey");
        int length = subjectPublicKeyInfo.ReadTlvLength();
        ReadOnlySpan<byte> bitString = subjectPublicKeyInfo.ReadBytes(length);

        if(bitString.Length < 1 || bitString[0] != 0x00)
        {
            throw new InvalidOperationException("DG15 subjectPublicKey is not a byte-aligned BIT STRING.");
        }

        return bitString[1..];
    }


    /// <summary>
    /// Resolves the curve a SubjectPublicKeyInfo's domain parameters name — either a named-curve OID or
    /// explicit prime-field parameters — to the exchange-key <see cref="Tag"/> of a supported curve.
    /// </summary>
    private static Tag ResolveCurve(ref ApduReader algorithm)
    {
        byte parameterTag = algorithm.PeekBytes(1)[0];
        if(parameterTag == ObjectIdentifierTag)
        {
            return ExchangeTagFor(EllipticCurveUtilities.CurveTypeFromCurveOid(ReadObjectIdentifier(ref algorithm)));
        }

        if(parameterTag == SequenceTag)
        {
            return CurveFromExplicitParameters(ref algorithm);
        }

        throw new InvalidOperationException("DG15 has no recognisable elliptic-curve domain parameters.");
    }


    /// <summary>
    /// Resolves an explicit ECParameters SEQUENCE to a curve by identifying its prime-field prime.
    /// </summary>
    private static Tag CurveFromExplicitParameters(ref ApduReader algorithm)
    {
        ApduReader parameters = ReadConstructed(ref algorithm, SequenceTag, "ECParameters");
        SkipElement(ref parameters, IntegerTag, "ECParameters version");

        ApduReader fieldId = ReadConstructed(ref parameters, SequenceTag, "fieldID");
        SkipElement(ref fieldId, ObjectIdentifierTag, "field type");

        ExpectTag(ref fieldId, IntegerTag, "field prime");
        int primeLength = fieldId.ReadTlvLength();
        ReadOnlySpan<byte> prime = fieldId.ReadBytes(primeLength);

        return ExchangeTagFor(EllipticCurveUtilities.CurveTypeFromPrime(prime));
    }


    /// <summary>
    /// Maps a recognised curve to the elliptic-curve point <see cref="Tag"/> for it (the SEC1 uncompressed
    /// encoding eMRTD keys use), throwing for unsupported curves.
    /// </summary>
    private static Tag ExchangeTagFor(EllipticCurveTypes curve) => curve switch
    {
        EllipticCurveTypes.P256 => CryptoTags.P256ExchangePublicKey,
        EllipticCurveTypes.P384 => CryptoTags.P384ExchangePublicKey,
        EllipticCurveTypes.P521 => CryptoTags.P521ExchangePublicKey,
        EllipticCurveTypes.BrainpoolP224r1 => CryptoTags.BrainpoolP224r1ExchangePublicKey,
        EllipticCurveTypes.BrainpoolP256r1 => CryptoTags.BrainpoolP256r1ExchangePublicKey,
        EllipticCurveTypes.BrainpoolP320r1 => CryptoTags.BrainpoolP320r1ExchangePublicKey,
        EllipticCurveTypes.BrainpoolP384r1 => CryptoTags.BrainpoolP384r1ExchangePublicKey,
        EllipticCurveTypes.BrainpoolP512r1 => CryptoTags.BrainpoolP512r1ExchangePublicKey,
        _ => throw new InvalidOperationException("DG15 uses an elliptic curve not supported for Active Authentication.")
    };


    /// <summary>
    /// Reads a constructed element of the expected tag and returns a reader over its content.
    /// </summary>
    private static ApduReader ReadConstructed(ref ApduReader reader, int expectedTag, string elementName)
    {
        ExpectTag(ref reader, expectedTag, elementName);

        return new ApduReader(reader.ReadBytes(reader.ReadTlvLength()));
    }


    /// <summary>
    /// Reads an OBJECT IDENTIFIER and returns its value bytes.
    /// </summary>
    private static ReadOnlySpan<byte> ReadObjectIdentifier(ref ApduReader reader)
    {
        ExpectTag(ref reader, ObjectIdentifierTag, "object identifier");

        return reader.ReadBytes(reader.ReadTlvLength());
    }


    /// <summary>
    /// Reads and checks the expected tag, throwing when it does not match.
    /// </summary>
    private static void ExpectTag(ref ApduReader reader, int expectedTag, string elementName)
    {
        if(reader.ReadByte() != expectedTag)
        {
            throw new InvalidOperationException($"Expected a {elementName} element (tag 0x{expectedTag:X2}).");
        }
    }


    /// <summary>
    /// Skips an element of the expected tag.
    /// </summary>
    private static void SkipElement(ref ApduReader reader, int expectedTag, string elementName)
    {
        ExpectTag(ref reader, expectedTag, elementName);
        reader.Skip(reader.ReadTlvLength());
    }
}
