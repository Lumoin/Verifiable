using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The parsed EF.DG14 (Data Group 14) of an ICAO Doc 9303 eMRTD: the SecurityInfos that announce the
/// chip's Chip Authentication capability — the protocol parameters and the static public key a terminal
/// uses to agree a fresh Secure Messaging key and prove the chip is genuine.
/// </summary>
/// <remarks>
/// <para>
/// DG14 (file identifier <c>0x010E</c>, BER-TLV template tag <c>0x6E</c>) wraps
/// <c>SecurityInfos ::= SET OF SecurityInfo</c> (BSI TR-03110). Each SecurityInfo is a SEQUENCE whose
/// first element is a protocol object identifier. This type extracts the two needed for Chip
/// Authentication — <c>ChipAuthenticationInfo</c> (key agreement, cipher, version, key id) and
/// <c>ChipAuthenticationPublicKeyInfo</c> (the chip's static ECDH public key) — and skips the rest
/// (PACEInfo, TerminalAuthenticationInfo, plain-DH keys, …). The chip's public key is copied into an
/// <see cref="EncodedEcPoint"/> tagged with the curve resolved from the SubjectPublicKeyInfo, whether
/// the domain parameters are a named-curve OID or are encoded explicitly (the common eMRTD case).
/// </para>
/// </remarks>
public sealed class DataGroup14: IDisposable
{
    /// <summary>The eMRTD elementary file identifier of EF.DG14.</summary>
    public const ushort FileIdentifier = 0x010E;

    private const int DataGroupTemplateTag = 0x6E;
    private const int SetTag = 0x31;
    private const int SequenceTag = 0x30;
    private const int ObjectIdentifierTag = 0x06;
    private const int IntegerTag = 0x02;
    private const int BitStringTag = 0x03;

    //BSI TR-03110 protocol OID value bytes (after the 0x06 tag and length). The base arc
    //0.4.0.127.0.7.2.2 encodes to 04 00 7F 00 07 02 02; id-CA and id-PK extend it. The two
    //id-CA prefixes are nine bytes; the full OID appends a one-byte cipher arc (1=3DES,
    //2=AES-128, 3=AES-192, 4=AES-256).
    private static readonly byte[] IdPkEcdh = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x01, 0x02];
    private static readonly byte[] IdCaEcdhPrefix = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02];
    private static readonly byte[] IdCaDhPrefix = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x01];

    private readonly IReadOnlyList<ChipAuthenticationInfo> chipAuthenticationInfos;
    private readonly IReadOnlyList<ChipAuthenticationPublicKeyInfo> chipAuthenticationPublicKeyInfos;
    private bool disposed;


    private DataGroup14(
        IReadOnlyList<ChipAuthenticationInfo> chipAuthenticationInfos,
        IReadOnlyList<ChipAuthenticationPublicKeyInfo> chipAuthenticationPublicKeyInfos)
    {
        this.chipAuthenticationInfos = chipAuthenticationInfos;
        this.chipAuthenticationPublicKeyInfos = chipAuthenticationPublicKeyInfos;
    }


    /// <summary>Gets the chip's announced Chip Authentication protocols.</summary>
    public IReadOnlyList<ChipAuthenticationInfo> ChipAuthenticationInfos => chipAuthenticationInfos;

    /// <summary>Gets the chip's static Chip Authentication public keys. Owned by this data group.</summary>
    public IReadOnlyList<ChipAuthenticationPublicKeyInfo> ChipAuthenticationPublicKeyInfos => chipAuthenticationPublicKeyInfos;


    /// <summary>
    /// Parses an EF.DG14 file, extracting the Chip Authentication info and public-key SecurityInfos.
    /// </summary>
    /// <param name="dataGroup14">The DG14 file bytes (the BER-TLV structure beginning with tag <c>0x6E</c>).</param>
    /// <param name="pool">The memory pool for the public-key carriers.</param>
    /// <returns>The parsed <see cref="DataGroup14"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed DG14 or uses an unsupported curve.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the public-key carriers transfers to the returned DataGroup14; the catch disposes them on a partial parse failure.")]
    public static DataGroup14 Parse(ReadOnlySpan<byte> dataGroup14, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new ApduReader(dataGroup14);
        ApduReader template = ReadConstructed(ref reader, DataGroupTemplateTag, "DG14 template");
        ApduReader securityInfos = ReadConstructed(ref template, SetTag, "SecurityInfos");

        var infos = new List<ChipAuthenticationInfo>();
        var publicKeyInfos = new List<ChipAuthenticationPublicKeyInfo>();
        try
        {
            while(!securityInfos.IsEmpty)
            {
                ApduReader securityInfo = ReadConstructed(ref securityInfos, SequenceTag, "SecurityInfo");
                ReadOnlySpan<byte> protocol = ReadObjectIdentifier(ref securityInfo);

                if(protocol.SequenceEqual(IdPkEcdh))
                {
                    publicKeyInfos.Add(ParsePublicKeyInfo(ref securityInfo, pool));
                }
                else if(TryDecodeChipAuthenticationProtocol(protocol, out bool isEllipticCurve, out ChipAuthenticationCipher cipher))
                {
                    infos.Add(ParseChipAuthenticationInfo(ref securityInfo, isEllipticCurve, cipher));
                }

                //Other SecurityInfos (PACEInfo, TerminalAuthenticationInfo, id-PK-DH, …) are skipped:
                //ReadConstructed already advanced the SET reader past this whole SecurityInfo.
            }

            return new DataGroup14(infos, publicKeyInfos);
        }
        catch
        {
            foreach(ChipAuthenticationPublicKeyInfo info in publicKeyInfos)
            {
                info.Dispose();
            }

            throw;
        }
    }


    /// <summary>
    /// Writes an EF.DG14 file announcing one elliptic-curve Chip Authentication protocol and one static
    /// public key — the inverse of <see cref="Parse"/>. The SubjectPublicKeyInfo is encoded with the
    /// chip key's curve as a named-curve OID.
    /// </summary>
    /// <param name="chipPublicKey">The chip's static ECDH public key (SEC1 uncompressed), tagged with its curve.</param>
    /// <param name="cipher">The Secure Messaging cipher the protocol establishes.</param>
    /// <param name="version">The Chip Authentication protocol version (0-127).</param>
    /// <param name="keyId">The key identifier, or <see langword="null"/> for a single-key chip (0-127 when present).</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.DG14 <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the public-key tag carries no curve algorithm.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ElementaryFile, which the caller disposes; the catch disposes it on failure.")]
    public static ElementaryFile Write(EncodedEcPoint chipPublicKey, ChipAuthenticationCipher cipher, int version, int? keyId, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(chipPublicKey);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(version);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(version, 0x7F);
        if(keyId is int keyIdValue)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(keyIdValue);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(keyIdValue, 0x7F);
        }

        if(!chipPublicKey.Tag.TryGet(out CryptoAlgorithm algorithm))
        {
            throw new InvalidOperationException("The chip public key tag must carry a curve algorithm.");
        }

        ReadOnlySpan<byte> curveOid = EllipticCurveUtilities.CurveOidDerValue(EllipticCurveUtilities.CurveTypeFor(algorithm));
        ReadOnlySpan<byte> point = chipPublicKey.AsReadOnlySpan();
        int keyIdElement = keyId.HasValue ? BerTlvWriter.ElementSize(IntegerTag, 1) : 0;

        int algorithmContent =
            BerTlvWriter.ElementSize(ObjectIdentifierTag, WellKnownOids.EcPublicKeyDerValue.Length)
            + BerTlvWriter.ElementSize(ObjectIdentifierTag, curveOid.Length);
        int subjectPublicKeyInfoContent =
            BerTlvWriter.ElementSize(SequenceTag, algorithmContent)
            + BerTlvWriter.ElementSize(BitStringTag, 1 + point.Length);
        int publicKeyInfoContent =
            BerTlvWriter.ElementSize(ObjectIdentifierTag, IdPkEcdh.Length)
            + BerTlvWriter.ElementSize(SequenceTag, subjectPublicKeyInfoContent)
            + keyIdElement;

        int chipAuthenticationInfoContent =
            BerTlvWriter.ElementSize(ObjectIdentifierTag, IdCaEcdhPrefix.Length + 1)
            + BerTlvWriter.ElementSize(IntegerTag, 1)
            + keyIdElement;

        int setContent =
            BerTlvWriter.ElementSize(SequenceTag, publicKeyInfoContent)
            + BerTlvWriter.ElementSize(SequenceTag, chipAuthenticationInfoContent);
        int templateContent = BerTlvWriter.ElementSize(SetTag, setContent);
        int total = BerTlvWriter.ElementSize(DataGroupTemplateTag, templateContent);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteHeader(DataGroupTemplateTag, templateContent);
            writer.WriteHeader(SetTag, setContent);

            //ChipAuthenticationPublicKeyInfo: id-PK-ECDH, SubjectPublicKeyInfo, optional keyId.
            writer.WriteHeader(SequenceTag, publicKeyInfoContent);
            writer.WriteElement(ObjectIdentifierTag, IdPkEcdh);
            writer.WriteHeader(SequenceTag, subjectPublicKeyInfoContent);
            writer.WriteHeader(SequenceTag, algorithmContent);
            writer.WriteElement(ObjectIdentifierTag, WellKnownOids.EcPublicKeyDerValue);
            writer.WriteElement(ObjectIdentifierTag, curveOid);
            writer.WriteHeader(BitStringTag, 1 + point.Length);
            writer.WriteValue([0x00]);
            writer.WriteValue(point);
            if(keyId is int publicKeyId)
            {
                WriteSmallInteger(ref writer, publicKeyId);
            }

            //ChipAuthenticationInfo: id-CA-ECDH-<cipher>, version, optional keyId.
            writer.WriteHeader(SequenceTag, chipAuthenticationInfoContent);
            writer.WriteHeader(ObjectIdentifierTag, IdCaEcdhPrefix.Length + 1);
            writer.WriteValue(IdCaEcdhPrefix);
            writer.WriteValue([CipherArc(cipher)]);
            WriteSmallInteger(ref writer, version);
            if(keyId is int infoKeyId)
            {
                WriteSmallInteger(ref writer, infoKeyId);
            }

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
            foreach(ChipAuthenticationPublicKeyInfo info in chipAuthenticationPublicKeyInfos)
            {
                info.Dispose();
            }

            disposed = true;
        }
    }


    /// <summary>
    /// Parses a ChipAuthenticationPublicKeyInfo from the bytes following its protocol OID: the
    /// SubjectPublicKeyInfo (algorithm, domain parameters, EC point) and the optional key identifier.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the EncodedEcPoint transfers to the returned ChipAuthenticationPublicKeyInfo, which the caller disposes; the catch disposes it on a partial parse failure.")]
    private static ChipAuthenticationPublicKeyInfo ParsePublicKeyInfo(ref ApduReader securityInfo, MemoryPool<byte> pool)
    {
        ApduReader subjectPublicKeyInfo = ReadConstructed(ref securityInfo, SequenceTag, "SubjectPublicKeyInfo");
        ApduReader algorithm = ReadConstructed(ref subjectPublicKeyInfo, SequenceTag, "AlgorithmIdentifier");

        ReadOnlySpan<byte> algorithmOid = ReadObjectIdentifier(ref algorithm);
        if(!algorithmOid.SequenceEqual(WellKnownOids.EcPublicKeyDerValue))
        {
            throw new InvalidOperationException("DG14 ChipAuthenticationPublicKeyInfo is not an elliptic-curve public key.");
        }

        Tag curve = ResolveCurve(ref algorithm);
        ReadOnlySpan<byte> point = ReadPublicKeyPoint(ref subjectPublicKeyInfo);

        EncodedEcPoint publicKey = EncodedEcPoint.FromBytes(point, curve, pool);
        try
        {
            int? keyId = TryReadKeyId(ref securityInfo);

            return new ChipAuthenticationPublicKeyInfo(publicKey, keyId);
        }
        catch
        {
            publicKey.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Parses a ChipAuthenticationInfo from the bytes following its protocol OID: the version and the
    /// optional key identifier. The key-agreement family and cipher come from the already-decoded OID.
    /// </summary>
    private static ChipAuthenticationInfo ParseChipAuthenticationInfo(ref ApduReader securityInfo, bool isEllipticCurve, ChipAuthenticationCipher cipher)
    {
        int version = ReadInteger(ref securityInfo, "ChipAuthenticationInfo version");
        int? keyId = TryReadKeyId(ref securityInfo);

        return new ChipAuthenticationInfo(isEllipticCurve, cipher, version, keyId);
    }


    /// <summary>
    /// Reads the EC point from a SubjectPublicKeyInfo's subjectPublicKey BIT STRING, requiring the
    /// byte-aligned, SEC1 uncompressed form (<c>0x04 || X || Y</c>) Chip Authentication keys use.
    /// </summary>
    private static ReadOnlySpan<byte> ReadPublicKeyPoint(ref ApduReader subjectPublicKeyInfo)
    {
        ExpectTag(ref subjectPublicKeyInfo, BitStringTag, "subjectPublicKey");
        int length = subjectPublicKeyInfo.ReadTlvLength();
        ReadOnlySpan<byte> bitString = subjectPublicKeyInfo.ReadBytes(length);

        //A BIT STRING begins with the count of unused trailing bits (0 for a byte-aligned key); the
        //remainder is the SEC1 point, which Chip Authentication keys encode uncompressed (leading 0x04).
        if(bitString.Length < 2 || bitString[0] != 0x00 || bitString[1] != 0x04)
        {
            throw new InvalidOperationException("DG14 ChipAuthenticationPublicKeyInfo does not carry an uncompressed elliptic-curve point.");
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
            return CurveFromNamedOid(ReadObjectIdentifier(ref algorithm));
        }

        if(parameterTag == SequenceTag)
        {
            return CurveFromExplicitParameters(ref algorithm);
        }

        throw new InvalidOperationException("DG14 ChipAuthenticationPublicKeyInfo has no recognisable elliptic-curve domain parameters.");
    }


    /// <summary>
    /// Resolves an explicit ECParameters SEQUENCE to a curve by identifying its prime-field prime
    /// through <see cref="EllipticCurveUtilities.CurveTypeFromPrime"/>.
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
    /// Resolves a named-curve object identifier through <see cref="EllipticCurveUtilities.CurveTypeFromCurveOid"/>.
    /// </summary>
    private static Tag CurveFromNamedOid(ReadOnlySpan<byte> oid) => ExchangeTagFor(EllipticCurveUtilities.CurveTypeFromCurveOid(oid));


    /// <summary>
    /// Maps a recognised curve to the ECDH exchange-key <see cref="Tag"/> Chip Authentication uses for
    /// it, throwing for curves not supported as a chip's static Chip Authentication key.
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
        _ => throw new InvalidOperationException("DG14 ChipAuthenticationPublicKeyInfo uses an elliptic curve not supported for Chip Authentication.")
    };


    /// <summary>
    /// Decodes a Chip Authentication protocol OID into its key-agreement family and Secure Messaging
    /// cipher, returning <see langword="false"/> when the OID is not an <c>id-CA-DH</c>/<c>id-CA-ECDH</c> one.
    /// </summary>
    private static bool TryDecodeChipAuthenticationProtocol(ReadOnlySpan<byte> protocol, out bool isEllipticCurve, out ChipAuthenticationCipher cipher)
    {
        isEllipticCurve = false;
        cipher = ChipAuthenticationCipher.TripleDes;

        if(protocol.Length != IdCaEcdhPrefix.Length + 1)
        {
            return false;
        }

        ReadOnlySpan<byte> prefix = protocol[..^1];
        if(prefix.SequenceEqual(IdCaEcdhPrefix))
        {
            isEllipticCurve = true;
        }
        else if(prefix.SequenceEqual(IdCaDhPrefix))
        {
            isEllipticCurve = false;
        }
        else
        {
            return false;
        }

        if(DecodeCipher(protocol[^1]) is not ChipAuthenticationCipher decoded)
        {
            return false;
        }

        cipher = decoded;
        return true;
    }


    /// <summary>
    /// Maps the cipher arc of a Chip Authentication OID to a <see cref="ChipAuthenticationCipher"/>, or
    /// <see langword="null"/> when the arc is not a known cipher.
    /// </summary>
    private static ChipAuthenticationCipher? DecodeCipher(byte arc) => arc switch
    {
        0x01 => ChipAuthenticationCipher.TripleDes,
        0x02 => ChipAuthenticationCipher.Aes128,
        0x03 => ChipAuthenticationCipher.Aes192,
        0x04 => ChipAuthenticationCipher.Aes256,
        _ => null
    };


    /// <summary>
    /// Reads an optional trailing key-identifier INTEGER, returning <see langword="null"/> when the
    /// SecurityInfo has no more content.
    /// </summary>
    private static int? TryReadKeyId(ref ApduReader securityInfo)
    {
        if(securityInfo.IsEmpty)
        {
            return null;
        }

        return ReadInteger(ref securityInfo, "key identifier");
    }


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
    /// Reads a small non-negative INTEGER (a version or key identifier).
    /// </summary>
    private static int ReadInteger(ref ApduReader reader, string elementName)
    {
        ExpectTag(ref reader, IntegerTag, elementName);
        ReadOnlySpan<byte> value = reader.ReadBytes(reader.ReadTlvLength());

        int result = 0;
        foreach(byte b in value)
        {
            result = (result << 8) | b;
        }

        return result;
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


    /// <summary>
    /// Writes a small non-negative INTEGER (a version or key identifier, 0-127) as a one-byte value.
    /// </summary>
    private static void WriteSmallInteger(ref BerTlvWriter writer, int value)
    {
        writer.WriteHeader(IntegerTag, 1);
        writer.WriteValue([(byte)value]);
    }


    /// <summary>
    /// The final OID arc selecting the Secure Messaging cipher of an id-CA protocol identifier.
    /// </summary>
    private static byte CipherArc(ChipAuthenticationCipher cipher) => cipher switch
    {
        ChipAuthenticationCipher.TripleDes => 0x01,
        ChipAuthenticationCipher.Aes128 => 0x02,
        ChipAuthenticationCipher.Aes192 => 0x03,
        ChipAuthenticationCipher.Aes256 => 0x04,
        _ => throw new ArgumentOutOfRangeException(nameof(cipher), cipher, "Unknown Chip Authentication cipher.")
    };
}
