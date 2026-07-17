using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared mdoc test helpers that were previously copy-pasted across the mdoc
/// test files (CBOR element-value encoding, P-256 → COSE_Key conversion, key
/// disposal). Consume via <c>using static</c> so existing call sites stay
/// unchanged:
/// <code>using static Verifiable.Tests.TestInfrastructure.MdocTestFixtures;</code>
/// </summary>
/// <remarks>
/// Validity windows (<c>SampleValidity</c>) are intentionally NOT consolidated
/// here — different test files pin different signed/valid dates, so each keeps
/// its own to stay explicit about the instant under test.
/// </remarks>
internal static class MdocTestFixtures
{
    /// <summary>
    /// Produces a per-item random salt for mdoc <c>IssuerSignedItem</c>s — the ISO/IEC 18013-5
    /// §9.1.2.5 minimum length (<see cref="MdocWellKnownKeys.IssuerSignedItemRandomMinimumLength"/>)
    /// tagged with <see cref="CryptoTags.MdocIssuerSignedItemRandom"/>, generated through the entropy
    /// provider via <see cref="TestSalts.Generate(int, Tag, MemoryPool{byte})"/>. Bakes the named length
    /// constant and tag so call sites carry no magic <c>16</c> and no repeated tag.
    /// </summary>
    /// <param name="pool">The memory pool to allocate from. Defaults to <see cref="BaseMemoryPool.Shared"/>.</param>
    /// <returns>A fresh mdoc item-random <see cref="Salt"/>; the caller owns and disposes it (or transfers ownership).</returns>
    public static Salt ItemRandomSalt(MemoryPool<byte>? pool = null) =>
        TestSalts.Generate(
            MdocWellKnownKeys.IssuerSignedItemRandomMinimumLength,
            CryptoTags.MdocIssuerSignedItemRandom,
            pool);


    /// <summary>Canonical-CBOR-encodes a text string as an mdoc element value.</summary>
    public static byte[] CborText(string value)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTextString(value);

        return writer.Encode();
    }


    /// <summary>Canonical-CBOR-encodes the boolean <see langword="true"/> as an mdoc element value.</summary>
    public static byte[] CborBoolTrue()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteBoolean(true);

        return writer.Encode();
    }


    /// <summary>
    /// Builds a <see cref="CoseKey"/> (EC2 / P-256) from a compressed P-256
    /// public key, decompressing to recover the y coordinate.
    /// </summary>
    public static CoseKey CoseKeyFromP256Public(PublicKeyMemory publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        ReadOnlySpan<byte> compressed = publicKey.AsReadOnlySpan();
        byte[] uncompressed = EllipticCurveUtilities.Decompress(compressed, EllipticCurveTypes.P256);

        return new CoseKey(
            kty: CoseKeyTypes.Ec2,
            curve: CoseKeyCurves.P256,
            x: compressed[1..].ToArray(),
            y: uncompressed);
    }


    /// <summary>Disposes both halves of a public/private key pair.</summary>
    public static void DisposeKeyMaterial(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial)
    {
        keyMaterial.PublicKey.Dispose();
        keyMaterial.PrivateKey.Dispose();
    }


    /// <summary>The EUDI PID document type and namespace <see cref="BuildSampleLogicalPid"/> issues into.</summary>
    public const string PidDocType = "eu.europa.ec.eudi.pid.1";

    /// <summary>The EUDI PID namespace, identical to <see cref="PidDocType"/> per the current EUDI PID rulebook.</summary>
    public const string PidNamespace = PidDocType;


    /// <summary>
    /// Builds a logical PID document carrying the two-claim <c>family_name</c>/<c>given_name</c> shape
    /// every mdoc PID end-to-end test issues, through the production <see cref="MdocIssuance.BuildDocument"/>.
    /// </summary>
    /// <param name="generateRandom">The per-item random-salt generator, e.g. <see cref="ItemRandomSalt"/> wrapped in a delegate.</param>
    /// <returns>The assembled logical document; the caller owns it per <see cref="MdocIssuance.BuildDocument"/>'s ownership contract.</returns>
    public static MdocLogicalDocument BuildSampleLogicalPid(GenerateMdocItemRandomDelegate generateRandom) =>
        MdocIssuance.BuildDocument(
            docType: PidDocType,
            claims:
            [
                new() { NameSpace = PidNamespace, ElementIdentifier = "family_name", EncodedElementValue = CborText("Mustermann") },
                new() { NameSpace = PidNamespace, ElementIdentifier = "given_name", EncodedElementValue = CborText("Erika") }
            ],
            generateRandom: generateRandom);


    /// <summary>
    /// Hand-writes an MSO <c>valueDigests</c> map with one namespace holding two 32-byte zero digests
    /// (digest IDs 0 and 1). Independent, hand-built CBOR — the oracle
    /// <see cref="Verifiable.Cbor.Mdoc.MdocCborMsoReader"/>'s reader tests parse, never derived from the
    /// production MSO writer.
    /// </summary>
    /// <param name="writer">The CBOR writer to append to.</param>
    /// <param name="nameSpace">The single namespace the digests map carries.</param>
    public static void WriteValueDigests(CborWriter writer, string nameSpace)
    {
        writer.WriteStartMap(1);
        writer.WriteTextString(nameSpace);
        writer.WriteStartMap(2);
        writer.WriteUInt32(0);
        writer.WriteByteString(new byte[32]);
        writer.WriteUInt32(1);
        writer.WriteByteString(new byte[32]);
        writer.WriteEndMap();
        writer.WriteEndMap();
    }


    /// <summary>
    /// Hand-writes an MSO <c>deviceKeyInfo</c> map carrying only a P-256 COSE_Key <c>deviceKey</c> field
    /// (zero-filled X/Y). Independent, hand-built CBOR — the same oracle role as <see cref="WriteValueDigests"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer to append to.</param>
    public static void WriteDeviceKeyInfo(CborWriter writer)
    {
        writer.WriteStartMap(1);
        writer.WriteTextString(MdocMsoWellKnownKeys.DeviceKey);

        writer.WriteStartMap(4);
        writer.WriteInt32(CoseKeyParameters.Kty);
        writer.WriteInt32(CoseKeyTypes.Ec2);
        writer.WriteInt32(CoseKeyParameters.Crv);
        writer.WriteInt32(CoseKeyCurves.P256);
        writer.WriteInt32(CoseKeyParameters.X);
        writer.WriteByteString(new byte[32]);
        writer.WriteInt32(CoseKeyParameters.Y);
        writer.WriteByteString(new byte[32]);
        writer.WriteEndMap();

        writer.WriteEndMap();
    }


    /// <summary>
    /// Hand-writes an MSO <c>validityInfo</c> map with a signed instant and a one-year validity window.
    /// Independent, hand-built CBOR — the same oracle role as <see cref="WriteValueDigests"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer to append to.</param>
    public static void WriteValidityInfo(CborWriter writer)
    {
        writer.WriteStartMap(3);
        writer.WriteTextString(MdocMsoWellKnownKeys.Signed);
        WriteTdate(writer, "2026-05-24T12:00:00Z");
        writer.WriteTextString(MdocMsoWellKnownKeys.ValidFrom);
        WriteTdate(writer, "2026-05-24T12:00:00Z");
        writer.WriteTextString(MdocMsoWellKnownKeys.ValidUntil);
        WriteTdate(writer, "2027-05-24T12:00:00Z");
        writer.WriteEndMap();
    }


    /// <summary>Writes <paramref name="rfc3339"/> as an RFC 8949 §3.4.1 <c>tdate</c> (tag 0 over a text string).</summary>
    /// <param name="writer">The CBOR writer to append to.</param>
    /// <param name="rfc3339">The RFC 3339 date-time text.</param>
    public static void WriteTdate(CborWriter writer, string rfc3339)
    {
        writer.WriteTag(CborTag.DateTimeString);
        writer.WriteTextString(rfc3339);
    }
}
