using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;

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
    /// Builds an <see cref="MdocCoseKey"/> (EC2 / P-256) from a compressed P-256
    /// public key, decompressing to recover the y coordinate.
    /// </summary>
    public static MdocCoseKey CoseKeyFromP256Public(PublicKeyMemory publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        ReadOnlySpan<byte> compressed = publicKey.AsReadOnlySpan();
        byte[] uncompressed = EllipticCurveUtilities.Decompress(compressed, EllipticCurveTypes.P256);

        return new MdocCoseKey(
            kty: MdocCoseKeyTypes.Ec2,
            curve: MdocCoseKeyCurves.P256,
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
}
