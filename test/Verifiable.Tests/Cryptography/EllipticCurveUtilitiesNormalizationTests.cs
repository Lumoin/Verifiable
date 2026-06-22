using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for the SEC1-point normalization helpers added to <see cref="EllipticCurveUtilities"/>:
    /// <see cref="EllipticCurveUtilities.NormalizeToUncompressed(ReadOnlySpan{byte}, EllipticCurveTypes)"/> and
    /// <see cref="EllipticCurveUtilities.CurveTypeFor(CryptoAlgorithm)"/>. The round-trip cases use real
    /// generated NIST keypairs so the compressed points are valid on-curve, exercising the decompression path
    /// that DID-document-resolved NIST key agreement now relies on.
    /// </summary>
    [TestClass]
    internal sealed class EllipticCurveUtilitiesNormalizationTests
    {
        private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;


        /// <summary>A generated P-256 point round-trips uncompressed -> compress -> normalize back to the original 0x04||X||Y bytes.</summary>
        [TestMethod]
        public void NormalizeToUncompressedRoundTripsCompressedP256()
        {
            AssertCompressedRoundTrip(MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys, CryptoAlgorithm.P256);
        }


        /// <summary>A generated P-384 point round-trips uncompressed -> compress -> normalize back to the original 0x04||X||Y bytes.</summary>
        [TestMethod]
        public void NormalizeToUncompressedRoundTripsCompressedP384()
        {
            AssertCompressedRoundTrip(MicrosoftKeyMaterialCreator.CreateP384ExchangeKeys, CryptoAlgorithm.P384);
        }


        /// <summary>A generated P-521 point round-trips uncompressed -> compress -> normalize back to the original 0x04||X||Y bytes.</summary>
        [TestMethod]
        public void NormalizeToUncompressedRoundTripsCompressedP521()
        {
            AssertCompressedRoundTrip(MicrosoftKeyMaterialCreator.CreateP521ExchangeKeys, CryptoAlgorithm.P521);
        }


        /// <summary>
        /// A P-521 point whose Y coordinate has at least one high-order zero byte round-trips compress -> normalize
        /// back to the original 0x04||X||Y bytes. This deterministically targets the Decompress leading-zero
        /// left-padding branch: when the recovered Y is shorter than the 66-byte field width it must be left-padded
        /// to 66 bytes so the recombined uncompressed point is byte-for-byte identical to the original — a branch the
        /// random P-521 round-trip only hits probabilistically.
        /// </summary>
        [TestMethod]
        public void NormalizeToUncompressedRecoversP521PointWithLeadingZeroY()
        {
            //Generate P-521 keypairs until the uncompressed Y has a leading 0x00 byte. The leading-zero Y occurs
            //with probability ~1/256 per key, so a bounded loop deterministically finds one well within the cap.
            const int MaxAttempts = 200;
            byte[]? uncompressedWithLeadingZeroY = null;
            for(int attempt = 0; attempt < MaxAttempts && uncompressedWithLeadingZeroY is null; ++attempt)
            {
                PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = MicrosoftKeyMaterialCreator.CreateP521ExchangeKeys(Pool);
                using PublicKeyMemory publicKey = keys.PublicKey;
                using PrivateKeyMemory privateKey = keys.PrivateKey;

                ReadOnlySpan<byte> uncompressed = publicKey.AsReadOnlySpan();
                if(EllipticCurveUtilities.SliceYCoordinate(uncompressed)[0] == 0x00)
                {
                    uncompressedWithLeadingZeroY = uncompressed.ToArray();
                }
            }

            Assert.IsNotNull(uncompressedWithLeadingZeroY,
                $"A P-521 point with a leading-zero Y MUST be found within {MaxAttempts} attempts.");

            ReadOnlySpan<byte> expected = uncompressedWithLeadingZeroY;
            Assert.AreEqual(0x00, EllipticCurveUtilities.SliceYCoordinate(expected)[0],
                "The selected P-521 point MUST have a high-order zero byte in Y to exercise the left-padding branch.");

            byte[] compressed = EllipticCurveUtilities.Compress(
                EllipticCurveUtilities.SliceXCoordinate(expected),
                EllipticCurveUtilities.SliceYCoordinate(expected));

            byte[] result = EllipticCurveUtilities.NormalizeToUncompressed(compressed, EllipticCurveUtilities.CurveTypeFor(CryptoAlgorithm.P521));

            Assert.HasCount(EllipticCurveConstants.P521.UncompressedPointByteCount, result,
                "A normalized P-521 point MUST be 133 bytes (0x04 || 66-byte X || 66-byte Y).");
            Assert.IsTrue(result.AsSpan().SequenceEqual(expected),
                "NormalizeToUncompressed MUST recover the original uncompressed P-521 point even when Y has a leading zero byte.");
        }


        /// <summary>An already-uncompressed point is returned unchanged (a copy with identical bytes).</summary>
        [TestMethod]
        public void NormalizeToUncompressedPassesThroughUncompressedP256()
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
            using PublicKeyMemory publicKey = keys.PublicKey;
            using PrivateKeyMemory privateKey = keys.PrivateKey;

            ReadOnlySpan<byte> uncompressed = publicKey.AsReadOnlySpan();
            byte[] expected = uncompressed.ToArray();

            byte[] result = EllipticCurveUtilities.NormalizeToUncompressed(uncompressed, EllipticCurveUtilities.CurveTypeFor(CryptoAlgorithm.P256));

            Assert.IsTrue(result.AsSpan().SequenceEqual(expected),
                "An already-uncompressed point MUST be returned byte-for-byte unchanged.");
        }


        /// <summary>A span whose first byte is an invalid SEC1 prefix (0x05) is rejected.</summary>
        [TestMethod]
        public void NormalizeToUncompressedThrowsForBadPrefix()
        {
            byte[] point = new byte[EllipticCurveConstants.P256.CompressedPointByteCount];
            point[0] = 0x05;

            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                EllipticCurveUtilities.NormalizeToUncompressed(point, EllipticCurveTypes.P256));
        }


        /// <summary>An empty span is rejected.</summary>
        [TestMethod]
        public void NormalizeToUncompressedThrowsForEmptySpan()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                EllipticCurveUtilities.NormalizeToUncompressed(ReadOnlySpan<byte>.Empty, EllipticCurveTypes.P256));
        }


        /// <summary>The NIST curve algorithms map to their matching <see cref="EllipticCurveTypes"/> flags.</summary>
        [TestMethod]
        public void CurveTypeForMapsNistCurves()
        {
            Assert.AreEqual(EllipticCurveTypes.P256, EllipticCurveUtilities.CurveTypeFor(CryptoAlgorithm.P256));
            Assert.AreEqual(EllipticCurveTypes.P384, EllipticCurveUtilities.CurveTypeFor(CryptoAlgorithm.P384));
            Assert.AreEqual(EllipticCurveTypes.P521, EllipticCurveUtilities.CurveTypeFor(CryptoAlgorithm.P521));
            Assert.AreEqual(EllipticCurveTypes.Secp256k1, EllipticCurveUtilities.CurveTypeFor(CryptoAlgorithm.Secp256k1));
        }


        /// <summary>The four Brainpool r1 curve algorithms map to their matching <see cref="EllipticCurveTypes"/> flags.</summary>
        [TestMethod]
        public void CurveTypeForMapsBrainpoolCurves()
        {
            Assert.AreEqual(EllipticCurveTypes.BrainpoolP256r1, EllipticCurveUtilities.CurveTypeFor(CryptoAlgorithm.BrainpoolP256r1));
            Assert.AreEqual(EllipticCurveTypes.BrainpoolP320r1, EllipticCurveUtilities.CurveTypeFor(CryptoAlgorithm.BrainpoolP320r1));
            Assert.AreEqual(EllipticCurveTypes.BrainpoolP384r1, EllipticCurveUtilities.CurveTypeFor(CryptoAlgorithm.BrainpoolP384r1));
            Assert.AreEqual(EllipticCurveTypes.BrainpoolP512r1, EllipticCurveUtilities.CurveTypeFor(CryptoAlgorithm.BrainpoolP512r1));
        }


        /// <summary>A non-EC algorithm (X25519) has no SEC1 point encoding and is rejected.</summary>
        [TestMethod]
        public void CurveTypeForThrowsForNonEllipticCurveAlgorithm()
        {
            Assert.ThrowsExactly<NotSupportedException>(() => EllipticCurveUtilities.CurveTypeFor(CryptoAlgorithm.X25519));
        }


        //Generates a keypair for the given curve, compresses its uncompressed public point, then asserts
        //NormalizeToUncompressed recovers the original 0x04||X||Y bytes byte-for-byte. The curve is resolved
        //via CurveTypeFor so the helper under test selects the decompression parameters from the algorithm.
        private static void AssertCompressedRoundTrip(
            Func<MemoryPool<byte>, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
            CryptoAlgorithm algorithm)
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = createKeys(Pool);
            using PublicKeyMemory publicKey = keys.PublicKey;
            using PrivateKeyMemory privateKey = keys.PrivateKey;

            ReadOnlySpan<byte> uncompressed = publicKey.AsReadOnlySpan();
            byte[] expected = uncompressed.ToArray();

            byte[] compressed = EllipticCurveUtilities.Compress(
                EllipticCurveUtilities.SliceXCoordinate(uncompressed),
                EllipticCurveUtilities.SliceYCoordinate(uncompressed));

            byte[] result = EllipticCurveUtilities.NormalizeToUncompressed(compressed, EllipticCurveUtilities.CurveTypeFor(algorithm));

            Assert.IsTrue(result.AsSpan().SequenceEqual(expected),
                $"NormalizeToUncompressed MUST recover the original uncompressed point for {algorithm} after compression.");
        }
    }
}
