using SimpleBase;
using System.Buffers;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Microsoft;
using Verifiable.NSec;
using Verifiable.Tests.DataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// These test multibase encoding and decoding using known vectors from
    /// W3C DID and verifiable credentials specifications.
    /// </summary>
    [TestClass]
    public sealed class W3CdataTests
    {
        /// <summary>
        /// Source for this vector at <see href="https://w3c-ccg.github.io/did-method-key/#secp256k1">did:key secp256k1</see>.
        /// </summary>
        [TestMethod]
        public void Secp256k1WithMultibaseBtc58Succeeds()
        {
            var encodedKey = "zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2";

            //Decode keeping the codec header to match the original test behavior.
            var decodedOwner = MultibaseSerializer.Decode(
                encodedKey,
                codecHeaderLength: 0,
                Base58.Bitcoin.Decode,
                SensitiveMemoryPool<byte>.Shared);
            var bytes = decodedOwner.Memory.Span;

            //Extract key data without codec header for re-encoding.
            var keyDataOnly = bytes.Slice(2).ToArray();
            decodedOwner.Dispose();

            var multibaseEncodedPublicKey = MultibaseSerializer.Encode(
                keyDataOnly,
                MulticodecHeaders.Secp256k1PublicKey,
                MultibaseAlgorithms.Base58Btc,
                Base58.Bitcoin.Encode);

            Assert.StartsWith("zQ3s", multibaseEncodedPublicKey, StringComparison.InvariantCulture);
        }


        /// <summary>
        /// Tests BLS12-381 encoding and decoding.
        /// </summary>
        [TestMethod]
        public void Bls12381WithMultibaseBtc58Succeeds()
        {
            //https://w3c-ccg.github.io/did-method-key/#bls-12381
            //did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY
            //did:key:zUC7KKoJk5ttwuuc8pmQDiUmtckEPTwcaFVZe4DSFV7fURuoRnD17D3xkBK3A9tZqdADkTTMKSwNkhjo9Hs6HfgNUXo48TNRaxU6XPLSPdRgMc15jCD5DfN34ixjoVemY62JxnW
            var encodedKey = "zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY";

            //First method: decode with array decoder.
            var decodedOwner1 = MultibaseSerializer.Decode(
                encodedKey,
                codecHeaderLength: 0,
                Base58.Bitcoin.Decode,
                SensitiveMemoryPool<byte>.Shared);
            var bytes = decodedOwner1.Memory.Span;
            var keyDataOnly1 = bytes.Slice(2).ToArray();
            decodedOwner1.Dispose();

            var multibaseEncoded1 = MultibaseSerializer.Encode(
                keyDataOnly1,
                MulticodecHeaders.Bls12381G2PublicKey,
                MultibaseAlgorithms.Base58Btc,
                Base58.Bitcoin.Encode);

            //Second method: decode with stack decoder.
            var bytes2Owner = MultibaseSerializer.Decode(
                encodedKey,
                codecHeaderLength: 0,
                Base58.Bitcoin.Decode,
                SensitiveMemoryPool<byte>.Shared);
            var bytes2 = bytes2Owner.Memory.Span;
            var keyDataOnly2 = bytes2.Slice(2).ToArray();
            bytes2Owner.Dispose();

            var multibaseEncoded2 = MultibaseSerializer.Encode(
                keyDataOnly2,
                MulticodecHeaders.Bls12381G2PublicKey,
                MultibaseAlgorithms.Base58Btc,
                Base58.Bitcoin.Encode);

            Assert.StartsWith("zUC7", multibaseEncoded1, StringComparison.InvariantCulture);
            Assert.AreEqual(encodedKey, multibaseEncoded1);

            Assert.StartsWith("zUC7", multibaseEncoded2, StringComparison.InvariantCulture);
            Assert.AreEqual(encodedKey, multibaseEncoded2);
        }
    }


    /// <summary>
    /// Roundtrip multibase encoding and decoding tests.
    /// </summary>
    /// <remarks>
    /// There is an added importance to codify tests for known values and
    /// acknowledge that in general it is not possible to distinguish
    /// single byte code values (codes) from multibyte code values on bytes
    /// only, since if the data follows immediately, a multibyte
    /// header with data can start with a byte that looks like a single byte
    /// codec value following some data. In DIDs, VCs and related technologies
    /// one (must) check against known string headers (or byte patterns) to limit
    /// exposure and in general check values are allowed in the context of
    /// <see cref="CryptoSuiteConstants"/> used.
    /// </remarks>
    [TestClass]
    public sealed class MultibaseEncodingTests
    {
        /// <summary>
        /// Test elliptic curve key generation and validation.
        /// </summary>
        [TestMethod]
        [DynamicData(nameof(EllipticCurveTheoryData.GetEllipticCurveTestData), typeof(EllipticCurveTheoryData))]
        public void EllipticCurvesWithMultibaseBtc58Succeeds(EllipticCurveTestCase testCase)
        {
            if(OperatingSystem.IsMacOS() && testCase.CurveIdentifier == CryptoAlgorithm.Secp256k1)
            {
                return; // The secP256k1 curve is not supported on macOS.
            }

            var td = EllipticCurveTheoryData.CreateEllipticCurveTestData(testCase);
            var compressed = EllipticCurveUtilities.Compress(td.PublicKeyMaterialX, td.PublicKeyMaterialY);

            var multibaseEncodedPublicKey = MultibaseSerializer.Encode(
                compressed,
                td.PublicKeyMulticodecHeader,
                MultibaseAlgorithms.Base58Btc,
                Base58.Bitcoin.Encode);

            Assert.StartsWith(td.Base58BtcEncodedMulticodecHeaderPublicKey, multibaseEncodedPublicKey, StringComparison.InvariantCulture);

            //Decode and compare with original compressed key.
            var multibaseDecodedPublicKeyOwner = MultibaseSerializer.Decode(
                multibaseEncodedPublicKey,
                codecHeaderLength: 0,
                Base58.Bitcoin.Decode,
                SensitiveMemoryPool<byte>.Shared);

            //The decoded data includes the codec header, so we need to compare the full data.
            var decodedWithHeader = multibaseDecodedPublicKeyOwner.Memory.ToArray();
            multibaseDecodedPublicKeyOwner.Dispose();

            //Reconstruct what we expect: codec header + compressed key.
            var expectedData = new byte[td.PublicKeyMulticodecHeader.Length + compressed.Length];
            td.PublicKeyMulticodecHeader.CopyTo(expectedData);
            compressed.CopyTo(expectedData.AsSpan(td.PublicKeyMulticodecHeader.Length));

            CollectionAssert.AreEqual(expectedData, decodedWithHeader);
        }


        /// <summary>
        /// Test RSA key generation and validation.
        /// </summary>
        [TestMethod]
        [DynamicData(nameof(RsaTheoryData.GetRsaTestData), typeof(RsaTheoryData))]
        public void RsaWithMultibaseBtc58Succeeds(RsaTestData td)
        {
            var encodedModulus = RsaUtilities.Encode(td.Modulus);

            var multibaseEncodedPublicKey = MultibaseSerializer.Encode(
                encodedModulus,
                td.PublicKeyMulticodecHeader,
                MultibaseAlgorithms.Base58Btc,
                Base58.Bitcoin.Encode);

            Assert.StartsWith(td.Base58BtcEncodedMulticodecHeaderPublicKey, multibaseEncodedPublicKey, StringComparison.InvariantCulture);
        }


        /// <summary>
        /// Test Ed25519 key encoding.
        /// </summary>
        [TestMethod]
        public void Ed25519WithMultibaseBtc58Succeeds()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            var publicKeyEd25519 = keys.PublicKey.AsReadOnlySpan();
            var privateKeyEd25519 = keys.PrivateKey.AsReadOnlySpan();

            //Use high-level API for public key encoding.
            var multibaseEncodedPublicKey = MultibaseSerializer.EncodeKey(
                publicKeyEd25519,
                CryptoAlgorithm.Ed25519,
                Base58.Bitcoin.Encode);

            //Private keys require manual encoding with appropriate header.
            var multibaseEncodedPrivateKey = MultibaseSerializer.Encode(
                privateKeyEd25519,
                MulticodecHeaders.Ed25519PrivateKey,
                MultibaseAlgorithms.Base58Btc,
                Base58.Bitcoin.Encode);

            Assert.StartsWith(Base58BtcEncodedMulticodecHeaders.Ed25519PublicKey.ToString(), multibaseEncodedPublicKey, StringComparison.InvariantCulture);
            Assert.StartsWith(Base58BtcEncodedMulticodecHeaders.Ed25519PrivateKey.ToString(), multibaseEncodedPrivateKey, StringComparison.InvariantCulture);
        }


        /// <summary>
        /// Test X25519 key encoding.
        /// </summary>
        [TestMethod]
        public void X25519WithMultibaseBtc58Succeeds()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(SensitiveMemoryPool<byte>.Shared);
            var publicKeyEd25519 = keys.PublicKey.AsReadOnlySpan();
            var privateKeyEd25519 = keys.PrivateKey.AsReadOnlySpan();

            var x25519PublicKeyOwner = Sodium.ConvertEd25519PublicKeyToCurve25519PublicKey(publicKeyEd25519, SensitiveMemoryPool<byte>.Shared);
            var x25519PrivateKey = Sodium.ConvertEd25519PrivateKeyToCurve25519PrivateKey(privateKeyEd25519.ToArray());

            //Use high-level API for public key encoding.
            var multibaseEncodedPublicKey = MultibaseSerializer.EncodeKey(
                x25519PublicKeyOwner.Memory.Span,
                CryptoAlgorithm.X25519,
                Base58.Bitcoin.Encode);

            //Private keys require manual encoding with appropriate header.
            var multibaseEncodedPrivateKey = MultibaseSerializer.Encode(
                x25519PrivateKey,
                MulticodecHeaders.X25519PrivateKey,
                MultibaseAlgorithms.Base58Btc,
                Base58.Bitcoin.Encode);

            x25519PublicKeyOwner.Dispose();

            Assert.StartsWith(Base58BtcEncodedMulticodecHeaders.X25519PublicKey.ToString(), multibaseEncodedPublicKey, StringComparison.InvariantCulture);
            Assert.StartsWith(Base58BtcEncodedMulticodecHeaders.X25519PrivateKey.ToString(), multibaseEncodedPrivateKey, StringComparison.InvariantCulture);
        }


        /// <summary>
        /// Test P256 key creation.
        /// </summary>
        [TestMethod]
        public void P256KeyCreationTest()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);

            //Use high-level API for encoding.
            var multibaseEncodedPublicKey = MultibaseSerializer.EncodeKey(
                keys.PublicKey.AsReadOnlySpan(),
                CryptoAlgorithm.P256,
                Base58.Bitcoin.Encode);

            Assert.StartsWith(Base58BtcEncodedMulticodecHeaders.P256PublicKey.ToString(), multibaseEncodedPublicKey, StringComparison.InvariantCulture);
        }
    }
}
