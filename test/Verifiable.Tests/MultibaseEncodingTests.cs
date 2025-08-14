using SimpleBase;
using System.Buffers;
using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Did;
using Verifiable.Microsoft;
using Verifiable.NSec;
using Verifiable.Tests.DataProviders;


namespace Verifiable.Tests
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
            var bytes = MultibaseSerializer.Decode(encodedKey, ExactSizeMemoryPool<byte>.Shared, Base58.Bitcoin.Decode).Memory.Span;

            var multibaseEncodedPublicKey = MultibaseSerializer.Encode(bytes, MulticodecHeaders.Secp256k1PublicKey, MultibaseAlgorithms.Base58Btc, Base58.Bitcoin.Encode);
            Assert.StartsWith("zQ3s", multibaseEncodedPublicKey, StringComparison.InvariantCulture);
        }


        [TestMethod]
        public void Bls12381WithMultibaseBtc58Succeeds()
        {
            //https://w3c-ccg.github.io/did-method-key/#bls-12381
            //did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY
            //did:key:zUC7KKoJk5ttwuuc8pmQDiUmtckEPTwcaFVZe4DSFV7fURuoRnD17D3xkBK3A9tZqdADkTTMKSwNkhjo9Hs6HfgNUXo48TNRaxU6XPLSPdRgMc15jCD5DfN34ixjoVemY62JxnW
            var encodedKey = "zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY";

            //TODO: Check this before committing.
            var bytes = MultibaseSerializer.Decode(encodedKey, ExactSizeMemoryPool<byte>.Shared, (data, codecHeaderLength, resultMemoryPool) =>
            {
                ReadOnlySpan<char> dataWithoutMultibasePrefix = data;
                int safeEncodingBufferCount = Base58.Bitcoin.GetSafeByteCountForDecoding(dataWithoutMultibasePrefix);
                Span<byte> safeEncodingBuffer = safeEncodingBufferCount <= 512 ? stackalloc byte[safeEncodingBufferCount] : resultMemoryPool.Rent(safeEncodingBufferCount).Memory.Span;

                if(!Base58.Bitcoin.TryDecode(dataWithoutMultibasePrefix, safeEncodingBuffer, out int numBytesWritten))
                {
                    throw new Exception("Decoding failed.");
                }

                var actualBufferLength = numBytesWritten - codecHeaderLength;
                var output = resultMemoryPool.Rent(actualBufferLength);
                safeEncodingBuffer.Slice(codecHeaderLength, actualBufferLength).CopyTo(output.Memory.Span);

                return output;
            });

            var multibaseEncoded1 = MultibaseSerializer.Encode(bytes.Memory.Span, MulticodecHeaders.Bls12381G2PublicKey, MultibaseAlgorithms.Base58Btc, Base58.Bitcoin.Encode);


            var bytes2 = MultibaseSerializer.Decode(encodedKey, ExactSizeMemoryPool<byte>.Shared, Base58.Bitcoin.Decode);
            var multibaseEncoded2 = MultibaseSerializer.Encode(bytes2.Memory.Span, MulticodecHeaders.Bls12381G2PublicKey, MultibaseAlgorithms.Base58Btc, MemoryPool<char>.Shared, (data, codecHeader, pool) =>
            {
                int bufferLengthForDataToBeEncoded = codecHeader.Length + data.Length;
                Span<byte> dataWithEncodingHeaders = stackalloc byte[bufferLengthForDataToBeEncoded];

                codecHeader.CopyTo(dataWithEncodingHeaders);
                data.CopyTo(dataWithEncodingHeaders.Slice(codecHeader.Length));

                int bufferSize = Base58.Bitcoin.GetSafeCharCountForEncoding(dataWithEncodingHeaders);
                Span<char> buffer = bufferSize <= 512 ? stackalloc char[bufferSize] : pool.Rent(bufferSize).Memory.Span;

                if(!Base58.Bitcoin.TryEncode(dataWithEncodingHeaders, buffer, out int bytesWritten))
                {
                    throw new Exception("Encoding failed.");
                }

                return new string(buffer.Slice(0, bytesWritten));
            });

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
    /// There is an added importancy to codify tests for known values and
    /// acknowledge that in general it is not possible to distinquish
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
        [DynamicData(nameof(EllipticCurveTheoryData.GetEllipticCurveTestData), typeof(EllipticCurveTheoryData), DynamicDataSourceType.Method)]
        public void EllipticCurvesWithMultibaseBtc58Succeeds(EllipticCurveTestData td)
        {
            var compressed = EllipticCurveUtilities.Compress(td.PublicKeyMaterialX, td.PublicKeyMaterialY);

            var multibaseEncodedPublicKey = MultibaseSerializer.Encode(compressed, td.PublicKeyMulticodecHeader, MultibaseAlgorithms.Base58Btc, Base58.Bitcoin.Encode);
            Assert.StartsWith(td.Base58BtcEncodedMulticodecHeaderPublicKey, multibaseEncodedPublicKey, StringComparison.InvariantCulture);

            var multibaseDecodedPublicKey = MultibaseSerializer.Decode(multibaseEncodedPublicKey, ExactSizeMemoryPool<byte>.Shared, Base58.Bitcoin.Decode);
            CollectionAssert.AreEqual(compressed, multibaseDecodedPublicKey.Memory.ToArray());
        }


        /// <summary>
        /// Test RSA key generation and validation.
        /// </summary>
        [TestMethod]
        [DynamicData(nameof(RsaTheoryData.GetRsaTestData), typeof(RsaTheoryData), DynamicDataSourceType.Method)]
        public void RsaWithMultibaseBtc58Succeeds(RsaTestData td)
        {
            var encodedModulus = RsaUtilities.Encode(td.Modulus);

            var multibaseEncodedPublicKey = MultibaseSerializer.Encode(encodedModulus, td.PublicKeyMulticodecHeader, MultibaseAlgorithms.Base58Btc, Base58.Bitcoin.Encode);
            Assert.StartsWith(td.Base58BtcEncodedMulticodecHeaderPublicKey, multibaseEncodedPublicKey, StringComparison.InvariantCulture);
        }


        [TestMethod]
        public void Ed25519WithMultibaseBtc58Succeeds()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);
            var publicKeyEd25519 = keys.PublicKey.AsReadOnlySpan();
            var privateKeyEd25519 = keys.PrivateKey.AsReadOnlySpan();

            var multibaseEncodedPublicKey = MultibaseSerializer.Encode(publicKeyEd25519, MulticodecHeaders.Ed25519PublicKey, MultibaseAlgorithms.Base58Btc, Base58.Bitcoin.Encode);
            var multibaseEncodedPrivateKey = MultibaseSerializer.Encode(privateKeyEd25519, MulticodecHeaders.Ed25519PrivateKey, MultibaseAlgorithms.Base58Btc, Base58.Bitcoin.Encode);

            Assert.StartsWith(Base58BtcEncodedMulticodecHeaders.Ed25519PublicKey.ToString(), multibaseEncodedPublicKey, StringComparison.InvariantCulture);
            Assert.StartsWith(Base58BtcEncodedMulticodecHeaders.Ed25519PrivateKey.ToString(), multibaseEncodedPrivateKey, StringComparison.InvariantCulture);
        }


        [TestMethod]
        public void X25519WithMultibaseBtc58Succeeds()
        {
            var keys = NSecKeyCreator.CreateEd25519Keys(ExactSizeMemoryPool<byte>.Shared);
            var publicKeyEd25519 = keys.PublicKey.AsReadOnlySpan();
            var privateKeyEd25519 = keys.PrivateKey.AsReadOnlySpan();

            var x25519PublicKey = Sodium.ConvertEd25519PublicKeyToCurve25519PublicKey(publicKeyEd25519, ExactSizeMemoryPool<byte>.Shared);
            var x25519PrivateKey = Sodium.ConvertEd25519PrivateKeyToCurve25519PrivateKey(privateKeyEd25519.ToArray());

            var multibaseEncodedPublicKey = MultibaseSerializer.Encode(x25519PublicKey.Memory.Span, MulticodecHeaders.X25519PublicKey, MultibaseAlgorithms.Base58Btc, Base58.Bitcoin.Encode);
            var multibaseEncodedPrivateKey = MultibaseSerializer.Encode(x25519PrivateKey, MulticodecHeaders.X25519PrivateKey, MultibaseAlgorithms.Base58Btc, Base58.Bitcoin.Encode);

            Assert.StartsWith(Base58BtcEncodedMulticodecHeaders.X25519PublicKey.ToString(), multibaseEncodedPublicKey, StringComparison.InvariantCulture);
            Assert.StartsWith(Base58BtcEncodedMulticodecHeaders.X25519PrivateKey.ToString(), multibaseEncodedPrivateKey, StringComparison.InvariantCulture);
        }


        [TestMethod]
        public void P256KeyCreationTest()
        {
            var keys = PublicPrivateKeyMaterialExtensions.Create(SensitiveMemoryPool<byte>.Shared, MicrosoftKeyCreator.CreateP256Keys);

            //var derivedKeys = PublicPrivateKeyMaterialExtensions.Create(SensitiveMemoryPool<byte>.Shared, MicrosoftKeyCreator.CreateP256KeyDerived);

            var multibaseEncodedPublicKey = MultibaseSerializer.Encode(keys.PublicKey.AsReadOnlySpan(), MulticodecHeaders.P256PublicKey, MultibaseAlgorithms.Base58Btc, Base58.Bitcoin.Encode);
            Assert.StartsWith(Base58BtcEncodedMulticodecHeaders.P256PublicKey.ToString(), multibaseEncodedPublicKey, StringComparison.InvariantCulture);
        }
    }
}
