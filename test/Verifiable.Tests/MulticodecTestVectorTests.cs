using SimpleBase;
using System;
using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Did;
using Xunit;

namespace Verifiable.Tests
{
    /// <summary>
    /// These are tests that are sourced from well-known, cross-checked locations.
    /// </summary>
    public class MulticodecTestVectorTests
    {
        /// <summary>
        /// The fixed Base58 encoder used in these tests. This is trusted to work properly.
        /// </summary>
        private static ReadOnlySpanFunc<byte, string> TestBase58Encoder => Base58.Bitcoin.Encode;

        /// <summary>
        /// The fixed Base58 decoder used in these tests. This is trusted to work properly.
        /// </summary>
        //private static ArrayDecodeDelegate<char, byte> TestBase58Decoder => Base58.Bitcoin.Decode;

        private static BufferAllocationDecodeDelegate TestBase58Decoder => (data, codecHeaderLength, resultMemoryPool) =>
        {
            ReadOnlySpan<char> dataWithoutMultibasePrefix = data;

            // Use Base58.Bitcoin.Decode instead of TryDecode
            byte[] decodedArray = Base58.Bitcoin.Decode(dataWithoutMultibasePrefix);

            // The actual buffer length is the length of the decoded array minus the codec header length
            var actualBufferLength = decodedArray.Length - codecHeaderLength;

            // Rent a buffer of the correct size from the memory pool
            var output = resultMemoryPool.Rent(actualBufferLength);

            // Copy the decoded data, excluding the codec header, into the rented buffer
            decodedArray.AsSpan(codecHeaderLength, actualBufferLength).CopyTo(output.Memory.Span);

            return output;
        };

        /*
        private static BufferAllocationDecodeDelegate TestBase58Decoder => (data, codecHeaderLength, resultMemoryPool) =>
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
        };*/


        /// <summary>
        /// Sourced from <href="https://w3c-ccg.github.io/did-method-key/#ed25519-x25519">Ed25519</href>.        
        /// </summary>
        [Fact]
        public void RountripEd25519()
        {
            const string Vector1 = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
            const string Vector2 = "z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG";
            const string Vector3 = "z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf";

            var decodedVector1 = SsiSerializer.Decode(Vector1, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            
            var multibaseEncodedPublicKey = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.Ed25519PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            var reEncodedVector1 = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.Ed25519PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector1, reEncodedVector1);

            var decodedVector2 = SsiSerializer.Decode(Vector2, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector2 = SsiSerializer.Encode(decodedVector2, MulticodecHeaders.Ed25519PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector2, reEncodedVector2);

            var decodedVector3 = SsiSerializer.Decode(Vector3, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector3 = SsiSerializer.Encode(decodedVector3, MulticodecHeaders.Ed25519PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector3, reEncodedVector3);

            //A sanity check, some (in practice 'any') other vector type should not work.
            var reEncodedVector1WithWrongHeader = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.P256PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.NotEqual(Vector1, reEncodedVector1WithWrongHeader);
        }


        /// <summary>
        /// Sourced from <href="https://w3c-ccg.github.io/did-method-key/#x25519">25519</href>.
        /// </summary>
        [Fact]
        public void RountripX25519()
        {
            const string Vector1 = "z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F";
            const string Vector2 = "z6LStiZsmxiK4odS4Sb6JmdRFuJ6e1SYP157gtiCyJKfrYha";
            const string Vector3 = "z6LSoMdmJz2Djah2P4L9taDmtqeJ6wwd2HhKZvNToBmvaczQ";

            var decodedVector1 = SsiSerializer.Decode(Vector1, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;            
            var reEncodedVector1 = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.X25519PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector1, reEncodedVector1);

            var decodedVector2 = SsiSerializer.Decode(Vector2, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector2 = SsiSerializer.Encode(decodedVector2, MulticodecHeaders.X25519PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector2, reEncodedVector2);

            var decodedVector3 = SsiSerializer.Decode(Vector3, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector3 = SsiSerializer.Encode(decodedVector3, MulticodecHeaders.X25519PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector3, reEncodedVector3);

            //A sanity check, some (in practice 'any') other vector type should not work.
            var reEncodedVector1WithWrongHeader = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.P256PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.NotEqual(Vector1, reEncodedVector1WithWrongHeader);
        }


        /// <summary>
        /// Sourced from <href="https://w3c-ccg.github.io/did-method-key/#secp256k1">Secp256k1</href>.        
        /// </summary>
        [Fact]
        public void RountripSecp256k1()
        {
            const string Vector1 = "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
            const string Vector2 = "zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2";
            const string Vector3 = "zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N";

            var decodedVector1 = SsiSerializer.Decode(Vector1, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector1 = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.Secp256k1PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector1, reEncodedVector1);

            var decodedVector2 = SsiSerializer.Decode(Vector2, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector2 = SsiSerializer.Encode(decodedVector2, MulticodecHeaders.Secp256k1PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector2, reEncodedVector2);

            var decodedVector3 = SsiSerializer.Decode(Vector3, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector3 = SsiSerializer.Encode(decodedVector3, MulticodecHeaders.Secp256k1PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector3, reEncodedVector3);

            //A sanity check, some (in practice 'any') other vector type should not work.
            var reEncodedVector1WithWrongHeader = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.P256PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.NotEqual(Vector1, reEncodedVector1WithWrongHeader);
        }


        /// <summary>
        /// Sourced from <href="https://w3c-ccg.github.io/did-method-key/#bls-12381">BLS 12381</href>.        
        /// </summary>
        [Fact]
        public void RountripBls12381()
        {
            const string Vector1 = "zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY";
            const string Vector2 = "zUC7KKoJk5ttwuuc8pmQDiUmtckEPTwcaFVZe4DSFV7fURuoRnD17D3xkBK3A9tZqdADkTTMKSwNkhjo9Hs6HfgNUXo48TNRaxU6XPLSPdRgMc15jCD5DfN34ixjoVemY62JxnW";

            var decodedVector1 = SsiSerializer.Decode(Vector1, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector1 = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.Bls12381G2PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector1, reEncodedVector1);

            var decodedVector2 = SsiSerializer.Decode(Vector2, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector2 = SsiSerializer.Encode(decodedVector2, MulticodecHeaders.Bls12381G2PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector2, reEncodedVector2);

            //A sanity check, some (in practice 'any') other vector type should not work.
            var reEncodedVector1WithWrongHeader = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.P256PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.NotEqual(Vector1, reEncodedVector1WithWrongHeader);
        }


        /// <summary>
        /// Sourced from <href="https://w3c-ccg.github.io/did-method-key/#p-256">P-256</href>.        
        /// </summary>
        [Fact]
        public void RountripP256()
        {
            const string Vector1 = "zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
            const string Vector2 = "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";

            var decodedVector1 = SsiSerializer.Decode(Vector1, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector1 = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.P256PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector1, reEncodedVector1);

            var decodedVector2 = SsiSerializer.Decode(Vector2, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector2 = SsiSerializer.Encode(decodedVector2, MulticodecHeaders.P256PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector2, reEncodedVector2);

            //A sanity check, some (in practice 'any') other vector type should not work.
            var reEncodedVector1WithWrongHeader = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.Bls12381G2PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.NotEqual(Vector1, reEncodedVector1WithWrongHeader);
        }


        /// <summary>
        /// Sourced from <href="https://w3c-ccg.github.io/did-method-key/#p-384">P-384</href>.        
        /// </summary>
        [Fact]
        public void RountripP384()
        {
            const string Vector1 = "z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9";
            const string Vector2 = "z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54";

            var decodedVector1 = SsiSerializer.Decode(Vector1, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector1 = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.P384PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector1, reEncodedVector1);

            var decodedVector2 = SsiSerializer.Decode(Vector2, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector2 = SsiSerializer.Encode(decodedVector2, MulticodecHeaders.P384PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector2, reEncodedVector2);

            //A sanity check, some (in practice 'any') other vector type should not work.
            var reEncodedVector1WithWrongHeader = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.P256PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.NotEqual(Vector1, reEncodedVector1WithWrongHeader);
        }


        /// <summary>
        /// Sourced from <href="https://w3c-ccg.github.io/did-method-key/#p-521">P-521</href>.        
        /// </summary>
        [Fact]
        public void RountripP521()
        {
            const string Vector1 = "z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7";
            const string Vector2 = "z2J9gcGdb2nEyMDmzQYv2QZQcM1vXktvy1Pw4MduSWxGabLZ9XESSWLQgbuPhwnXN7zP7HpTzWqrMTzaY5zWe6hpzJ2jnw4f";

            var decodedVector1 = SsiSerializer.Decode(Vector1, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector1 = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.P521PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector1, reEncodedVector1);

            var decodedVector2 = SsiSerializer.Decode(Vector2, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector2 = SsiSerializer.Encode(decodedVector2, MulticodecHeaders.P521PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector2, reEncodedVector2);

            //A sanity check, some (in practice 'any') other vector type should not work.
            var reEncodedVector1WithWrongHeader = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.P256PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.NotEqual(Vector1, reEncodedVector1WithWrongHeader);
        }


        /// <summary>
        /// Sourced from <href="https://w3c-ccg.github.io/did-method-key/#rsa">RSA 2048</href>.        
        /// </summary>
        [Fact]
        public void RountripRsa2048()
        {
            const string Vector1 = "z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i";
            
            var decodedVector1 = SsiSerializer.Decode(Vector1, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector1 = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.RsaPublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector1, reEncodedVector1);

            //A sanity check, some (in practice 'any') other vector type should not work.
            var reEncodedVector1WithWrongHeader = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.P256PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.NotEqual(Vector1, reEncodedVector1WithWrongHeader);
        }


        /// <summary>
        /// Sourced from <href="https://w3c-ccg.github.io/did-method-key/#rsa-4096">RSA 4096</href>.        
        /// </summary>
        [Fact]
        public void RountripRsa4096()
        {
            const string Vector1 = "zgghBUVkqmWS8e1ioRVp2WN9Vw6x4NvnE9PGAyQsPqM3fnfPf8EdauiRVfBTcVDyzhqM5FFC7ekAvuV1cJHawtfgB9wDcru1hPDobk3hqyedijhgWmsYfJCmodkiiFnjNWATE7PvqTyoCjcmrc8yMRXmFPnoASyT5beUd4YZxTE9VfgmavcPy3BSouNmASMQ8xUXeiRwjb7xBaVTiDRjkmyPD7NYZdXuS93gFhyDFr5b3XLg7Rfj9nHEqtHDa7NmAX7iwDAbMUFEfiDEf9hrqZmpAYJracAjTTR8Cvn6mnDXMLwayNG8dcsXFodxok2qksYF4D8ffUxMRmyyQVQhhhmdSi4YaMPqTnC1J6HTG9Yfb98yGSVaWi4TApUhLXFow2ZvB6vqckCNhjCRL2R4MDUSk71qzxWHgezKyDeyThJgdxydrn1osqH94oSeA346eipkJvKqYREXBKwgB5VL6WF4qAK6sVZxJp2dQBfCPVZ4EbsBQaJXaVK7cNcWG8tZBFWZ79gG9Cu6C4u8yjBS8Ux6dCcJPUTLtixQu4z2n5dCsVSNdnP1EEs8ZerZo5pBgc68w4Yuf9KL3xVxPnAB1nRCBfs9cMU6oL1EdyHbqrTfnjE8HpY164akBqe92LFVsk8RusaGsVPrMekT8emTq5y8v8CabuZg5rDs3f9NPEtogjyx49wiub1FecM5B7QqEcZSYiKHgF4mfkteT2";

            var decodedVector1 = SsiSerializer.Decode(Vector1, ExactSizeMemoryPool<byte>.Shared, TestBase58Decoder).Memory.Span;
            var reEncodedVector1 = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.RsaPublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.Equal(Vector1, reEncodedVector1);

            //A sanity check, some (in practice 'any') other vector type should not work.
            var reEncodedVector1WithWrongHeader = SsiSerializer.Encode(decodedVector1, MulticodecHeaders.P256PublicKey, MultibaseAlgorithms.Base58Btc, TestBase58Encoder);
            Assert.NotEqual(Vector1, reEncodedVector1WithWrongHeader);
        }
    }
}
