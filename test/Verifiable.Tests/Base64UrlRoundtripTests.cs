using System.Buffers;
using System.Buffers.Text;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests
{
    [TestClass]
    internal class Base64UrlRoundtripTests
    {
        [TestMethod]
        public void Base64UrlEncoderDecoderRoundtripTest()
        {
            //Test data - various byte arrays to ensure different padding scenarios.
            byte[][] testData =
            {
                [0x48, 0x65, 0x6C, 0x6C, 0x6F], // "Hello" - no padding needed in Base64
                [0x48, 0x65, 0x6C, 0x6C], // "Hell" - 2 padding chars needed
                [0x48, 0x65, 0x6C], // "Hel" - 1 padding char needed
                [0xFF, 0xFE, 0xFD], // Binary data with high values
                [0x3E, 0x3F, 0x3D], // Contains chars that become +/= in Base64
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(32), // Random 32 bytes
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(33), // Random 33 bytes (padding test)
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(34) // Random 34 bytes (padding test)
            };

            foreach(var originalData in testData)
            {                
                //Test our Base64Url encoder/decoder roundtrip.
                var pool = SensitiveMemoryPool<char>.Shared;
                var memPool = SensitiveMemoryPool<byte>.Shared;

                //Encode using our Base64Url encoder.
                string ourBase64Url = TestSetup.Base64UrlEncoder(originalData);
                
                //Decode using our Base64Url decoder.
                using var decodedOwner = TestSetup.Base64UrlDecoder(ourBase64Url, memPool);
                byte[] ourDecoded = decodedOwner.Memory.ToArray();
                
                //Verify roundtrip works.
                CollectionAssert.AreEqual(originalData, ourDecoded, "Our Base64Url roundtrip failed");

                //Compare with .NET Base64 reference implementation.
                string netBase64 = Convert.ToBase64String(originalData);
                string netBase64Url = netBase64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
                
                //Our encoder should produce the same result as .NET conversion.
                Assert.AreEqual(netBase64Url, ourBase64Url, "Base64Url encoding doesn't match .NET reference");

                //Test decoding .NET Base64Url with our decoder.
                using var netDecodedOwner = TestSetup.Base64UrlDecoder(netBase64Url, memPool);
                byte[] netDecoded = netDecodedOwner.Memory.ToArray();

                //Should decode .NET Base64Url correctly.
                CollectionAssert.AreEqual(originalData, netDecoded, "Failed to decode .NET Base64Url");                
            }
        }

        [TestMethod]
        public void Base64UrlCharacterReplacementTest()
        {
            //Test data that will produce + and / in Base64 (which become - and _ in Base64Url).
            byte[] testData = { 0x3E, 0x3F, 0x3D, 0xFF, 0xFE }; // This should produce +/= chars in Base64

            //Standard Base64.
            string base64 = Convert.ToBase64String(testData);
            
            //Manual Base64Url conversion.
            string manualBase64Url = base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
            
            //Our Base64Url encoder.
            var pool = SensitiveMemoryPool<char>.Shared;
            string ourBase64Url = TestSetup.Base64UrlEncoder(testData);
            
            //Should match manual conversion.
            Assert.AreEqual(manualBase64Url, ourBase64Url, "Character replacement doesn't match manual conversion");

            //Verify no forbidden characters in Base64Url.
            Assert.IsFalse(ourBase64Url.Contains('+', StringComparison.Ordinal), "Base64Url contains forbidden '+'");
            Assert.IsFalse(ourBase64Url.Contains('/', StringComparison.Ordinal), "Base64Url contains forbidden '/'");
            Assert.IsFalse(ourBase64Url.Contains('=', StringComparison.Ordinal), "Base64Url contains forbidden '='");
        }

        [TestMethod]
        public void Base64UrlPaddingTest()
        {
            //Test different padding scenarios.
            var testCases = new[]
            {
                (Data: new byte[] { 0x48 }, ExpectedPadding: 2), // 1 byte -> 2 padding chars in Base64
                (Data: new byte[] { 0x48, 0x65 }, ExpectedPadding: 1), // 2 bytes -> 1 padding char in Base64
                (Data: new byte[] { 0x48, 0x65, 0x6C }, ExpectedPadding: 0), // 3 bytes -> no padding in Base64
                (Data: new byte[] { 0x48, 0x65, 0x6C, 0x6C }, ExpectedPadding: 2), // 4 bytes -> 2 padding chars
            };

            var pool = SensitiveMemoryPool<char>.Shared;
            ReadOnlySpan<byte> emptyCodecHeader = ReadOnlySpan<byte>.Empty;

            foreach(var (data, expectedPadding) in testCases)
            {
                //Standard Base64 with padding.
                string base64 = Convert.ToBase64String(data);
                int actualPadding = base64.Length - base64.TrimEnd('=').Length;

                Assert.AreEqual(expectedPadding, actualPadding, $"Padding expectation wrong for {Convert.ToHexString(data)}");

                //Our Base64Url should have no padding.
                string ourBase64Url = TestSetup.Base64UrlEncoder(data);
                Assert.IsFalse(ourBase64Url.Contains('=', StringComparison.Ordinal), $"Base64Url should not contain padding for {Convert.ToHexString(data)}");

                //Length should be base64 length minus padding.
                Assert.AreEqual(base64.Length - expectedPadding, ourBase64Url.Length, "Base64Url length incorrect");

                Console.WriteLine($"Data: {Convert.ToHexString(data)} -> Base64: {base64} -> Base64Url: {ourBase64Url}");
            }
        }

        [TestMethod]
        public void DirectBase64ComparisonTest()
        {
            //Test using System.Buffers.Text.Base64 directly vs our implementation.
            byte[] testData = { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64 }; // "Hello World"

            //Direct System.Buffers.Text.Base64 usage.
            int maxEncodedLength = Base64.GetMaxEncodedToUtf8Length(testData.Length);
            Span<byte> directBase64Buffer = stackalloc byte[maxEncodedLength];

            OperationStatus status = Base64.EncodeToUtf8(testData, directBase64Buffer, out int bytesConsumed, out int bytesWritten);
            Assert.AreEqual(OperationStatus.Done, status, "Direct Base64 encoding failed");

            string directBase64 = Encoding.UTF8.GetString(directBase64Buffer[..bytesWritten]);
            
            //Our Base64Url encoder (should use same Base64 underneath).
            var pool = SensitiveMemoryPool<char>.Shared;
            string ourBase64Url = TestSetup.Base64UrlEncoder(testData);

            //Convert our result back to Base64 for comparison.
            string ourAsBase64 = ourBase64Url.Replace('-', '+').Replace('_', '/');

            //Add padding if needed.
            int paddingNeeded = (4 - (ourAsBase64.Length % 4)) % 4;
            if(paddingNeeded > 0)
            {
                ourAsBase64 = ourAsBase64.PadRight(ourAsBase64.Length + paddingNeeded, '=');
            }
            
            //Should match the direct Base64 encoding.
            Assert.AreEqual(directBase64, ourAsBase64, "Our Base64 doesn't match direct System.Buffers.Text.Base64");
        }
    }
}