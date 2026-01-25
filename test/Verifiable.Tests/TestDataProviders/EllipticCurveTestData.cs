using DotLiquid.Tags;
using System.Collections.Specialized;
using System.Reflection;
using System.Security.Cryptography;
using Tpm2Lib;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;


namespace Verifiable.Tests.DataProviders
{
    /// <summary>
    /// Test data container for elliptic curve tests.
    /// </summary>
    /// <param name="IsEven">If the elliptic curve coordinates are <see cref="EllipticCurveUtilities.EvenYCoordinate"/>
    /// or <see cref="EllipticCurveUtilities.OddYCoordinate"/>.</param>
    /// <param name="Base58BtcEncodedMulticodecHeaderPublicKey">A BTC 58 encoded public header prefix, see <see cref="Base58BtcEncodedMulticodecHeaders"/>.</param>
    /// <param name="Base58BtcEncodedMulticodecHeaderPrivateKey">A BTC 58 encoded public header prefix, see <see cref="Base58BtcEncodedMulticodecHeaders"/>.</param>
    /// <param name="CurveIdentifier">The crypto algorytm for elliptic curve. See <see cref="CryptoAlgorithm"/>.</param>
    /// <param name="PublicKeyMaterialX">The public key point X key material.</param>
    /// <param name="PublicKeyMaterialY">The public key point Y key material.</param>
    /// <param name="PrivateKeyMaterial">The private key material.</param>
    /// <param name="PrimeBytes">The prime bytes for the curve.</param>
    public record EllipticCurveTestData(
        bool IsEven,
        byte[] PublicKeyMulticodecHeader,
        byte[] PrivateKeyMulticodecHeader,
        string Base58BtcEncodedMulticodecHeaderPublicKey,
        string Base58BtcEncodedMulticodecHeaderPrivateKey,
        CryptoAlgorithm CurveIdentifier,
        byte[] PublicKeyMaterialX,
        byte[] PublicKeyMaterialY,
        byte[] PrivateKeyMaterial,
        byte[] PrimeBytes);

    public record EllipticCurveTestCase(CryptoAlgorithm CurveIdentifier, bool IsEven)
    {
        public override string ToString() => $"{CurveIdentifier.ToString()} {(IsEven ? "Even" : "Odd")}";
    }

    /// <summary>
    /// Contains elliptic curve test data generator and provides it for MSTest DynamicData.
    /// </summary>
    public class EllipticCurveTheoryData
    {
        /// <summary>
        /// The DID supported elliptic curves. These are used to generate keys for testing.
        /// </summary>
        private static IList<CryptoAlgorithm> EllipticCurveCryptoAlgorithms => 
        [
            CryptoAlgorithm.P256,
            CryptoAlgorithm.P384,
            CryptoAlgorithm.P521,
            CryptoAlgorithm.Secp256k1,
        ];

        /// <summary>
        /// Provides the elliptic curve test data as DynamicData for MSTest.
        /// </summary>
        /// <returns>An IEnumerable of object arrays containing test data.</returns>
        public static IEnumerable<object[]> GetEllipticCurveTestData()
        {
            foreach(var cryptoAlgorithm in EllipticCurveCryptoAlgorithms)
            {
                yield return new object[] { new EllipticCurveTestCase(cryptoAlgorithm, IsEven: true) };
                yield return new object[] { new EllipticCurveTestCase(cryptoAlgorithm, IsEven: false) };
            }
        }

        public static EllipticCurveTestData CreateEllipticCurveTestData(EllipticCurveTestCase testCase)
        {
            (EllipticCurveTestData EvenKey, EllipticCurveTestData OddKey) = GenerateEllipticTestKeyMaterial(testCase.CurveIdentifier);
            return testCase.IsEven ? EvenKey : OddKey;
        }
        
        private static (EllipticCurveTestData EvenKey, EllipticCurveTestData OddKey) GenerateEllipticTestKeyMaterial(CryptoAlgorithm humanReadableCurveName)
        {
            ECDsa? evenKey = null;
            ECDsa? oddKey = null;
            while(evenKey == null || oddKey == null)
            {
                var loopKey = ECDsa.Create(FromHumanReadableEllipticPrimeCurve(humanReadableCurveName));
                ECParameters loopParams = loopKey.ExportParameters(includePrivateParameters: false);
                byte loopSignByte = EllipticCurveUtilities.CompressionSignByte(loopParams.Q.Y);
                if(loopSignByte == EllipticCurveUtilities.EvenYCoordinate)
                {
                    evenKey = loopKey;
                }
                else
                {
                    oddKey = loopKey;
                }
            }

            byte[] primeBytes = humanReadableCurveName switch
            {
                var a when a == CryptoAlgorithm.P256 => EllipticCurveConstants.P256.PrimeBytes.ToArray(),
                var a when a == CryptoAlgorithm.P384 => EllipticCurveConstants.P384.PrimeBytes.ToArray(),
                var a when a == CryptoAlgorithm.P521 => EllipticCurveConstants.P521.PrimeBytes.ToArray(),
                var a when a == CryptoAlgorithm.Secp256k1 => EllipticCurveConstants.Secp256k1.PrimeBytes.ToArray(),
                _ => throw new NotSupportedException()
            };

            (string PublicKey, string PrivateKey) btc58Headers = FromCurveNameToBtc58EncodedHeader(humanReadableCurveName);
            (byte[] PublicKeyHeader, byte[] PrivateKeyHeader) = FromCurveNameToMultiCodecHeader(humanReadableCurveName);

            ECParameters evenKeyParameters = evenKey.ExportParameters(includePrivateParameters: true);
            byte[] evenPublicKeyX = evenKeyParameters.Q.X!;
            byte[] evenPublicKeyY = evenKeyParameters.Q.Y!;
            byte[] evenPrivateKey = evenKeyParameters.D!;
            var evenTestKeyMaterial = new EllipticCurveTestData(
                true,
                PublicKeyHeader,
                PrivateKeyHeader,
                btc58Headers.PublicKey,
                btc58Headers.PrivateKey,
                humanReadableCurveName,
                evenPublicKeyX,
                evenPublicKeyY,
                evenPrivateKey,
                primeBytes);

            ECParameters oddKeyParameters = oddKey.ExportParameters(includePrivateParameters: true);
            byte[] oddPublicKeyX = oddKeyParameters.Q.X!;
            byte[] oddPublicKeyY = oddKeyParameters.Q.Y!;
            byte[] oddPrivateKey = oddKeyParameters.D!;
            var oddTestKeyMaterial = new EllipticCurveTestData(
                false,
                PublicKeyHeader,
                PrivateKeyHeader,
                btc58Headers.PublicKey,
                btc58Headers.PrivateKey,
                humanReadableCurveName,
                oddPublicKeyX,
                oddPublicKeyY,
                oddPrivateKey,
                primeBytes);

            return (evenTestKeyMaterial, oddTestKeyMaterial);
        }

        private static ECCurve FromHumanReadableEllipticPrimeCurve(CryptoAlgorithm humanReadable) => humanReadable switch
        {
            var a when a == CryptoAlgorithm.P256 => ECCurve.NamedCurves.nistP256,
            var a when a == CryptoAlgorithm.P384 => ECCurve.NamedCurves.nistP384,
            var a when a == CryptoAlgorithm.P521 => ECCurve.NamedCurves.nistP521,
            var a when a == CryptoAlgorithm.Secp256k1 => ECCurve.CreateFromFriendlyName("secP256k1"),
            _ => throw new NotSupportedException()
        };

        private static (string PublicKey, string PrivateKey) FromCurveNameToBtc58EncodedHeader(CryptoAlgorithm humanReadable) => humanReadable switch
        {
            var a when a == CryptoAlgorithm.P256 => (Base58BtcEncodedMulticodecHeaders.P256PublicKey.ToString(), string.Empty),
            var a when a == CryptoAlgorithm.P384 => (Base58BtcEncodedMulticodecHeaders.P384PublicKey.ToString(), string.Empty),
            var a when a == CryptoAlgorithm.P521 => (Base58BtcEncodedMulticodecHeaders.P521PublicKey.ToString(), string.Empty),
            var a when a == CryptoAlgorithm.Secp256k1 => (Base58BtcEncodedMulticodecHeaders.Secp256k1PublicKey.ToString(), string.Empty),
            _ => throw new NotSupportedException()
        };

        private static (byte[] PublicKeyHeader, byte[] PrivateKeyHeader) FromCurveNameToMultiCodecHeader(CryptoAlgorithm humanReadable) => humanReadable switch
        {
            var a when a == CryptoAlgorithm.P256 => (MulticodecHeaders.P256PublicKey.ToArray(), Array.Empty<byte>()),
            var a when a == CryptoAlgorithm.P384 => (MulticodecHeaders.P384PublicKey.ToArray(), Array.Empty<byte>()),
            var a when a == CryptoAlgorithm.P521 => (MulticodecHeaders.P521PublicKey.ToArray(), Array.Empty<byte>()),
            var a when a == CryptoAlgorithm.Secp256k1 => (MulticodecHeaders.Secp256k1PublicKey.ToArray(), MulticodecHeaders.Secp256k1PrivateKey.ToArray()),
            _ => throw new NotSupportedException()
        };
    }
}
