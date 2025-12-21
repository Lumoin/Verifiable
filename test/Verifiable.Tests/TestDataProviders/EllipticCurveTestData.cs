using System.Security.Cryptography;
using Verifiable.Cryptography;


namespace Verifiable.Tests.DataProviders
{
    /// <summary>
    /// Test data container for elliptic curve tests.
    /// </summary>
    /// <param name="IsEven">If the elliptic curve coordinates are <see cref="EllipticCurveUtilities.EvenYCoordinate"/>
    /// or <see cref="EllipticCurveUtilities.OddYCoordinate"/>.</param>
    /// <param name="Base58BtcEncodedMulticodecHeaderPublicKey">A BTC 58 encoded public header prefix, see <see cref="Base58BtcEncodedMulticodecHeaders"/>.</param>
    /// <param name="Base58BtcEncodedMulticodecHeaderPrivateKey">A BTC 58 encoded public header prefix, see <see cref="Base58BtcEncodedMulticodecHeaders"/>.</param>
    /// <param name="CurveIdentifier">The human-friendly name for elliptic curves according to Microsoft. See <see cref="EllipticCurveTheoryData.HumanReadableEllipticCurveConstants"/>.</param>
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
        string CurveIdentifier,
        byte[] PublicKeyMaterialX,
        byte[] PublicKeyMaterialY,
        byte[] PrivateKeyMaterial,
        byte[] PrimeBytes);

    /// <summary>
    /// Contains elliptic curve test data generator and provides it for MSTest DynamicData.
    /// </summary>
    public class EllipticCurveTheoryData
    {
        public const string EllipticP256 = "P-256";
        public const string EllipticP384 = "P-384";
        public const string EllipticP521 = "P-521";
        public const string EllipticSecP256k1 = "secP256k1";

        /// <summary>
        /// The DID supported elliptic curves. These are used to generate keys for testing.
        /// </summary>
        public static IList<string> HumanReadableEllipticCurveConstants => new List<string>(new[]
        {
            EllipticP256,
            EllipticP384,
            EllipticP521,
            EllipticSecP256k1
        });

        /// <summary>
        /// Provides the elliptic curve test data as DynamicData for MSTest.
        /// </summary>
        /// <returns>An IEnumerable of object arrays containing test data.</returns>
        public static IEnumerable<object[]> GetEllipticCurveTestData()
        {
            foreach(string humanReadableEllipticCurveConstant in HumanReadableEllipticCurveConstants)
            {
                (EllipticCurveTestData EvenKey, EllipticCurveTestData OddKey) = GenerateEllipticTestKeyMaterial(humanReadableEllipticCurveConstant);
                yield return new object[] { EvenKey };
                yield return new object[] { OddKey };
            }
        }

        private static (EllipticCurveTestData EvenKey, EllipticCurveTestData OddKey) GenerateEllipticTestKeyMaterial(string humanReadableCurveName)
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
                EllipticP256 => EllipticCurveConstants.P256.PrimeBytes.ToArray(),
                EllipticP384 => EllipticCurveConstants.P384.PrimeBytes.ToArray(),
                EllipticP521 => EllipticCurveConstants.P521.PrimeBytes.ToArray(),
                EllipticSecP256k1 => EllipticCurveConstants.Secp256k1.PrimeBytes.ToArray(),
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

        private static ECCurve FromHumanReadableEllipticPrimeCurve(string humanReadable) => humanReadable switch
        {
            EllipticP256 => ECCurve.NamedCurves.nistP256,
            EllipticP384 => ECCurve.NamedCurves.nistP384,
            EllipticP521 => ECCurve.NamedCurves.nistP521,
            EllipticSecP256k1 => ECCurve.CreateFromFriendlyName(EllipticSecP256k1),
            _ => throw new NotSupportedException()
        };

        private static (string PublicKey, string PrivateKey) FromCurveNameToBtc58EncodedHeader(string humanReadable) => humanReadable switch
        {
            EllipticP256 => (Base58BtcEncodedMulticodecHeaders.P256PublicKey.ToString(), string.Empty),
            EllipticP384 => (Base58BtcEncodedMulticodecHeaders.P384PublicKey.ToString(), string.Empty),
            EllipticP521 => (Base58BtcEncodedMulticodecHeaders.P521PublicKey.ToString(), string.Empty),
            EllipticSecP256k1 => (Base58BtcEncodedMulticodecHeaders.Secp256k1PublicKey.ToString(), string.Empty),
            _ => throw new NotSupportedException()
        };

        private static (byte[] PublicKeyHeader, byte[] PrivateKeyHeader) FromCurveNameToMultiCodecHeader(string humanReadable) => humanReadable switch
        {
            EllipticP256 => (MulticodecHeaders.P256PublicKey.ToArray(), Array.Empty<byte>()),
            EllipticP384 => (MulticodecHeaders.P384PublicKey.ToArray(), Array.Empty<byte>()),
            EllipticP521 => (MulticodecHeaders.P521PublicKey.ToArray(), Array.Empty<byte>()),
            EllipticSecP256k1 => (MulticodecHeaders.Secp256k1PublicKey.ToArray(), MulticodecHeaders.Secp256k1PrivateKey.ToArray()),
            _ => throw new NotSupportedException()
        };
    }
}
