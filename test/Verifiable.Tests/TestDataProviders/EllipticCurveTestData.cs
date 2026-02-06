using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Verifiable.Cryptography;


namespace Verifiable.Tests.TestDataProviders
{
    /// <summary>
    /// Test data container for elliptic curve tests.
    /// </summary>
    /// <param name="IsEven">Whether the Y coordinate is even (<see cref="EllipticCurveUtilities.EvenYCoordinate"/>)
    /// or odd (<see cref="EllipticCurveUtilities.OddYCoordinate"/>).</param>
    /// <param name="PublicKeyMulticodecHeader">The multicodec header bytes for the public key.</param>
    /// <param name="PrivateKeyMulticodecHeader">The multicodec header bytes for the private key.</param>
    /// <param name="Base58BtcEncodedMulticodecHeaderPublicKey">A Base58 BTC encoded public header prefix, see <see cref="Base58BtcEncodedMulticodecHeaders"/>.</param>
    /// <param name="Base58BtcEncodedMulticodecHeaderPrivateKey">A Base58 BTC encoded private header prefix, see <see cref="Base58BtcEncodedMulticodecHeaders"/>.</param>
    /// <param name="CurveIdentifier">The human-friendly name for the elliptic curve.</param>
    /// <param name="PublicKeyMaterialX">The public key point X coordinate.</param>
    /// <param name="PublicKeyMaterialY">The public key point Y coordinate.</param>
    /// <param name="PrivateKeyMaterial">The private key scalar.</param>
    /// <param name="PrimeBytes">The prime bytes for the curve.</param>
    internal record EllipticCurveTestData(
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
    /// Contains elliptic curve test data generator using BouncyCastle for cross-platform compatibility.
    /// Provides data for MSTest DynamicData.
    /// </summary>
    internal class EllipticCurveTheoryData
    {
        public const string EllipticP256 = "P-256";
        public const string EllipticP384 = "P-384";
        public const string EllipticP521 = "P-521";
        public const string EllipticSecP256k1 = "secP256k1";

        /// <summary>
        /// The DID supported elliptic curves. These are used to generate keys for testing.
        /// </summary>
        public static IList<string> HumanReadableEllipticCurveConstants => new List<string>(
        [
            EllipticP256,
            EllipticP384,
            EllipticP521,
            EllipticSecP256k1
        ]);

        /// <summary>
        /// Provides the elliptic curve test data as DynamicData for MSTest.
        /// Each curve produces two test cases: one with an even Y coordinate and one with an odd Y coordinate.
        /// </summary>
        public static IEnumerable<object[]> GetEllipticCurveTestData()
        {
            foreach(string humanReadableEllipticCurveConstant in HumanReadableEllipticCurveConstants)
            {
                (EllipticCurveTestData EvenKey, EllipticCurveTestData OddKey) = GenerateEllipticTestKeyMaterial(humanReadableEllipticCurveConstant);
                yield return [EvenKey];
                yield return [OddKey];
            }
        }

        /// <summary>
        /// Generates a pair of even-Y and odd-Y test key material for the given curve using BouncyCastle.
        /// </summary>
        private static (EllipticCurveTestData EvenKey, EllipticCurveTestData OddKey) GenerateEllipticTestKeyMaterial(string humanReadableCurveName)
        {
            string secCurveName = FromHumanReadableToSecCurveName(humanReadableCurveName);
            var curve = SecNamedCurves.GetByName(secCurveName);
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            var random = new SecureRandom();

            AsymmetricCipherKeyPair? evenKeyPair = null;
            AsymmetricCipherKeyPair? oddKeyPair = null;

            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(domainParams, random));

            while(evenKeyPair == null || oddKeyPair == null)
            {
                var keyPair = generator.GenerateKeyPair();
                var publicKeyParam = (ECPublicKeyParameters)keyPair.Public;

                //The last byte of the Y coordinate determines even/odd parity.
                byte[] yBytes = publicKeyParam.Q.AffineYCoord.GetEncoded();
                bool isEven = (yBytes[^1] & 1) == 0;

                if(isEven && evenKeyPair == null)
                {
                    evenKeyPair = keyPair;
                }
                else if(!isEven && oddKeyPair == null)
                {
                    oddKeyPair = keyPair;
                }
            }

            byte[] primeBytes = humanReadableCurveName switch
            {
                EllipticP256 => EllipticCurveConstants.P256.PrimeBytes.ToArray(),
                EllipticP384 => EllipticCurveConstants.P384.PrimeBytes.ToArray(),
                EllipticP521 => EllipticCurveConstants.P521.PrimeBytes.ToArray(),
                EllipticSecP256k1 => EllipticCurveConstants.Secp256k1.PrimeBytes.ToArray(),
                _ => throw new NotSupportedException($"Unsupported curve: {humanReadableCurveName}.")
            };

            (string PublicKey, string PrivateKey) btc58Headers = FromCurveNameToBtc58EncodedHeader(humanReadableCurveName);
            (byte[] PublicKeyHeader, byte[] PrivateKeyHeader) = FromCurveNameToMultiCodecHeader(humanReadableCurveName);

            var evenTestKeyMaterial = ExtractTestData(
                evenKeyPair, true, PublicKeyHeader, PrivateKeyHeader,
                btc58Headers, humanReadableCurveName, primeBytes, curve);

            var oddTestKeyMaterial = ExtractTestData(
                oddKeyPair, false, PublicKeyHeader, PrivateKeyHeader,
                btc58Headers, humanReadableCurveName, primeBytes, curve);

            return (evenTestKeyMaterial, oddTestKeyMaterial);
        }

        /// <summary>
        /// Extracts X, Y, and D from a BouncyCastle key pair into test data.
        /// </summary>
        private static EllipticCurveTestData ExtractTestData(
            AsymmetricCipherKeyPair keyPair,
            bool isEven,
            byte[] publicKeyMulticodecHeader,
            byte[] privateKeyMulticodecHeader,
            (string PublicKey, string PrivateKey) btc58Headers,
            string curveIdentifier,
            byte[] primeBytes,
            Org.BouncyCastle.Asn1.X9.X9ECParameters curve)
        {
            var publicKeyParam = (ECPublicKeyParameters)keyPair.Public;
            var privateKeyParam = (ECPrivateKeyParameters)keyPair.Private;

            int fieldSize = (curve.Curve.FieldSize + 7) / 8;

            byte[] x = publicKeyParam.Q.AffineXCoord.GetEncoded();
            byte[] y = publicKeyParam.Q.AffineYCoord.GetEncoded();
            byte[] d = privateKeyParam.D.ToByteArrayUnsigned();

            //Normalize private key to fixed curve field size with leading zero padding if needed.
            if(d.Length < fieldSize)
            {
                byte[] padded = new byte[fieldSize];
                d.CopyTo(padded.AsSpan(fieldSize - d.Length));
                d = padded;
            }

            return new EllipticCurveTestData(
                isEven,
                publicKeyMulticodecHeader,
                privateKeyMulticodecHeader,
                btc58Headers.PublicKey,
                btc58Headers.PrivateKey,
                curveIdentifier,
                x,
                y,
                d,
                primeBytes);
        }

        private static string FromHumanReadableToSecCurveName(string humanReadable) => humanReadable switch
        {
            EllipticP256 => "secp256r1",
            EllipticP384 => "secp384r1",
            EllipticP521 => "secp521r1",
            EllipticSecP256k1 => "secp256k1",
            _ => throw new NotSupportedException($"Unsupported curve: {humanReadable}.")
        };

        private static (string PublicKey, string PrivateKey) FromCurveNameToBtc58EncodedHeader(string humanReadable) => humanReadable switch
        {
            EllipticP256 => (Base58BtcEncodedMulticodecHeaders.P256PublicKey.ToString(), string.Empty),
            EllipticP384 => (Base58BtcEncodedMulticodecHeaders.P384PublicKey.ToString(), string.Empty),
            EllipticP521 => (Base58BtcEncodedMulticodecHeaders.P521PublicKey.ToString(), string.Empty),
            EllipticSecP256k1 => (Base58BtcEncodedMulticodecHeaders.Secp256k1PublicKey.ToString(), string.Empty),
            _ => throw new NotSupportedException($"Unsupported curve: {humanReadable}.")
        };

        private static (byte[] PublicKeyHeader, byte[] PrivateKeyHeader) FromCurveNameToMultiCodecHeader(string humanReadable) => humanReadable switch
        {
            EllipticP256 => (MulticodecHeaders.P256PublicKey.ToArray(), []),
            EllipticP384 => (MulticodecHeaders.P384PublicKey.ToArray(), []),
            EllipticP521 => (MulticodecHeaders.P521PublicKey.ToArray(), []),
            EllipticSecP256k1 => (MulticodecHeaders.Secp256k1PublicKey.ToArray(), MulticodecHeaders.Secp256k1PrivateKey.ToArray()),
            _ => throw new NotSupportedException($"Unsupported curve: {humanReadable}.")
        };
    }
}