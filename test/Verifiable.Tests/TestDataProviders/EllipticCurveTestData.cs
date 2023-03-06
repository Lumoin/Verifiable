using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Xunit;

namespace Verifiable.Tests.DataProviders
{
    /// <summary>
    /// Test data container for elliptic curve tests.
    /// </summary>
    /// <param name="IsEven">If the elliptic curve coordinates are <see cref="EllipticCurveUtilities.EvenYCoordinate"/>
    /// or <see cref="EllipticCurveUtilities.OddYCoordinate"/>.</param>
    /// <param name="Base58BtcEncodedMulticodecHeaderPublicteKey">A BTC 58 encoded public header prefix, see <see cref="Base58BtcEncodedMulticodecHeaders"/>.</param>
    /// <param name="Base58BtcEncodedMulticodecHeaderPrivateKey">A BTC 58 encoded public header prefix, see <see cref="Base58BtcEncodedMulticodecHeaders"/>.</param>
    /// <param name="CurveIdentifier">The human friendly name for elliptic curves according to Microsoft. See <see cref="EllipticCurveTheoryData.HumanReadableEllipticCurveConstants"/>.</param>
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
    ///  
    /// </summary>
    public class EllipticCurveTheoryData: TheoryData<EllipticCurveTestData>
    {
        private static readonly IList<EllipticCurveTestData> ellipticCurveTestData = new List<EllipticCurveTestData>();

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
        /// Turns the human readable curve name into <see cref="ECCurve"/>.
        /// </summary>
        /// <param name="humanReadable">Human readable elliptic curve name.</param>
        /// <returns>Corresponding <see cref="ECCurve"/>.</returns>
        /// <exception cref="NotSupportedException"></exception>
        public static ECCurve FromHumanReadableEllipticPrimeCurve(string humanReadable) => humanReadable switch
        {
            EllipticP256 => ECCurve.NamedCurves.nistP256,
            EllipticP384 => ECCurve.NamedCurves.nistP384,
            EllipticP521 => ECCurve.NamedCurves.nistP521,
            EllipticSecP256k1 => ECCurve.CreateFromFriendlyName(EllipticSecP256k1),
            _ => throw new NotSupportedException()
        };


        /// <summary>
        /// Turns the human readable curve name into <see cref="Base58BtcEncodedMulticodecHeaders"/>.
        /// </summary>
        /// <param name="humanReadable">Human readable elliptic curve name.</param>
        /// <returns><see cref="Base58BtcEncodedMulticodecHeaders">public and private Base58 BTC encode multicodec value</see>.</returns>
        /// <exception cref="NotSupportedException"></exception>
        public static (string PublicKey, string PrivateKey) FromCurveNameToBtc58EncodedHeader(string humanReadable) => humanReadable switch
        {
            EllipticP256 => (Base58BtcEncodedMulticodecHeaders.P256PublicKey.ToString(), string.Empty),
            EllipticP384 => (Base58BtcEncodedMulticodecHeaders.P384PublicKey.ToString(), string.Empty),
            EllipticP521 => (Base58BtcEncodedMulticodecHeaders.P521PublicKey.ToString(), string.Empty),
            EllipticSecP256k1 => (Base58BtcEncodedMulticodecHeaders.Secp256k1PublicKey.ToString(), string.Empty),
            _ => throw new NotSupportedException()
        };


        /// <summary>
        /// Turns the human readable curve name into <see cref="Base58BtcEncodedMulticodecHeaders"/>.
        /// </summary>
        /// <param name="humanReadable">Human readable elliptic curve name.</param>
        /// <returns><see cref="Base58BtcEncodedMulticodecHeaders">public and private Base58 BTC encode multicodec value</see>.</returns>
        /// <exception cref="NotSupportedException"></exception>
        public static (byte[] PublicKeyHeader, byte[] PrivateKeyHeader) FromCurveNameToMultiCodecHeader(string humanReadable) => humanReadable switch
        {
            EllipticP256 => (MulticodecHeaders.P256PublicKey.ToArray(), Array.Empty<byte>()),
            EllipticP384 =>  (MulticodecHeaders.P384PublicKey.ToArray(), Array.Empty<byte>()),
            EllipticP521 =>  (MulticodecHeaders.P521PublicKey.ToArray(), Array.Empty<byte>()),
            EllipticSecP256k1 =>  (MulticodecHeaders.Secp256k1PublicKey.ToArray(), MulticodecHeaders.Secp256k1PrivateKey.ToArray()),
            _ => throw new NotSupportedException()
        };


        static EllipticCurveTheoryData()
        {
            foreach(string humanReadableEllipticCurveConstant in HumanReadableEllipticCurveConstants)
            {
                (EllipticCurveTestData EvenKey, EllipticCurveTestData OddKey) = GenerateEllipticTestKeyMaterial(humanReadableEllipticCurveConstant);                
                ellipticCurveTestData.Add(EvenKey);
                ellipticCurveTestData.Add(OddKey);
            }
        }

        public EllipticCurveTheoryData()
        {
            foreach(var td in ellipticCurveTestData)
            {
                Add(td);
            }
        }

        private static (EllipticCurveTestData EvenKey, EllipticCurveTestData OddKey) GenerateEllipticTestKeyMaterial(string humanReadableCurveName)
        {
            ECDsa? evenKey = null;
            ECDsa? oddKey = null;
            while(evenKey == null || oddKey == null)
            {
                var loopKey = ECDsa.Create(FromHumanReadableEllipticPrimeCurve(humanReadableCurveName));
                var loopParams = loopKey.ExportParameters(includePrivateParameters: false);
                var loopSignByte = EllipticCurveUtilities.CompressionSignByte(loopParams.Q.Y);
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

            var btc58Headers = FromCurveNameToBtc58EncodedHeader(humanReadableCurveName);
            var multiCodecHeaders = FromCurveNameToMultiCodecHeader(humanReadableCurveName);
            
            ECParameters evenKeyParameters = evenKey.ExportParameters(includePrivateParameters: true);
            byte[] evenPublicKeyX = evenKeyParameters.Q.X!;
            byte[] evenPublicKeyY = evenKeyParameters.Q.Y!;
            byte[] evenPrivateKey = evenKeyParameters.D!;
            var evenTestKeyMaterial = new EllipticCurveTestData(
                true,
                multiCodecHeaders.PublicKeyHeader,
                multiCodecHeaders.PrivateKeyHeader,
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
                true,
                multiCodecHeaders.PublicKeyHeader,
                multiCodecHeaders.PrivateKeyHeader,
                btc58Headers.PublicKey,
                btc58Headers.PrivateKey,                
                humanReadableCurveName,
                oddPublicKeyX,
                oddPublicKeyY,
                oddPrivateKey,
                primeBytes);

            return (evenTestKeyMaterial, oddTestKeyMaterial);
        }
    }
}
