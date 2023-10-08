using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Runtime.CompilerServices;

namespace Verifiable.BouncyCastle
{
    public static class BouncyCastleCryptographicFunctions
    {
        public static bool VerifyP256(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            const string SignatureAlgorithm = "SHA256withECDSA";
            const string CurveName = "P-256";

            return Verify(dataToVerify.ToArray(), signature.ToArray(), publicKeyMaterial.ToArray(), SignatureAlgorithm, CurveName);
        }


        public static bool VerifyP384(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            const string SignatureAlgorithm = "SHA384withECDSA";
            const string CurveName = "P-384";

            return Verify(dataToVerify.ToArray(), signature.ToArray(), publicKeyMaterial.ToArray(), SignatureAlgorithm, CurveName);
        }


        public static bool VerifyP521(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            const string SignatureAlgorithm = "SHA512withECDSA";
            const string CurveName = "P-521";

            return Verify(dataToVerify.ToArray(), signature.ToArray(), publicKeyMaterial.ToArray(), SignatureAlgorithm, CurveName);
        }

        public static bool VerifySeckpk1(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            const string SignatureAlgorithm = "SHA256withECDSA";
            const string CurveName = "secp256k1";

            return Verify(dataToVerify.ToArray(), signature.ToArray(), publicKeyMaterial.ToArray(), SignatureAlgorithm, CurveName);
        }

        public static bool VerifyEd25519(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            const string SignatureAlgorithm = "Ed25519";
            return Verify(dataToVerify.ToArray(), signature.ToArray(), publicKeyMaterial.ToArray(), SignatureAlgorithm, string.Empty);
        }


        private static bool Verify(byte[] dataToVerify, byte[] signature, byte[] publicKeyMaterial, string signatureAlgorithm, string curveName)
        {
            ICipherParameters publicKeyParams;
            if(signatureAlgorithm == "Ed25519")
            {
                publicKeyParams = new Ed25519PublicKeyParameters(publicKeyMaterial, 0);
            }
            else
            {
                //PublicKeyFactory.CreateKey is not used here because it automatically detects
                //the key type from the key material.
                //The automatic key type detection could lead to potential security issues if an attacker
                //is able to manipulate the key format to use a weaker algorithm or curve.

                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.GetInstance(publicKeyMaterial);
                Asn1Object asn1Params = subjectPublicKeyInfo.AlgorithmID.Parameters.ToAsn1Object();
                DerObjectIdentifier oid = (DerObjectIdentifier)asn1Params;

                X9ECParameters x9EC = ECNamedCurveTable.GetByOid(oid);
                ECDomainParameters ecDomain = new(x9EC.Curve, x9EC.G, x9EC.N, x9EC.H, x9EC.GetSeed());

                Org.BouncyCastle.Math.EC.ECPoint publicKeyPoint = x9EC.Curve.DecodePoint(subjectPublicKeyInfo.PublicKeyData.GetBytes());
                publicKeyParams = new ECPublicKeyParameters(publicKeyPoint, ecDomain);

                static int GetSignatureLength(int fieldSizeInBits)
                {
                    //Round up to the nearest byte, and then multiply by 2 for R and S values.
                    //This is done instead of just dividing by four since P-521 length
                    //is not divisible by four.
                    return (fieldSizeInBits + 7) / 8 * 2;
                }

                //BouncyCasle expects the key parameter to be in ASN.1 format for SHA algorithms.
                //TODO: Be explicit regarding they key format instead of "knowing" it's in raw format and specifically
                //SubjectKeyPublicKeyInfo.
                if(signatureAlgorithm.StartsWith("SHA") && signature.Length == GetSignatureLength(publicKeyPoint.Curve.FieldSize))
                {
                    int halfLength = signature.Length / 2;
                    Org.BouncyCastle.Math.BigInteger r = new Org.BouncyCastle.Math.BigInteger(1, signature, 0, halfLength);
                    Org.BouncyCastle.Math.BigInteger s = new Org.BouncyCastle.Math.BigInteger(1, signature, halfLength, halfLength);

                    using(MemoryStream derSignatureStream = new())
                    {
                        DerSequenceGenerator seqGen = new(derSignatureStream);
                        seqGen.AddObject(new DerInteger(r));
                        seqGen.AddObject(new DerInteger(s));
                        seqGen.Close();

                        signature = derSignatureStream.ToArray();
                    }
                }
            }

            ISigner signer = SignerUtilities.GetSigner(signatureAlgorithm);
            signer.Init(forSigning: false, publicKeyParams);
            signer.BlockUpdate(dataToVerify, 0, dataToVerify.Length);

            bool ret = signer.VerifySignature(signature);
            return ret;
        }
    }
}
