using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// The SECOND, house-engine-backed <see cref="VerifyXAdESSignatureValueDelegate"/> implementation the twin asks for: unlike <see cref="XAdESSignatureFactsDelegates.VerifyValueAsync"/> (which composes the BCL's <see
/// cref="System.Security.Cryptography.Xml.SignedXml"/>), this implementation composes the shipped verification surface directly — <see cref="XmlNodeTable.TryParse"/>, <see cref="XmlSignatureLocator.FindSignatures"/>, <see
/// cref="XmlSignature.TryRead"/>, <see cref="XmlReferenceProcessing.TryComputeDigestInput(XmlNodeTable, XmlSignature, int, XmlReferenceResolver?, BaseMemoryPool, out PooledMemory?, out XmlSignatureProcessingError)"/>,
/// <see cref="XmlReferenceProcessing.TryComputeSignedInfoOctets"/>, the house digest seam (<see cref="CryptographicKeyEvents.ComputeDigestAsync(System.ReadOnlyMemory{byte}, int, Tag, BaseMemoryPool,
/// System.Collections.Frozen.FrozenDictionary{string, object}?, string?, System.Threading.CancellationToken)"/>) and the house verification seam (<see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>) —
/// exactly the pipeline <c>XmlSignatureInteropOracleTests.VerifyCaseAsync</c> already proved against a real, independent platform signer for the XMLDSIG core. Restricted to ECDSA P-256 signing certificates, the only
/// shape this suite's fixtures mint. Verifies the <c>ds:SignatureValue</c> under the caller-supplied signing certificate's own public key (never <c>ds:KeyInfo</c>) — the same contract <see
/// cref="XAdESSignatureFactsDelegates.VerifyValueAsync"/> honours, so the two implementations diverge only in HOW they compute the cryptography, never in WHOSE key they compute it under.
/// </summary>
internal static class XAdESHouseEngineSignatureVerification
{
    /// <summary>The <see cref="VerifyXAdESSignatureValueDelegate"/> implementation.</summary>
    /// <param name="xmlDocument">The XML document octets carrying the <c>ds:Signature</c> to verify.</param>
    /// <param name="signingCertificate">The signing certificate identified by an earlier building block (Table 14's own "Signing Certificate" input) — the <c>ds:SignatureValue</c> is verified under THIS certificate's public key, never the document's own <c>ds:KeyInfo</c>.</param>
    /// <param name="pool">The memory pool every intermediate buffer is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome in Table 15's vocabulary.</returns>
    public static async ValueTask<SignatureCryptographicVerification> VerifyValueAsync(
        ReadOnlyMemory<byte> xmlDocument,
        PkiCertificateMemory signingCertificate,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);

        byte[]? publicKeyMaterial = ExtractEcdsaPublicKey(signingCertificate);
        if(publicKeyMaterial is null)
        {
            return Fail(SignatureCryptographicOutcome.SignedDataNotFound, "signingCertificate carries no recognized ECDSA public key.");
        }

        if(!XmlNodeTable.TryParse(xmlDocument, pool, out XmlNodeTable? table, out XmlReadError parseError))
        {
            return Fail(SignatureCryptographicOutcome.SignedDataNotFound, $"The document is not well-formed XML: {parseError.Failure} at offset {parseError.ByteOffset}.");
        }

        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            if(signatureIndices.Length != 1)
            {
                return Fail(SignatureCryptographicOutcome.SignedDataNotFound, $"The document must carry exactly one ds:Signature; found {signatureIndices.Length}.");
            }

            if(!XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError readError))
            {
                return Fail(SignatureCryptographicOutcome.SignedDataNotFound, $"The ds:Signature did not read: {readError.Failure}.");
            }

            using(signature)
            {
                for(int referenceOrdinal = 0; referenceOrdinal < signature!.SignedInfo.References.Count; ++referenceOrdinal)
                {
                    XmlReference reference = signature.SignedInfo.References[referenceOrdinal];
                    if(!XmlReferenceProcessing.TryComputeDigestInput(table!, signature, referenceOrdinal, resolver: null, pool, out PooledMemory? digestInput, out XmlSignatureProcessingError digestInputError))
                    {
                        return Fail(SignatureCryptographicOutcome.HashFailure, $"Reference {referenceOrdinal}: digest input did not compute: {digestInputError.Failure}.");
                    }

                    using(digestInput)
                    {
                        string digestMethodUri = Utf8(reference.DigestMethodAlgorithm);
                        PkiDigestAlgorithm? digestAlgorithm = XmlSignatureWellKnown.DigestAlgorithmFromUri(digestMethodUri);
                        if(digestAlgorithm is null)
                        {
                            return Fail(SignatureCryptographicOutcome.HashFailure, $"Reference {referenceOrdinal}: digest method '{digestMethodUri}' does not resolve.");
                        }

                        using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
                            digestInput!.AsReadOnlyMemory(), digestAlgorithm.Value.OutputByteLength, digestAlgorithm.Value.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                        if(!computed.AsReadOnlySpan().SequenceEqual(reference.DigestValueOctets.AsReadOnlySpan()))
                        {
                            return Fail(SignatureCryptographicOutcome.HashFailure, $"Reference {referenceOrdinal}: recomputed digest does not match the document's own DigestValue.");
                        }
                    }
                }

                if(!XmlReferenceProcessing.TryComputeSignedInfoOctets(table!, signature, pool, out PooledMemory? signedInfoOctets, out XmlSignatureProcessingError signedInfoError))
                {
                    return Fail(SignatureCryptographicOutcome.SignatureValueFailure, $"ds:SignedInfo octets did not compute: {signedInfoError.Failure}.");
                }

                using(signedInfoOctets)
                {
                    VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(CryptoAlgorithm.P256, Purpose.Verification);
                    (bool isVerified, _) = await verify(signedInfoOctets!.AsReadOnlyMemory(), signature.SignatureValueOctets.AsReadOnlyMemory(), publicKeyMaterial, context: null, cancellationToken).ConfigureAwait(false);

                    return isVerified
                        ? new SignatureCryptographicVerification { Outcome = SignatureCryptographicOutcome.Verified, SigningCertificate = signingCertificate }
                        : Fail(SignatureCryptographicOutcome.SignatureValueFailure, "The ds:SignatureValue did not verify under signingCertificate's public key.");
                }
            }
        }
    }


    /// <summary>Extracts the compressed SEC1 point of <paramref name="certificate"/>'s own ECDSA public key, the exact wire form the house ECDSA verification seam consumes; <see langword="null"/> when it carries none.</summary>
    private static byte[]? ExtractEcdsaPublicKey(PkiCertificateMemory certificate)
    {
        using X509Certificate2 loaded = X509CertificateLoader.LoadCertificate(certificate.AsReadOnlySpan());
        using ECDsa? ecdsaPublicKey = loaded.GetECDsaPublicKey();
        if(ecdsaPublicKey is null)
        {
            return null;
        }

        ECParameters ecParameters = ecdsaPublicKey.ExportParameters(false);

        return EllipticCurveUtilities.Compress(ecParameters.Q.X!, ecParameters.Q.Y!);
    }


    private static SignatureCryptographicVerification Fail(SignatureCryptographicOutcome outcome, string reason) => new()
    {
        Outcome = outcome,
        Reason = reason
    };


    private static string Utf8(ReadOnlySpan<byte> value) => Encoding.UTF8.GetString(value);
}
