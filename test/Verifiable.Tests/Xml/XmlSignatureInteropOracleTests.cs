using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// The interop oracle: every document <see cref="XmlSignatureInteropCorpusGenerator"/> mints is read, digested and cryptographically verified through this library's own stack — <see cref="XmlNodeTable.TryParse"/>,
/// <see cref="XmlSignatureLocator.FindSignatures"/>, <see cref="XmlSignature.TryRead"/>, <see cref="XmlReferenceProcessing.TryComputeDigestInput"/>, <see cref="XmlReferenceProcessing.TryComputeSignedInfoOctets"/>,
/// the house digest seam (<see
/// cref="CryptographicKeyEvents.ComputeDigestAsync(System.ReadOnlyMemory{byte},int,Tag,BaseMemoryPool,System.Collections.Frozen.FrozenDictionary{string,object}?,string?,System.Threading.CancellationToken)"/>) and
/// the house verification seam (<see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>) — against documents six of whose seven cases a REAL, independent platform signer (<see
/// cref="SignedXml.ComputeSignature"/>) produced, never this library's own writer: verification dispatches from each <see cref="XmlSignatureInteropCase.KeyTag"/> — the corpus generator's own record of
/// which algorithm signed — never from the document's <c>SignatureMethod</c> URI, and <see cref="XmlSignatureWellKnown.IsConsistentWithKey"/> is asserted to pass for every case before that dispatch.
/// </summary>
[TestClass]
internal sealed class XmlSignatureInteropOracleTests
{
    private static readonly IReadOnlyList<XmlSignatureInteropCase> Corpus = XmlSignatureInteropCorpusGenerator.Generate(BaseMemoryPool.Shared);


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2 (per-reference digesting), section 4.3.1
    /// (<c>SignedInfo</c> canonicalization) and section 3.2.1 (signature validation) end to end, over every
    /// corpus case: this library's own structural read, transform-chain digest computation and
    /// <c>SignedInfo</c> canonicalization reproduce exactly the octets a genuine signer committed to, and the
    /// house verification seam accepts the resulting <c>SignatureValue</c> against the key material the
    /// document's own <c>KeyInfo</c> — <c>X509Data</c> in five cases, <c>KeyValue</c> in one — carries.
    /// </summary>
    [TestMethod]
    public async Task EveryInteropCaseReadsDigestsAndVerifiesAsync()
    {
        foreach(XmlSignatureInteropCase testCase in Corpus)
        {
            await VerifyCaseAsync(testCase, BaseMemoryPool.Shared).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Proves the consistency predicate refuses BEFORE any verification dispatch is attempted: a P-384 key paired with the
    /// <c>ecdsa-sha256</c> <c>SignatureMethod</c> — a document naming the right family (ECDSA) but the wrong digest, a
    /// legal wire combination <see href="https://www.rfc-editor.org/rfc/rfc9231#section-2.3.6">IETF RFC 9231 clause
    /// 2.3.6</see> itself cannot rule out since the URI names only the hash — and an RSA key paired with the same URI, a
    /// family mismatch outright, are both refused by <see cref="XmlSignatureWellKnown.IsConsistentWithKey"/> without
    /// either reaching <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.ResolveVerification"/>.
    /// </summary>
    [TestMethod]
    public void MismatchedKeyAndUriRefuseConsistencyBeforeDispatch()
    {
        Assert.IsFalse(
            XmlSignatureWellKnown.IsConsistentWithKey(XmlSignatureWellKnown.EcdsaSha256SignatureUri, CryptoTags.P384Signature),
            "A P-384 key under the ecdsa-sha256 URI names the right family but the wrong digest and must not be consistent.");
        Assert.IsFalse(
            XmlSignatureWellKnown.IsConsistentWithKey(XmlSignatureWellKnown.EcdsaSha256SignatureUri, CryptoTags.RsaSha256Pkcs1Signature),
            "An RSA key under an ECDSA URI is a family mismatch and must not be consistent.");
    }


    /// <summary>
    /// Proves the reverse direction, restricted to "where the platform API admits it": for every corpus
    /// case whose <c>CanonicalizationMethod</c> the platform actually ships a transform for (<see
    /// cref="XmlSignatureInteropCase.IsPlatformVerifiable"/> — every case except the hand-assembled
    /// Canonical XML 1.1 one), a document THIS library's own engine independently digested, canonicalized
    /// and verified above is ALSO accepted by the platform's own, independent <see
    /// cref="SignedXml.LoadXml(System.Xml.XmlElement)"/>/<see cref="SignedXml.CheckSignature"/> — exercising
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 6.6.4's enveloped-signature transform, among the platform's own
    /// reference-processing pipeline, over the enveloped-shape cases.
    /// </summary>
    /// <remarks>
    /// Not a byte-exact octet comparison against a standalone <see cref="XmlDsigEnvelopedSignatureTransform"/>:
    /// that transform's <c>SignaturePosition</c>, which selects which <c>ds:Signature</c> occurrence to
    /// remove, is an <c>internal</c> property <see cref="SignedXml"/> alone sets while driving its own
    /// reference-processing pipeline (confirmed by reflection: no public API sets it) — used truly standalone,
    /// <see cref="XmlDsigEnvelopedSignatureTransform.GetOutput()"/> removes nothing at all and returns the
    /// document unchanged. The platform therefore exposes NO public API that yields the enveloped-signature
    /// transform's intermediate octets outside a full <see cref="SignedXml.CheckSignature()"/> run — this is
    /// the confirmed shape of "where the platform API admits it" for this transform specifically.
    /// </remarks>
    [TestMethod]
    public void PlatformCheckSignatureAcceptsEveryCaseThisLibraryIndependentlyVerified()
    {
        foreach(XmlSignatureInteropCase testCase in Corpus)
        {
            if(!testCase.IsPlatformVerifiable)
            {
                continue;
            }

            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null! };
            using(var stream = new MemoryStream(testCase.Document, writable: false))
            {
                using XmlReader reader = XmlReader.Create(stream, settings);
                document.Load(reader);
            }

            XmlElement signatureElement = (XmlElement)document.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#")[0]!;
            var platformSignedXml = new SignedXml(document);
            platformSignedXml.LoadXml(signatureElement);

            Assert.IsTrue(platformSignedXml.CheckSignature(), $"Case '{testCase.Name}': the platform's own CheckSignature() must accept this document.");
        }
    }


    /// <summary>Runs the full read/digest/verify pipeline of one corpus case.</summary>
    private static async Task VerifyCaseAsync(XmlSignatureInteropCase testCase, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(testCase.Document, pool, out XmlNodeTable? table, out XmlReadError parseError);
        Assert.IsTrue(isParsed, $"Case '{testCase.Name}' must parse: {parseError.Failure}.");
        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            Assert.HasCount(1, signatureIndices, $"Case '{testCase.Name}' must carry exactly one signature.");

            bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError readError);
            Assert.IsTrue(isRead, $"Case '{testCase.Name}' must read: {readError.Failure}.");
            using(signature)
            {
                for(int referenceOrdinal = 0; referenceOrdinal < signature!.SignedInfo.References.Count; ++referenceOrdinal)
                {
                    XmlReference reference = signature.SignedInfo.References[referenceOrdinal];
                    string digestMethodUri = Encoding.UTF8.GetString(reference.DigestMethodAlgorithm);
                    byte[] expectedDigest = reference.DigestValueOctets.AsReadOnlySpan().ToArray();

                    bool isDigested = XmlReferenceProcessing.TryComputeDigestInput(
                        table!, signature, referenceOrdinal, resolver: null, pool, out PooledMemory? digestInput, out XmlSignatureProcessingError digestError);
                    Assert.IsTrue(isDigested, $"Case '{testCase.Name}' reference {referenceOrdinal} must compute a digest input: {digestError.Failure}.");
                    using(digestInput)
                    {
                        PkiDigestAlgorithm? digestAlgorithm = XmlSignatureWellKnown.DigestAlgorithmFromUri(digestMethodUri);
                        Assert.IsNotNull(digestAlgorithm, $"Case '{testCase.Name}' reference {referenceOrdinal}: digest method '{digestMethodUri}' must resolve.");

                        using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
                            digestInput!.AsReadOnlyMemory(), digestAlgorithm.Value.OutputByteLength, digestAlgorithm.Value.DigestTag, pool).ConfigureAwait(false);

                        Assert.AreSequenceEqual(
                            expectedDigest, computed.AsReadOnlySpan().ToArray(),
                            $"Case '{testCase.Name}' reference {referenceOrdinal}: recomputed digest must match the document's own DigestValue.");
                    }
                }

                string signatureMethodUri = Encoding.UTF8.GetString(signature.SignedInfo.SignatureMethod.Algorithm);

                // The URI names only a family and digest, never a curve, so dispatch is resolved from the
                // KEY's own tag (this corpus case's own record of which algorithm signed), never from the
                // URI — and the two must agree before any dispatch is attempted.
                Assert.IsTrue(
                    XmlSignatureWellKnown.IsConsistentWithKey(signatureMethodUri, testCase.KeyTag),
                    $"Case '{testCase.Name}': signature method '{signatureMethodUri}' must be consistent with the minting key's own tag.");

                CryptoAlgorithm algorithm = testCase.KeyTag.Get<CryptoAlgorithm>();
                bool isEcdsa = algorithm.Equals(CryptoAlgorithm.P256) || algorithm.Equals(CryptoAlgorithm.P384) || algorithm.Equals(CryptoAlgorithm.P521);

                bool isSignedInfoComputed = XmlReferenceProcessing.TryComputeSignedInfoOctets(table!, signature, pool, out PooledMemory? signedInfoOctets, out XmlSignatureProcessingError signedInfoError);
                Assert.IsTrue(isSignedInfoComputed, $"Case '{testCase.Name}': SignedInfo octets must compute: {signedInfoError.Failure}.");
                using(signedInfoOctets)
                {
                    Assert.IsNotNull(signature.KeyInfo, $"Case '{testCase.Name}' must carry a KeyInfo.");
                    byte[] publicKeyMaterial = ExtractPublicKeyMaterial(signature.KeyInfo!.Value, isEcdsa);

                    VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, Purpose.Verification);
                    (bool isVerified, _) = await verify(signedInfoOctets!.AsReadOnlyMemory(), signature.SignatureValueOctets.AsReadOnlyMemory(), publicKeyMaterial).ConfigureAwait(false);

                    Assert.IsTrue(isVerified, $"Case '{testCase.Name}': SignatureValue must verify against the KeyInfo-derived public key.");
                }
            }
        }
    }


    /// <summary>
    /// Extracts DER PKCS#1 <c>RSAPublicKey</c> octets (RSA) or a compressed SEC1 point (ECDSA) from a
    /// structurally-read <c>KeyInfo</c>'s <c>X509Data</c> certificate or <c>KeyValue RSAKeyValue</c> — the
    /// exact wire forms the house verification seam consumes as <c>publicKeyMaterial</c>.
    /// </summary>
    private static byte[] ExtractPublicKeyMaterial(XmlKeyInfo keyInfo, bool isEcdsa)
    {
        foreach(XmlKeyInfoChild child in keyInfo.Children)
        {
            if(child.Kind == XmlKeyInfoChildKind.X509Data)
            {
                foreach(XmlX509DataMember member in child.X509DataMembers!)
                {
                    if(member.Kind != XmlX509DataMemberKind.Certificate)
                    {
                        continue;
                    }

                    byte[] certificateDer = member.DecodedOctets!.AsReadOnlySpan().ToArray();
                    using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(certificateDer);
                    if(isEcdsa)
                    {
                        using ECDsa ecdsaPublicKey = certificate.GetECDsaPublicKey()!;
                        ECParameters ecParameters = ecdsaPublicKey.ExportParameters(false);

                        return EllipticCurveUtilities.Compress(ecParameters.Q.X!, ecParameters.Q.Y!);
                    }

                    using RSA rsaPublicKey = certificate.GetRSAPublicKey()!;

                    return rsaPublicKey.ExportRSAPublicKey();
                }
            }

            if(child.Kind == XmlKeyInfoChildKind.KeyValue && child.KeyValue!.Value.Kind == XmlKeyValueKind.Rsa)
            {
                XmlRsaKeyValue rsaKeyValue = child.KeyValue.Value.Rsa!.Value;
                using RSA rsaPublicKey = RSA.Create();
                rsaPublicKey.ImportParameters(new RSAParameters
                {
                    Modulus = rsaKeyValue.Modulus.AsReadOnlySpan().ToArray(),
                    Exponent = rsaKeyValue.Exponent.AsReadOnlySpan().ToArray()
                });

                return rsaPublicKey.ExportRSAPublicKey();
            }
        }

        throw new InvalidOperationException("No recognized public-key-bearing KeyInfo child was found.");
    }
}
