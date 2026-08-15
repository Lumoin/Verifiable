using System.Linq;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proves the <see cref="XmlSignatureWellKnown"/> signature-method mapping is
/// total over the nine family-and-digest combinations this library verifies plus the three URIs it
/// names-and-refuses, the house verification registry's own key-tag pairing agrees with that mapping for
/// every documented combination, the <see cref="XmlSignatureWellKnown.IsConsistentWithKey"/> predicate
/// passes for every documented pair, and the transform-identifier recognition this library added restates
/// <see cref="XmlSignatureIdentifiers"/>'s six transform identifiers byte-identically, in both directions,
/// as a real bijection with the Pki layer's own enumerated recognized set.
/// </summary>
[TestClass]
internal sealed class XmlSignatureWellKnownSignatureAlgorithmTests
{
    /// <summary>Every signature-method URI this library resolves, paired with the family and digest it must resolve to.</summary>
    private static (string AlgorithmUri, XmlSignatureAlgorithm Algorithm)[] SupportedUriToAlgorithm =>
    [
        (XmlSignatureWellKnown.RsaSha256SignatureUri, new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPkcs1, PkiDigestAlgorithm.Sha256)),
        (XmlSignatureWellKnown.RsaSha384SignatureUri, new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPkcs1, PkiDigestAlgorithm.Sha384)),
        (XmlSignatureWellKnown.RsaSha512SignatureUri, new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPkcs1, PkiDigestAlgorithm.Sha512)),
        (XmlSignatureWellKnown.EcdsaSha256SignatureUri, new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.Ecdsa, PkiDigestAlgorithm.Sha256)),
        (XmlSignatureWellKnown.EcdsaSha384SignatureUri, new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.Ecdsa, PkiDigestAlgorithm.Sha384)),
        (XmlSignatureWellKnown.EcdsaSha512SignatureUri, new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.Ecdsa, PkiDigestAlgorithm.Sha512)),
        (XmlSignatureWellKnown.RsaPssSha256SignatureUri, new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPss, PkiDigestAlgorithm.Sha256)),
        (XmlSignatureWellKnown.RsaPssSha384SignatureUri, new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPss, PkiDigestAlgorithm.Sha384)),
        (XmlSignatureWellKnown.RsaPssSha512SignatureUri, new XmlSignatureAlgorithm(XmlSignatureAlgorithmFamily.RsaPss, PkiDigestAlgorithm.Sha512))
    ];

    /// <summary>
    /// Every supported URI, paired with the house verification <see cref="Tag"/> that is consistent with it —
    /// the exact <see cref="CryptoTags"/> members <see cref="XmlSignatureWellKnown.SignatureAlgorithmFromUri"/>
    /// used to resolve to before this library decoupled the URI mapping from the key.
    /// </summary>
    private static (string AlgorithmUri, Tag KeyTag)[] SupportedUriToConsistentKeyTag =>
    [
        (XmlSignatureWellKnown.RsaSha256SignatureUri, CryptoTags.RsaSha256Pkcs1Signature),
        (XmlSignatureWellKnown.RsaSha384SignatureUri, CryptoTags.RsaSha384Pkcs1Signature),
        (XmlSignatureWellKnown.RsaSha512SignatureUri, CryptoTags.RsaSha512Pkcs1Signature),
        (XmlSignatureWellKnown.EcdsaSha256SignatureUri, CryptoTags.P256Signature),
        (XmlSignatureWellKnown.EcdsaSha384SignatureUri, CryptoTags.P384Signature),
        (XmlSignatureWellKnown.EcdsaSha512SignatureUri, CryptoTags.P521Signature),
        (XmlSignatureWellKnown.RsaPssSha256SignatureUri, CryptoTags.RsaSha256PssSignature),
        (XmlSignatureWellKnown.RsaPssSha384SignatureUri, CryptoTags.RsaSha384PssSignature),
        (XmlSignatureWellKnown.RsaPssSha512SignatureUri, CryptoTags.RsaSha512PssSignature)
    ];

    /// <summary>Every named-and-refused signature-method URI.</summary>
    private static string[] RefusedUris =>
    [
        XmlSignatureWellKnown.RsaSha1SignatureUri,
        XmlSignatureWellKnown.DsaSha1SignatureUri,
        XmlSignatureWellKnown.HmacSha1SignatureUri
    ];

    /// <summary>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc4051#section-2.3.2">IETF RFC 4051 clause 2.3.2</see>
    /// through 2.3.4 and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9231#section-2.3.6">IETF RFC 9231 clause 2.3.6</see> and
    /// 2.3.10 as totality: every URI <see cref="XmlSignatureWellKnown.SignatureAlgorithmFromUri"/> is
    /// documented to resolve does resolve, to the exact family and digest named, and no two resolve to the
    /// same family/digest pair.
    /// </summary>
    [TestMethod]
    public void SignatureAlgorithmFromUriResolvesEveryDocumentedUriToItsOwnFamilyAndDigest()
    {
        foreach((string uri, XmlSignatureAlgorithm expected) in SupportedUriToAlgorithm)
        {
            XmlSignatureAlgorithm? resolved = XmlSignatureWellKnown.SignatureAlgorithmFromUri(uri);
            Assert.IsNotNull(resolved, $"'{uri}' must resolve.");
            Assert.AreEqual(expected, resolved, $"'{uri}' must resolve to its documented family and digest.");
        }

        XmlSignatureAlgorithm[] distinctAlgorithms = [.. SupportedUriToAlgorithm.Select(pair => pair.Algorithm).Distinct()];
        Assert.HasCount(SupportedUriToAlgorithm.Length, distinctAlgorithms, "No two signature-method URIs may resolve to the same family and digest.");
    }


    /// <summary>
    /// Proves the key-side resolution agrees with the URI-side resolution for every documented pair: the
    /// house verification registry's own fixed curve/digest and RSA-digest pairing (<see
    /// cref="XmlSignatureWellKnown.SignatureAlgorithmFromKeyTag"/>) resolves each <see
    /// cref="SupportedUriToConsistentKeyTag"/> key tag to the SAME family and digest <see
    /// cref="XmlSignatureWellKnown.SignatureAlgorithmFromUri"/> resolves the paired URI to — the two
    /// resolution paths name the same family/digest pairs <see
    /// href="https://www.rfc-editor.org/rfc/rfc9231#section-2.3.6">IETF RFC 9231 clause 2.3.6</see> and
    /// 2.3.10 define, so a key-driven dispatch can never disagree with what the wire URI itself states.
    /// </summary>
    [TestMethod]
    public void SignatureAlgorithmFromKeyTagAgreesWithSignatureAlgorithmFromUriForConsistentPairs()
    {
        foreach((string uri, Tag keyTag) in SupportedUriToConsistentKeyTag)
        {
            XmlSignatureAlgorithm? fromUri = XmlSignatureWellKnown.SignatureAlgorithmFromUri(uri);
            XmlSignatureAlgorithm? fromKey = XmlSignatureWellKnown.SignatureAlgorithmFromKeyTag(keyTag);
            Assert.IsNotNull(fromKey, $"The key tag paired with '{uri}' must resolve.");
            Assert.AreEqual(fromUri, fromKey, $"'{uri}' and its paired key tag must resolve to the same family and digest.");
        }
    }


    /// <summary>
    /// Proves the consistency predicate PASSES for every documented URI/key-tag pair — the positive half of
    /// the predicate contract the interop oracle dispatches verification through, over the <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-AlgID">XML Signature clause
    /// 6.1</see> algorithm identifiers this type resolves.
    /// </summary>
    [TestMethod]
    public void IsConsistentWithKeyPassesForEveryDocumentedPair()
    {
        foreach((string uri, Tag keyTag) in SupportedUriToConsistentKeyTag)
        {
            Assert.IsTrue(XmlSignatureWellKnown.IsConsistentWithKey(uri, keyTag), $"'{uri}' must be consistent with its paired key tag.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-AlgID">XML Signature
    /// clause 6.1</see>'s "Required"/"Recommended" DSAwithSHA1/HMAC-SHA1/RSA-SHA1 are named-and-refused
    /// rather than silently absorbed: each is recognised by <see cref="XmlSignatureWellKnown.IsRefusedSignatureUri"/>
    /// and resolves to no family/digest through <see cref="XmlSignatureWellKnown.SignatureAlgorithmFromUri"/>.
    /// </summary>
    [TestMethod]
    public void RefusedSignatureUrisResolveToNoAlgorithmAndAreNamedRefused()
    {
        foreach(string uri in RefusedUris)
        {
            Assert.IsTrue(XmlSignatureWellKnown.IsRefusedSignatureUri(uri), $"'{uri}' must be a named-and-refused signature-method URI.");
            Assert.IsNull(XmlSignatureWellKnown.SignatureAlgorithmFromUri(uri), $"'{uri}' must not resolve to a family and digest.");
            Assert.IsFalse(XmlSignatureWellKnown.IsSupportedSignatureUri(uri), $"'{uri}' must not report as supported.");
        }
    }


    /// <summary>
    /// Proves <see cref="XmlSignatureWellKnown.IsSupportedSignatureUri"/> agrees with
    /// <see cref="XmlSignatureWellKnown.SignatureAlgorithmFromUri"/> over the whole supported set, and that
    /// an unrecognised URI is neither supported nor refused — totality over
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-AlgID">XML Signature clause
    /// 6.1</see>'s algorithm-identifier space: every URI this type names is either supported or refused,
    /// never both and never silently absorbed.
    /// </summary>
    [TestMethod]
    public void IsSupportedSignatureUriAgreesWithTheResolvedSet()
    {
        foreach((string uri, _) in SupportedUriToAlgorithm)
        {
            Assert.IsTrue(XmlSignatureWellKnown.IsSupportedSignatureUri(uri), $"'{uri}' must report as supported.");
            Assert.IsFalse(XmlSignatureWellKnown.IsRefusedSignatureUri(uri), $"'{uri}' must not be named-and-refused.");
        }

        const string unrecognized = "urn:example:not-a-signature-method";
        Assert.IsFalse(XmlSignatureWellKnown.IsSupportedSignatureUri(unrecognized));
        Assert.IsFalse(XmlSignatureWellKnown.IsRefusedSignatureUri(unrecognized));
        Assert.IsNull(XmlSignatureWellKnown.SignatureAlgorithmFromUri(unrecognized));
    }


    /// <summary>
    /// Every transform identifier this type states, paired between the Pki layer's own member and the
    /// leaf's identically-named member — the fixture <see cref="TransformIdentifiersFormABijectionWithTheRecognizedSetAndTheLeaf"/>
    /// and <see cref="AllTransformUrisAreRecognizedAndTheRecognizedCountMatchesTheList"/> both draw on.
    /// </summary>
    private static (string Pki, string Leaf)[] TransformIdentifierPairs =>
    [
        (XmlSignatureWellKnown.EnvelopedSignatureTransformUri, XmlSignatureIdentifiers.EnvelopedSignatureTransformUri),
        (XmlSignatureWellKnown.Base64TransformUri, XmlSignatureIdentifiers.Base64TransformUri),
        (XmlSignatureWellKnown.XPathTransformUri, XmlSignatureIdentifiers.XPathTransformUri),
        (XmlSignatureWellKnown.XsltTransformUri, XmlSignatureIdentifiers.XsltTransformUri),
        (XmlSignatureWellKnown.XPathFilter2TransformUri, XmlSignatureIdentifiers.XPathFilter2TransformUri),
        (XmlSignatureWellKnown.RelationshipTransformUri, XmlSignatureIdentifiers.RelationshipTransformUri)
    ];


    /// <summary>
    /// Proves the transform-URI restatement is a REAL bijection with <see
    /// cref="XmlSignatureWellKnown.AllTransformUris"/> — not merely that this type's six URIs happen to be
    /// byte-identical to the leaf's identically-named members (a leaf-side addition without a matching
    /// addition here would not disturb that check), but that this type's stated pairing covers <see
    /// cref="XmlSignatureWellKnown.AllTransformUris"/> exactly, in either order, so a transform identifier
    /// added to either side alone, without the matching addition on the other, changes a cardinality or a
    /// set-membership this assertion catches. The six identifiers themselves are the <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-AlgID">XML Signature clause 6.1</see>
    /// transform algorithm identifiers this library recognizes.
    /// </summary>
    [TestMethod]
    public void TransformIdentifiersFormABijectionWithTheRecognizedSetAndTheLeaf()
    {
        (string Pki, string Leaf)[] pairs = TransformIdentifierPairs;

        foreach((string pki, string leaf) in pairs)
        {
            Assert.AreEqual(leaf, pki, $"'{pki}' (Pki) and '{leaf}' (leaf) must name the same transform identifier.");
            Assert.IsTrue(XmlSignatureWellKnown.IsRecognizedTransformUri(pki), $"'{pki}' must be a recognized transform identifier.");
        }

        string[] pkiSide = [.. pairs.Select(pair => pair.Pki)];
        Assert.AreSequenceEqual(XmlSignatureWellKnown.AllTransformUris, pkiSide, SequenceOrder.InAnyOrder,
            "This type's stated pairing must be exactly XmlSignatureWellKnown.AllTransformUris — a transform identifier added to either side alone, without the matching addition on the other, must change this comparison.");
    }


    /// <summary>
    /// Binds <see cref="XmlSignatureWellKnown.AllTransformUris"/> directly to
    /// <see cref="XmlSignatureWellKnown.IsRecognizedTransformUri"/>, independent of the fixture pairing
    /// <see cref="TransformIdentifiersFormABijectionWithTheRecognizedSetAndTheLeaf"/> compares against: every
    /// listed URI is recognized, and the count the predicate recognizes over the union of the leaf-side and
    /// Pki-side transform constants equals the list's own count — a recognition arm added to
    /// <see cref="XmlSignatureWellKnown.IsRecognizedTransformUri"/> without a matching
    /// <see cref="XmlSignatureWellKnown.AllTransformUris"/> entry changes that count, per the
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-AlgID">XML Signature clause
    /// 6.1</see> algorithm-identifier totality this suite otherwise proves only through the hand-maintained
    /// fixture.
    /// </summary>
    [TestMethod]
    public void AllTransformUrisAreRecognizedAndTheRecognizedCountMatchesTheList()
    {
        foreach(string uri in XmlSignatureWellKnown.AllTransformUris)
        {
            Assert.IsTrue(XmlSignatureWellKnown.IsRecognizedTransformUri(uri), $"'{uri}' is listed in AllTransformUris and must be recognized.");
        }

        string[] unionOfBothSidesConstants =
        [
            .. TransformIdentifierPairs.Select(pair => pair.Pki).Concat(TransformIdentifierPairs.Select(pair => pair.Leaf)).Distinct()
        ];
        int recognizedCount = unionOfBothSidesConstants.Count(XmlSignatureWellKnown.IsRecognizedTransformUri);
        Assert.AreEqual(XmlSignatureWellKnown.AllTransformUris.Count, recognizedCount,
            "The predicate must recognize exactly as many candidates from the leaf/Pki union as AllTransformUris lists — a recognition arm added without the matching list entry changes this count.");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-AlgID">XML Signature
    /// clause 6.1</see>'s "the URI as written" rule at the transform-recognition seam: a near-miss identifier
    /// differing in case or trailing characters from every recognized one is not recognized.
    /// </summary>
    [TestMethod]
    public void NearMissTransformIdentifiersAreNotRecognized()
    {
        string[] nearMisses =
        [
            "http://www.w3.org/2000/09/xmldsig#Enveloped-Signature",
            "http://www.w3.org/2000/09/xmldsig#base64 ",
            "http://www.w3.org/2002/06/xmldsig-filter2/"
        ];

        foreach(string uri in nearMisses)
        {
            Assert.IsFalse(XmlSignatureWellKnown.IsRecognizedTransformUri(uri), $"'{uri}' must not be recognized.");
        }
    }
}
