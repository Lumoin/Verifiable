using System.Buffers.Text;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests that the judgement of a JWK's <c>x5c</c> (RFC 7517 section 4.7, <see cref="JwkCertificateChain.DefectOf"/>) tells a key
/// whose agreement with a certificate's key it does not compare from a key it compared and found to differ: a key of a type,
/// curve or algorithm the judgement compares no key of is refused as <see cref="JwkCertificateChainDefect.KeyComparisonUnsupported"/>,
/// a judgement not made, never as <see cref="JwkCertificateChainDefect.FirstCertificateNotOfTheKey"/>, an established mismatch.
/// </summary>
[TestClass]
internal sealed class JwkCertificateChainUnsupportedKeyTests
{
    /// <summary>
    /// A JWK of a type the judgement compares no key of - an X25519 or Ed448 OKP key, an <c>oct</c> key, a JWK naming no type, an
    /// EC key on a curve it names none of, an AKP key of an algorithm that is no ML-DSA parameter set - beside the certificate of
    /// an Ed25519 key is refused as a comparison not made; the control, an Ed25519 JWK of another key beside the same certificate,
    /// is an established mismatch.
    /// </summary>
    /// <param name="keyCase">The name of the JWK the row judges.</param>
    [TestMethod]
    [DataRow("x25519", DisplayName = "An X25519 OKP key")]
    [DataRow("ed448", DisplayName = "An Ed448 OKP key")]
    [DataRow("oct", DisplayName = "An oct key")]
    [DataRow("no-kty", DisplayName = "A JWK naming no key type")]
    [DataRow("unnamed-curve", DisplayName = "An EC key on a curve the judgement names none of")]
    [DataRow("unnamed-akp-algorithm", DisplayName = "An AKP key of no ML-DSA parameter set")]
    public void AKeyTheJudgementComparesNoneOfIsAComparisonNotMade(string keyCase)
    {
        var certificateKey = Enumerable.Range(0, 32).Select(static index => (byte)index).ToArray();
        var certificate = CertificateDerProducer.Base64(CertificateDerProducer.Ed25519Key(certificateKey));
        var x = Base64Url.EncodeToString(certificateKey);

        IReadOnlyDictionary<string, string> members = keyCase switch
        {
            "x25519" => new Dictionary<string, string>(StringComparer.Ordinal) { ["kty"] = "OKP", ["crv"] = "X25519", ["x"] = x },
            "ed448" => new Dictionary<string, string>(StringComparer.Ordinal) { ["kty"] = "OKP", ["crv"] = "Ed448", ["x"] = x },
            "oct" => new Dictionary<string, string>(StringComparer.Ordinal) { ["kty"] = "oct", ["k"] = x },
            "no-kty" => new Dictionary<string, string>(StringComparer.Ordinal) { ["crv"] = "Ed25519", ["x"] = x },
            "unnamed-curve" => new Dictionary<string, string>(StringComparer.Ordinal) { ["kty"] = "EC", ["crv"] = "P-999", ["x"] = x, ["y"] = x },
            "unnamed-akp-algorithm" => new Dictionary<string, string>(StringComparer.Ordinal) { ["kty"] = "AKP", ["alg"] = "SLH-DSA-SHA2-128s", ["pub"] = x },
            _ => throw new ArgumentOutOfRangeException(nameof(keyCase), keyCase, "No JWK is named so.")
        };

        var anotherEd25519Key = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["kty"] = "OKP",
            ["crv"] = "Ed25519",
            ["x"] = Base64Url.EncodeToString(new byte[32])
        };

        Assert.AreEqual(JwkCertificateChainDefect.KeyComparisonUnsupported, JwkCertificateChain.DefectOf([certificate], members), keyCase);
        Assert.AreEqual(JwkCertificateChainDefect.FirstCertificateNotOfTheKey, JwkCertificateChain.DefectOf([certificate], anotherEd25519Key), "The control: an Ed25519 key of another key is an established mismatch.");
    }
}
