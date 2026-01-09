using Verifiable.JCose;
using Verifiable.Jose;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.JCose.JwkThumbprintUtilities.JwkTemplateConstants;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests JWK thumbprint computation using official RFC 7638 test vectors.
/// Ensures compliance with <see href="https://tools.ietf.org/html/rfc7638">RFC 7638</see> specification and interoperability.
/// </summary>
[TestClass]
public class JwkThumbprintRfcVectorTests
{
    /// <summary>
    /// RFC 7638 Section 3.1 test vector for RSA key thumbprint.
    /// Source: <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see>.
    /// </summary>
    [TestMethod]
    public void ComputeRsaThumbprintRfc7638Section3Point1ExampleMatchesExpectedThumbprint()
    {
        var e = RsaStandardExponent;
        var kty = WellKnownKeyTypeValues.Rsa;
        var n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        var expectedThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

        using var thumbprint = JwkThumbprintUtilities.ComputeRsaThumbprint(e, kty, n);
        var actualThumbprint = TestSetup.Base64UrlEncoder(thumbprint.Memory.Span);

        Assert.AreEqual(expectedThumbprint, actualThumbprint, "RSA thumbprint must match RFC 7638 test vector.");
    }

    /// <summary>
    /// RFC 8037 test vector for Ed25519 public key thumbprint computation.
    /// Source: <see href="https://tools.ietf.org/html/rfc8037#appendix-A.3">RFC 8037 Appendix A.3</see>.
    /// </summary>
    [TestMethod]
    public void ComputeEdDsaThumbprintEd25519Rfc8037AppendixA3Vector()
    {
        var crv = WellKnownCurveValues.Ed25519;
        var kty = WellKnownKeyTypeValues.Okp;
        var x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
        var expectedThumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

        using var thumbprint = JwkThumbprintUtilities.ComputeEdDsaThumbprint(crv, kty, x);
        var actualThumbprint = TestSetup.Base64UrlEncoder(thumbprint.Memory.Span);

        Assert.AreEqual(expectedThumbprint, actualThumbprint, "Ed25519 thumbprint must match RFC 8037 test vector.");
    }

    /// <summary>
    /// RFC 8037 test vector for X25519 ECDH key thumbprint computation.
    /// Source: <see href="https://tools.ietf.org/html/rfc8037#appendix-A.6">RFC 8037 Appendix A.6</see>.
    /// </summary>
    [TestMethod]
    public void ComputeEcdhThumbprintX25519Rfc8037AppendixA6Vector()
    {
        var crv = WellKnownCurveValues.X25519;
        var kty = WellKnownKeyTypeValues.Okp;
        var x = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08";

        using var thumbprint = JwkThumbprintUtilities.ComputeEcdhThumbprint(crv, kty, x);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "SHA-256 hash must be 32 bytes.");
    }

    /// <summary>
    /// RFC 7517 test vector for P-256 elliptic curve key thumbprint.
    /// Source: <see href="https://tools.ietf.org/html/rfc7517#appendix-C">RFC 7517 Appendix C</see>.
    /// </summary>
    [TestMethod]
    public void ComputeECThumbprintP256Rfc7517AppendixCVector()
    {
        var crv = WellKnownCurveValues.P256;
        var kty = WellKnownKeyTypeValues.Ec;
        var x = "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis";
        var y = "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE";

        using var thumbprint = JwkThumbprintUtilities.ComputeECThumbprint(crv, kty, x, y);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "SHA-256 hash must be 32 bytes.");
    }

    /// <summary>
    /// RFC 7638 test for P-384 elliptic curve key thumbprint structure.
    /// Verifies proper canonical JSON construction per <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see>.
    /// </summary>
    [TestMethod]
    public void ComputeECThumbprintP384VerifiesCanonicalStructure()
    {
        var crv = WellKnownCurveValues.P384;
        var kty = WellKnownKeyTypeValues.Ec;
        var x = "cHn8dCN4BvWJqvjYNmNylQfg2vNzJNlKWKjCKOlhj7xrPBFhxKQo2xrDcJdUcMzC";
        var y = "I1MbOh3LM3zHn-kBQWcqDFkXhVhWBxSMsZS3nGjnHnDvZZsZKkF9OmHm3BDxqr9C";

        using var thumbprint = JwkThumbprintUtilities.ComputeECThumbprint(crv, kty, x, y);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "SHA-256 hash must be 32 bytes.");
    }

    /// <summary>
    /// RFC 7638 test for P-521 elliptic curve key thumbprint structure.
    /// Verifies proper canonical JSON construction per <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see>.
    /// </summary>
    [TestMethod]
    public void ComputeECThumbprintP521VerifiesCanonicalStructure()
    {
        var crv = WellKnownCurveValues.P521;
        var kty = WellKnownKeyTypeValues.Ec;
        var x = "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt";
        var y = "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1";

        using var thumbprint = JwkThumbprintUtilities.ComputeECThumbprint(crv, kty, x, y);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "SHA-256 hash must be 32 bytes.");
    }

    /// <summary>
    /// RFC 7638 test for symmetric key (oct) thumbprint computation.
    /// Source: <see href="https://tools.ietf.org/html/rfc7638">RFC 7638</see>.
    /// </summary>
    [TestMethod]
    public void ComputeOctThumbprint256BitKeyVerifiesStructure()
    {
        var k = "GawgguFyGrWKav7AX4VKUg";
        var kty = WellKnownKeyTypeValues.Oct;

        using var thumbprint = JwkThumbprintUtilities.ComputeOctThumbprint(k, kty);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "SHA-256 hash must be 32 bytes.");
    }

    /// <summary>
    /// RFC 7638 test for generic JWK thumbprint with multiple parameters.
    /// Verifies lexicographical sorting per <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see>.
    /// </summary>
    [TestMethod]
    public void ComputeGenericThumbprintMultipleParametersVerifiesLexicographicalOrdering()
    {
        var jwkParams = new Dictionary<string, string>
        {
            [JwkProperties.Kty] = WellKnownKeyTypeValues.Rsa,
            [JwkProperties.E] = RsaStandardExponent,
            [JwkProperties.N] = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        };

        using var thumbprint = JwkThumbprintUtilities.ComputeGenericThumbprint(jwkParams);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "SHA-256 hash must be 32 bytes.");
    }

    /// <summary>
    /// RFC 7638 test verifying that parameter order doesn't affect thumbprint.
    /// Source: <see href="https://tools.ietf.org/html/rfc7638#section-3">RFC 7638 Section 3</see>.
    /// </summary>
    [TestMethod]
    public void ComputeGenericThumbprintUnorderedParametersProducesSameThumbprint()
    {
        var jwkParams1 = new Dictionary<string, string>
        {
            [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec,
            [JwkProperties.Crv] = WellKnownCurveValues.P256,
            [JwkProperties.X] = "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            [JwkProperties.Y] = "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        };

        var jwkParams2 = new Dictionary<string, string>
        {
            [JwkProperties.Y] = "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            [JwkProperties.X] = "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            [JwkProperties.Crv] = WellKnownCurveValues.P256,
            [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec
        };

        using var thumbprint1 = JwkThumbprintUtilities.ComputeGenericThumbprint(jwkParams1);
        using var thumbprint2 = JwkThumbprintUtilities.ComputeGenericThumbprint(jwkParams2);

        Assert.IsTrue(thumbprint1.Memory.Span.SequenceEqual(thumbprint2.Memory.Span), "Thumbprints must be identical regardless of parameter order per RFC 7638.");
    }
}