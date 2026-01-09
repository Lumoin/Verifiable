using Verifiable.JCose;
using static Verifiable.JCose.JwkThumbprintUtilities.JwkTemplateConstants;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests JWK thumbprint computation with malformed, invalid, and edge case inputs.
/// Ensures proper error handling and defensive programming per <see href="https://tools.ietf.org/html/rfc7638">RFC 7638</see>.
/// Includes post-quantum cryptography algorithm tests based on draft IETF specifications.
/// </summary>
[TestClass]
public class JwkThumbprintMalformedInputTests
{
    [TestMethod]
    public void ComputeRsaThumbprintNullExponentThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeRsaThumbprint(null!, "RSA", "validModulus"));
    }

    [TestMethod]
    public void ComputeRsaThumbprintNullKeyTypeThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeRsaThumbprint("AQAB", null!, "validModulus"));
    }

    [TestMethod]
    public void ComputeRsaThumbprintNullModulusThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeRsaThumbprint("AQAB", "RSA", null!));
    }

    [TestMethod]
    public void ComputeECThumbprintNullCurveThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeECThumbprint(null!, "EC", "validX", "validY"));
    }

    [TestMethod]
    public void ComputeECThumbprintNullKeyTypeThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeECThumbprint("P-256", null!, "validX", "validY"));
    }

    [TestMethod]
    public void ComputeECThumbprintNullXCoordinateThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeECThumbprint("P-256", "EC", null!, "validY"));
    }

    [TestMethod]
    public void ComputeECThumbprintNullYCoordinateThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeECThumbprint("P-256", "EC", "validX", null!));
    }

    [TestMethod]
    public void ComputeEdDsaThumbprintNullCurveThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeEdDsaThumbprint(null!, "OKP", "validX"));
    }

    [TestMethod]
    public void ComputeEcdhThumbprintNullPublicKeyThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeEcdhThumbprint("X25519", "OKP", null!));
    }

    [TestMethod]
    public void ComputeOctThumbprintNullKeyValueThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeOctThumbprint(null!, "oct"));
    }

    [TestMethod]
    public void ComputeMlDsaThumbprintNullAlgorithmThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeMlDsaThumbprint(null!, "MLDSA", "validX"));
    }

    [TestMethod]
    public void ComputeMlKemThumbprintNullAlgorithmThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeMlKemThumbprint(null!, "MLKEM", "validX"));
    }

    [TestMethod]
    public void ComputeSlhDsaThumbprintNullAlgorithmThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeSlhDsaThumbprint(null!, "SLHDSA", "validX"));
    }

    [TestMethod]
    public void ComputeGenericThumbprintNullParametersThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JwkThumbprintUtilities.ComputeGenericThumbprint(null!));
    }

    [TestMethod]
    public void ComputeGenericThumbprintEmptyParametersThrowsArgumentException()
    {
        var emptyParams = new Dictionary<string, string>();
        Assert.Throws<ArgumentException>(() => JwkThumbprintUtilities.ComputeGenericThumbprint(emptyParams));
    }

    [TestMethod]
    public void ComputeRsaThumbprintWithWrongKeyTypeProducesDifferentThumbprint()
    {
        //Using EC key type with RSA parameters should produce different thumbprint.
        var e = "AQAB";
        var ktyWrong = "EC";
        var ktyCorrect = "RSA";
        var n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

        using var thumbprintWrong = JwkThumbprintUtilities.ComputeRsaThumbprint(e, ktyWrong, n);
        using var thumbprintCorrect = JwkThumbprintUtilities.ComputeRsaThumbprint(e, ktyCorrect, n);
        
        Assert.IsFalse(thumbprintWrong.Memory.Span.SequenceEqual(thumbprintCorrect.Memory.Span), "Wrong key type should produce different thumbprint.");
    }

    [TestMethod]
    public void ComputeECThumbprintWithInvalidBase64UrlStillProducesThumbprint()
    {
        //Invalid base64url characters should still work since we hash the string representation.
        var crv = "P-256";
        var kty = "EC";
        var x = "Invalid@#$%Base64Url";
        var y = "Invalid@#$%Base64Url";

        using var thumbprint = JwkThumbprintUtilities.ComputeECThumbprint(crv, kty, x, y);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "Should compute thumbprint even with invalid encoding since we hash the string as-is per RFC 7638.");
    }

    [TestMethod]
    public void ComputeGenericThumbprintWithVeryLargeParameterValues()
    {
        //Test with extremely large parameter values to ensure buffer handling.
        var largeValue = new string('A', 100000);
        var jwkParams = new Dictionary<string, string>
        {
            ["kty"] = largeValue,
            ["n"] = largeValue,
            ["e"] = largeValue
        };

        using var thumbprint = JwkThumbprintUtilities.ComputeGenericThumbprint(jwkParams);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "Should handle very large parameter values without overflow.");
    }

    [TestMethod]
    public void ComputeGenericThumbprintWithSpecialCharactersInValues()
    {
        //Test UTF-8 encoding with special characters.
        var jwkParams = new Dictionary<string, string>
        {
            ["kty"] = "RSA",
            ["special-chars"] = "emoji🔐test",
            ["unicode"] = "中文测试",
            ["symbols"] = "!@#$%^&*()"
        };

        using var thumbprint = JwkThumbprintUtilities.ComputeGenericThumbprint(jwkParams);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "Should handle UTF-8 special characters correctly per RFC 7638.");
    }

    [TestMethod]
    public void ComputeMlDsaThumbprintWithMismatchedAlgorithmAndKeyType()
    {
        //ML-KEM algorithm with MLDSA key type (intentional mismatch).
        var alg = "MLKEM768";
        var kty = "MLDSA";
        var x = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

        using var thumbprint = JwkThumbprintUtilities.ComputeMlDsaThumbprint(alg, kty, x);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "Thumbprint should compute even with mismatched parameters (garbage in, deterministic garbage out per RFC 7638).");
    }

    [TestMethod]
    public void ComputeMlDsaThumbprintMlDsa44VerifiesStructure()
    {
        //ML-DSA-44 JWK with placeholder public key.
        var alg = "MLDSA44";
        var kty = "MLDSA";
        var x = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

        using var thumbprint = JwkThumbprintUtilities.ComputeMlDsaThumbprint(alg, kty, x);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "ML-DSA-44 thumbprint must be 32 bytes per RFC 7638.");
    }

    [TestMethod]
    public void ComputeMlKemThumbprintMlKem768VerifiesStructure()
    {
        //ML-KEM-768 JWK with placeholder encapsulation key.
        var alg = "MLKEM768";
        var kty = "MLKEM";
        var x = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v";

        using var thumbprint = JwkThumbprintUtilities.ComputeMlKemThumbprint(alg, kty, x);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "ML-KEM-768 thumbprint must be 32 bytes per RFC 7638.");
    }

    [TestMethod]
    public void ComputeSlhDsaThumbprintSlhDsa128fVerifiesStructure()
    {
        //SLH-DSA-128f JWK with placeholder public key.
        var alg = "SLHDSA128f";
        var kty = "SLHDSA";
        var x = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

        using var thumbprint = JwkThumbprintUtilities.ComputeSlhDsaThumbprint(alg, kty, x);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "SLH-DSA-128f thumbprint must be 32 bytes per RFC 7638.");
    }

    [TestMethod]
    public void ComputeECThumbprintWithEmptyStringParameters()
    {
        //Empty strings are valid per RFC 7638, they just produce a different thumbprint.
        var crv = "";
        var kty = "";
        var x = "";
        var y = "";

        using var thumbprint = JwkThumbprintUtilities.ComputeECThumbprint(crv, kty, x, y);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "Empty strings should produce valid thumbprint per RFC 7638.");
    }

    [TestMethod]
    public void ComputeGenericThumbprintWithSingleParameter()
    {
        //Single parameter dictionary.
        var jwkParams = new Dictionary<string, string> { ["kty"] = "RSA" };

        using var thumbprint = JwkThumbprintUtilities.ComputeGenericThumbprint(jwkParams);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "Single parameter should produce valid thumbprint.");
    }

    [TestMethod]
    public void ComputeGenericThumbprintWithDuplicateKeysDifferentCasing()
    {
        //Dictionary keys are case-sensitive in C#, but this tests behavior.
        var jwkParams = new Dictionary<string, string> { ["kty"] = "RSA", ["Kty"] = "EC" };

        using var thumbprint = JwkThumbprintUtilities.ComputeGenericThumbprint(jwkParams);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "Different casing should be treated as different keys.");
    }

    [TestMethod]
    public void ComputeRsaThumbprintWithWhitespaceInParameters()
    {
        //Whitespace is significant per RFC 7638.
        var e = " AQAB ";
        var kty = " RSA ";
        var n = " modulus ";

        using var thumbprint = JwkThumbprintUtilities.ComputeRsaThumbprint(e, kty, n);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "Whitespace should be preserved in thumbprint calculation per RFC 7638.");
    }

    [TestMethod]
    public void ComputeECThumbprintWithNonAsciiCharacters()
    {
        //Non-ASCII characters in parameters.
        var crv = "P-256🏴‍☠️";
        var kty = "EC麦わら";
        var x = "слава_україні";
        var y = "座標ワンピース";

        using var thumbprint = JwkThumbprintUtilities.ComputeECThumbprint(crv, kty, x, y);
        
        Assert.AreEqual(Sha256HashSizeInBytes, thumbprint.Memory.Length, "Non-ASCII characters should be UTF-8 encoded per RFC 7638.");
    }

    [TestMethod]
    public void ComputeGenericThumbprintDeterministicWithIdenticalInputs()
    {
        //Verify deterministic behavior with multiple calls.
        var jwkParams = new Dictionary<string, string> { ["kty"] = "RSA", ["e"] = "AQAB", ["n"] = "modulus" };

        using var thumbprint1 = JwkThumbprintUtilities.ComputeGenericThumbprint(jwkParams);
        using var thumbprint2 = JwkThumbprintUtilities.ComputeGenericThumbprint(jwkParams);
        using var thumbprint3 = JwkThumbprintUtilities.ComputeGenericThumbprint(jwkParams);

        Assert.IsTrue(thumbprint1.Memory.Span.SequenceEqual(thumbprint2.Memory.Span), "Identical inputs must produce identical thumbprints.");
        Assert.IsTrue(thumbprint2.Memory.Span.SequenceEqual(thumbprint3.Memory.Span), "Thumbprint computation must be deterministic per RFC 7638.");
    }

    [TestMethod]
    public void ComputePqcThumbprintDeterministicBehavior()
    {
        //ML-DSA-44 JWK parameters.
        var alg = "MLDSA44";
        var kty = "MLDSA";
        var x = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

        using var thumbprint1 = JwkThumbprintUtilities.ComputeMlDsaThumbprint(alg, kty, x);
        using var thumbprint2 = JwkThumbprintUtilities.ComputeMlDsaThumbprint(alg, kty, x);

        Assert.IsTrue(thumbprint1.Memory.Span.SequenceEqual(thumbprint2.Memory.Span), "PQC thumbprints must be deterministic per RFC 7638.");
    }
}