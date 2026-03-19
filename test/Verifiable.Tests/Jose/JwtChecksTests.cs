using System;
using System.Collections.Generic;
using Microsoft.Extensions.Time.Testing;
using Verifiable.JCose;

namespace Verifiable.Tests.Jose;

[TestClass]
internal sealed class JwtChecksTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();


    //IsAlgNone — JwtHeader.

    [TestMethod]
    public void IsAlgNoneReturnsTrueWhenAlgHeaderIsAbsent()
    {
        var header = new JwtHeader();

        Assert.IsTrue(header.IsAlgNone(),
            "A header without an alg parameter must be treated as alg=none.");
    }

    [TestMethod]
    public void IsAlgNoneReturnsTrueWhenAlgIsNoneString()
    {
        var header = new JwtHeader { [WellKnownJwkValues.Alg] = WellKnownJwaValues.None };

        Assert.IsTrue(header.IsAlgNone(),
            "A header with alg=none must be identified as unsafe.");
    }

    [TestMethod]
    public void IsAlgNoneReturnsFalseForValidAlgorithm()
    {
        var header = new JwtHeader { [WellKnownJwkValues.Alg] = WellKnownJwaValues.Es256 };

        Assert.IsFalse(header.IsAlgNone(),
            "A header with a valid signing algorithm must not be flagged as alg=none.");
    }


    //IsAlgNone — UnverifiedJwtHeader.

    [TestMethod]
    public void IsAlgNoneOnUnverifiedReturnsTrueWhenAlgAbsent()
    {
        var header = new UnverifiedJwtHeader();

        Assert.IsTrue(header.IsAlgNone(),
            "An unverified header without alg must be treated as alg=none.");
    }

    [TestMethod]
    public void IsAlgNoneOnUnverifiedReturnsTrueWhenAlgIsNone()
    {
        var header = new UnverifiedJwtHeader { [WellKnownJwkValues.Alg] = WellKnownJwaValues.None };

        Assert.IsTrue(header.IsAlgNone());
    }

    [TestMethod]
    public void IsAlgNoneOnUnverifiedReturnsFalseForValidAlgorithm()
    {
        var header = new UnverifiedJwtHeader { [WellKnownJwkValues.Alg] = WellKnownJwaValues.Es256 };

        Assert.IsFalse(header.IsAlgNone());
    }


    //HasValidAlg.

    [TestMethod]
    public void HasValidAlgReturnsTrueForEs256()
    {
        var header = new JwtHeader { [WellKnownJwkValues.Alg] = WellKnownJwaValues.Es256 };

        Assert.IsTrue(header.HasValidAlg());
    }

    [TestMethod]
    public void HasValidAlgReturnsFalseWhenAlgAbsent()
    {
        var header = new JwtHeader();

        Assert.IsFalse(header.HasValidAlg(),
            "A header without alg does not have a valid algorithm.");
    }

    [TestMethod]
    public void HasValidAlgReturnsFalseWhenAlgIsNone()
    {
        var header = new JwtHeader { [WellKnownJwkValues.Alg] = WellKnownJwaValues.None };

        Assert.IsFalse(header.HasValidAlg(),
            "alg=none is not a valid signing algorithm.");
    }


    //HasKty.

    [TestMethod]
    public void HasKtyReturnsTrueWhenKtyPresent()
    {
        var header = new JwtHeader { [WellKnownJwkValues.Kty] = WellKnownKeyTypeValues.Ec };

        Assert.IsTrue(header.HasKty());
    }

    [TestMethod]
    public void HasKtyReturnsFalseWhenKtyAbsent()
    {
        var header = new JwtHeader();

        Assert.IsFalse(header.HasKty());
    }

    [TestMethod]
    public void HasKtyReturnsFalseWhenKtyIsEmptyString()
    {
        var header = new JwtHeader { [WellKnownJwkValues.Kty] = string.Empty };

        Assert.IsFalse(header.HasKty(),
            "An empty kty value is not a valid key type.");
    }


    //HasRequiredEcFields.

    [TestMethod]
    public void HasRequiredEcFieldsReturnsTrueWhenAllEcFieldsPresent()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.Kty] = WellKnownKeyTypeValues.Ec,
            [WellKnownJwkValues.Crv] = WellKnownCurveValues.P256,
            [WellKnownJwkValues.X] = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            [WellKnownJwkValues.Y] = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        };

        Assert.IsTrue(header.HasRequiredEcFields());
    }

    [TestMethod]
    public void HasRequiredEcFieldsReturnsFalseWhenCrvMissing()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.Kty] = WellKnownKeyTypeValues.Ec,
            [WellKnownJwkValues.X] = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            [WellKnownJwkValues.Y] = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        };

        Assert.IsFalse(header.HasRequiredEcFields(),
            "EC key without crv is missing a mandatory field.");
    }

    [TestMethod]
    public void HasRequiredEcFieldsReturnsFalseWhenXCoordinateMissing()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.Kty] = WellKnownKeyTypeValues.Ec,
            [WellKnownJwkValues.Crv] = WellKnownCurveValues.P256,
            [WellKnownJwkValues.Y] = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        };

        Assert.IsFalse(header.HasRequiredEcFields(),
            "EC key without x coordinate is missing a mandatory field.");
    }

    [TestMethod]
    public void HasRequiredEcFieldsReturnsFalseWhenYCoordinateMissing()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.Kty] = WellKnownKeyTypeValues.Ec,
            [WellKnownJwkValues.Crv] = WellKnownCurveValues.P256,
            [WellKnownJwkValues.X] = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
        };

        Assert.IsFalse(header.HasRequiredEcFields(),
            "EC key without y coordinate is missing a mandatory field.");
    }


    //IsValidEcAlgCrvCombination.

    [TestMethod]
    public void IsValidEcAlgCrvCombinationReturnsTrueForEs256AndP256()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.Alg] = WellKnownJwaValues.Es256,
            [WellKnownJwkValues.Crv] = WellKnownCurveValues.P256
        };

        Assert.IsTrue(header.IsValidEcAlgCrvCombination());
    }

    [TestMethod]
    public void IsValidEcAlgCrvCombinationReturnsTrueForEs384AndP384()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.Alg] = WellKnownJwaValues.Es384,
            [WellKnownJwkValues.Crv] = WellKnownCurveValues.P384
        };

        Assert.IsTrue(header.IsValidEcAlgCrvCombination());
    }

    [TestMethod]
    public void IsValidEcAlgCrvCombinationReturnsTrueForEs512AndP521()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.Alg] = WellKnownJwaValues.Es512,
            [WellKnownJwkValues.Crv] = WellKnownCurveValues.P521
        };

        Assert.IsTrue(header.IsValidEcAlgCrvCombination());
    }

    [TestMethod]
    public void IsValidEcAlgCrvCombinationReturnsFalseForMismatchedAlgAndCrv()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.Alg] = WellKnownJwaValues.Es256,
            [WellKnownJwkValues.Crv] = WellKnownCurveValues.P384
        };

        Assert.IsFalse(header.IsValidEcAlgCrvCombination(),
            "ES256 paired with P-384 is an invalid combination.");
    }

    [TestMethod]
    public void IsValidEcAlgCrvCombinationReturnsFalseWhenAlgAbsent()
    {
        var header = new JwtHeader { [WellKnownJwkValues.Crv] = WellKnownCurveValues.P256 };

        Assert.IsFalse(header.IsValidEcAlgCrvCombination(),
            "An EC header without alg cannot have a valid alg/crv combination.");
    }


    //OKP checks.

    [TestMethod]
    public void HasRequiredOkpFieldsReturnsTrueWhenCrvPresent()
    {
        var header = new JwtHeader { [WellKnownJwkValues.Crv] = WellKnownCurveValues.Ed25519 };

        Assert.IsTrue(header.HasRequiredOkpFields());
    }

    [TestMethod]
    public void HasRequiredOkpFieldsReturnsFalseWhenCrvAbsent()
    {
        var header = new JwtHeader { [WellKnownJwkValues.Kty] = WellKnownKeyTypeValues.Okp };

        Assert.IsFalse(header.HasRequiredOkpFields(),
            "OKP key without crv is missing the mandatory curve field.");
    }

    [TestMethod]
    public void IsValidOkpAlgCrvCombinationReturnsTrueForEdDsaAndEd25519()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.Alg] = WellKnownJwaValues.EdDsa,
            [WellKnownJwkValues.Crv] = WellKnownCurveValues.Ed25519
        };

        Assert.IsTrue(header.IsValidOkpAlgCrvCombination());
    }

    [TestMethod]
    public void IsValidOkpAlgCrvCombinationReturnsTrueForX25519WithNoAlg()
    {
        var header = new JwtHeader { [WellKnownJwkValues.Crv] = WellKnownCurveValues.X25519 };

        Assert.IsTrue(header.IsValidOkpAlgCrvCombination(),
            "X25519 is a key agreement curve and must not carry an alg — absent alg is correct.");
    }

    [TestMethod]
    public void IsValidOkpAlgCrvCombinationReturnsFalseWhenX25519HasAlg()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.Alg] = WellKnownJwaValues.EdDsa,
            [WellKnownJwkValues.Crv] = WellKnownCurveValues.X25519
        };

        Assert.IsFalse(header.IsValidOkpAlgCrvCombination(),
            "X25519 must not carry an alg header — it is a key agreement curve, not a signing curve.");
    }


    //HasValidRsaFields.

    [TestMethod]
    public void HasValidRsaFieldsReturnsTrueForRsa2048ModulusLength()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.E] = "AQAB",
            [WellKnownJwkValues.N] = new string('A', 342)
        };

        Assert.IsTrue(header.HasValidRsaFields(),
            "An RSA header with exponent and a 2048-bit modulus (342 Base64Url chars) must be valid.");
    }

    [TestMethod]
    public void HasValidRsaFieldsReturnsTrueForRsa4096ModulusLength()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.E] = "AQAB",
            [WellKnownJwkValues.N] = new string('A', 683)
        };

        Assert.IsTrue(header.HasValidRsaFields(),
            "An RSA header with a 4096-bit modulus (683 Base64Url chars) must be valid.");
    }

    [TestMethod]
    public void HasValidRsaFieldsReturnsFalseWhenExponentMissing()
    {
        var header = new JwtHeader { [WellKnownJwkValues.N] = new string('A', 342) };

        Assert.IsFalse(header.HasValidRsaFields(),
            "RSA key without exponent e is invalid.");
    }

    [TestMethod]
    public void HasValidRsaFieldsReturnsFalseWhenModulusLengthIsWrong()
    {
        var header = new JwtHeader
        {
            [WellKnownJwkValues.E] = "AQAB",
            [WellKnownJwkValues.N] = new string('A', 100)
        };

        Assert.IsFalse(header.HasValidRsaFields(),
            "A modulus that is neither 2048-bit nor 4096-bit length must be rejected.");
    }


    //Trust boundary — same input, same result on both types.

    [TestMethod]
    public void TrustBoundaryIsStructuralAlgNoneProducesSameResultOnBothTypes()
    {
        string alg = WellKnownJwaValues.None;
        var trusted = new JwtHeader { [WellKnownJwkValues.Alg] = alg };
        var untrusted = new UnverifiedJwtHeader { [WellKnownJwkValues.Alg] = alg };

        Assert.AreEqual(trusted.IsAlgNone(), untrusted.IsAlgNone(),
            "The trust boundary is structural only — the check result must be identical for the same input.");
    }

    [TestMethod]
    public void TrustBoundaryIsStructuralEcFieldsProducesSameResultOnBothTypes()
    {
        var trusted = new JwtHeader
        {
            [WellKnownJwkValues.Crv] = WellKnownCurveValues.P256,
            [WellKnownJwkValues.X] = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            [WellKnownJwkValues.Y] = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        };
        var untrusted = new UnverifiedJwtHeader(trusted);

        Assert.AreEqual(trusted.HasRequiredEcFields(), untrusted.HasRequiredEcFields(),
            "The trust boundary is structural only — the check result must be identical for the same input.");
    }


    //Time checks — JwtPayload.

    [TestMethod]
    public void IsExpiredReturnsFalseWhenTokenNotYetExpired()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var payload = new JwtPayload
        {
            [WellKnownJwkValues.Exp] = (long)(now.AddMinutes(5).ToUnixTimeSeconds())
        };

        Assert.IsFalse(payload.IsExpired(now, TimeSpan.Zero),
            "A token expiring five minutes from now must not be considered expired.");
    }

    [TestMethod]
    public void IsExpiredReturnsTrueWhenTokenHasExpired()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var payload = new JwtPayload
        {
            [WellKnownJwkValues.Exp] = (long)(now.AddMinutes(-1).ToUnixTimeSeconds())
        };

        Assert.IsTrue(payload.IsExpired(now, TimeSpan.Zero),
            "A token whose exp is in the past must be considered expired.");
    }

    [TestMethod]
    public void IsExpiredReturnsFalseWhenExpAbsent()
    {
        var payload = new JwtPayload();
        DateTimeOffset now = TimeProvider.GetUtcNow();

        Assert.IsFalse(payload.IsExpired(now, TimeSpan.Zero),
            "A token without an exp claim is treated as non-expiring.");
    }

    [TestMethod]
    public void IsExpiredRespectClockSkewAllowance()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var payload = new JwtPayload
        {
            [WellKnownJwkValues.Exp] = (long)(now.AddSeconds(-30).ToUnixTimeSeconds())
        };

        Assert.IsFalse(payload.IsExpired(now, TimeSpan.FromSeconds(60)),
            "A token expired 30 seconds ago must be accepted within a 60-second clock skew window.");
    }

    [TestMethod]
    public void IsNotYetValidReturnsTrueWhenNbfIsInFuture()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var payload = new JwtPayload
        {
            [WellKnownJwkValues.Nbf] = (long)(now.AddMinutes(5).ToUnixTimeSeconds())
        };

        Assert.IsTrue(payload.IsNotYetValid(now, TimeSpan.Zero),
            "A token whose nbf is five minutes in the future must not yet be valid.");
    }

    [TestMethod]
    public void IsNotYetValidReturnsFalseWhenNbfIsPast()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var payload = new JwtPayload
        {
            [WellKnownJwkValues.Nbf] = (long)(now.AddMinutes(-1).ToUnixTimeSeconds())
        };

        Assert.IsFalse(payload.IsNotYetValid(now, TimeSpan.Zero),
            "A token whose nbf is in the past is already valid.");
    }

    [TestMethod]
    public void IsNotYetValidReturnsFalseWhenNbfAbsent()
    {
        var payload = new JwtPayload();
        DateTimeOffset now = TimeProvider.GetUtcNow();

        Assert.IsFalse(payload.IsNotYetValid(now, TimeSpan.Zero),
            "A token without nbf has no not-before constraint.");
    }

    [TestMethod]
    public void IsIssuedInFutureReturnsTrueWhenIatIsInFuture()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var payload = new JwtPayload
        {
            [WellKnownJwkValues.Iat] = (long)(now.AddMinutes(5).ToUnixTimeSeconds())
        };

        Assert.IsTrue(payload.IsIssuedInFuture(now, TimeSpan.Zero),
            "A token claiming to have been issued five minutes in the future is anomalous.");
    }

    [TestMethod]
    public void IsIssuedInFutureReturnsFalseWhenIatIsNow()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var payload = new JwtPayload
        {
            [WellKnownJwkValues.Iat] = (long)now.ToUnixTimeSeconds()
        };

        Assert.IsFalse(payload.IsIssuedInFuture(now, TimeSpan.Zero));
    }

    [TestMethod]
    public void LifetimeExceedsReturnsTrueWhenExpMinusNbfExceedsMaximum()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var payload = new JwtPayload
        {
            [WellKnownJwkValues.Nbf] = (long)now.ToUnixTimeSeconds(),
            [WellKnownJwkValues.Exp] = (long)now.AddSeconds(120).ToUnixTimeSeconds()
        };

        Assert.IsTrue(payload.LifetimeExceeds(TimeSpan.FromSeconds(60)),
            "A token with a 120-second lifetime must exceed a 60-second maximum.");
    }

    [TestMethod]
    public void LifetimeExceedsReturnsFalseWhenExpMinusNbfIsWithinMaximum()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var payload = new JwtPayload
        {
            [WellKnownJwkValues.Nbf] = (long)now.ToUnixTimeSeconds(),
            [WellKnownJwkValues.Exp] = (long)now.AddSeconds(60).ToUnixTimeSeconds()
        };

        Assert.IsFalse(payload.LifetimeExceeds(TimeSpan.FromSeconds(60)),
            "A token whose lifetime equals the maximum must not exceed it.");
    }

    [TestMethod]
    public void LifetimeExceedsFallsBackToIatWhenNbfAbsent()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var payload = new JwtPayload
        {
            [WellKnownJwkValues.Iat] = (long)now.ToUnixTimeSeconds(),
            [WellKnownJwkValues.Exp] = (long)now.AddSeconds(120).ToUnixTimeSeconds()
        };

        Assert.IsTrue(payload.LifetimeExceeds(TimeSpan.FromSeconds(60)),
            "When nbf is absent, iat must be used as the validity window start.");
    }

    [TestMethod]
    public void IsExpBeforeNbfReturnsTrueWhenExpIsBeforeNbf()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var payload = new JwtPayload
        {
            [WellKnownJwkValues.Nbf] = (long)now.AddSeconds(60).ToUnixTimeSeconds(),
            [WellKnownJwkValues.Exp] = (long)now.ToUnixTimeSeconds()
        };

        Assert.IsTrue(payload.IsExpBeforeNbf(),
            "A token that expires before it becomes valid is malformed.");
    }

    [TestMethod]
    public void IsExpBeforeNbfReturnsFalseWhenExpIsAfterNbf()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var payload = new JwtPayload
        {
            [WellKnownJwkValues.Nbf] = (long)now.ToUnixTimeSeconds(),
            [WellKnownJwkValues.Exp] = (long)now.AddSeconds(60).ToUnixTimeSeconds()
        };

        Assert.IsFalse(payload.IsExpBeforeNbf(),
            "A well-formed token with exp after nbf must not be flagged as malformed.");
    }


    //Time checks — UnverifiedJwtPayload produces identical results.

    [TestMethod]
    public void TrustBoundaryIsStructuralTimeChecksProduceSameResultOnBothPayloadTypes()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        long expSeconds = now.AddMinutes(-1).ToUnixTimeSeconds();

        var trusted = new JwtPayload { [WellKnownJwkValues.Exp] = expSeconds };
        var untrusted = new UnverifiedJwtPayload { [WellKnownJwkValues.Exp] = expSeconds };

        Assert.AreEqual(
            trusted.IsExpired(now, TimeSpan.Zero),
            untrusted.IsExpired(now, TimeSpan.Zero),
            "The trust boundary is structural only — time check results must be identical for the same input.");
    }
}