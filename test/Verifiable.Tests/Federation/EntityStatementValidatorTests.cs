using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Opening invariants for <see cref="EntityStatementValidator"/> against
/// statements minted by <see cref="FederationTestRing"/>.
/// </summary>
[TestClass]
internal sealed class EntityStatementValidatorTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task HappyPathEntityConfigurationEmitsAllSuccessOrNotApplicable()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/leaf"));

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node,
            issuedAt: now,
            expiresAt: now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool signatureVerified = await FederationTestRing.VerifyAsync(
            node, minted.CompactJws, TestContext.CancellationToken).ConfigureAwait(false);

        EntityStatementValidationContext context = new()
        {
            Header = minted.Header,
            Statement = minted.Statement,
            SignatureVerified = signatureVerified,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        EntityStatementValidator validator = EntityStatementValidator.Default();
        ClaimIssueResult result = await validator.ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(signatureVerified, "Fixture signature should verify against the signing node's public key.");
        Assert.AreEqual(ClaimIssueCompletionStatus.Complete, result.CompletionStatus, "All rules should run to completion.");
        Assert.HasCount(14, result.Claims,
            "Profile emits 14 claims (codes 1100-1113: incl. ExpAfterIat (1110) and the three JWKS checks (1111-1113)).");
        foreach(Claim claim in result.Claims)
        {
            Assert.IsTrue(
                claim.Outcome is ClaimOutcome.Success or ClaimOutcome.NotApplicable,
                $"Happy-path claim {claim.Id} expected Success or NotApplicable, got {claim.Outcome}.");
        }
    }


    [TestMethod]
    public async Task ExpiredEntityConfigurationFailsExpInFuture()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/expired"));

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node,
            issuedAt: now.AddHours(-2),
            expiresAt: now.AddHours(-1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool signatureVerified = await FederationTestRing.VerifyAsync(
            node, minted.CompactJws, TestContext.CancellationToken).ConfigureAwait(false);

        EntityStatementValidationContext context = new()
        {
            Header = minted.Header,
            Statement = minted.Statement,
            SignatureVerified = signatureVerified,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        EntityStatementValidator validator = EntityStatementValidator.Default();
        ClaimIssueResult result = await validator.ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim expClaim = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.ExpInFuture.Code);
        Assert.AreEqual(ClaimOutcome.Failure, expClaim.Outcome, "Expired EC should fail ExpInFuture.");

        Claim iatClaim = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.IatInRange.Code);
        Assert.AreEqual(ClaimOutcome.Failure, iatClaim.Outcome,
            "Two-hour-old iat with five-minute skew should fail IatInRange.");
    }


    [TestMethod]
    public async Task EntityConfigurationWithExpiryAtOrBeforeIssuanceFailsExpAfterIat()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/inverted-window"));

        //exp one minute BEFORE iat — a non-positive lifetime. exp is still in the
        //future and iat is within skew, so only the mutual-consistency check fails.
        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node,
            issuedAt: now.AddMinutes(1),
            expiresAt: now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool signatureVerified = await FederationTestRing.VerifyAsync(
            node, minted.CompactJws, TestContext.CancellationToken).ConfigureAwait(false);

        EntityStatementValidationContext context = new()
        {
            Header = minted.Header,
            Statement = minted.Statement,
            SignatureVerified = signatureVerified,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await EntityStatementValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim expAfterIat = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.ExpAfterIat.Code);
        Assert.AreEqual(ClaimOutcome.Failure, expAfterIat.Outcome,
            "exp at or before iat must fail ExpAfterIat.");

        Claim expInFuture = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.ExpInFuture.Code);
        Assert.AreEqual(ClaimOutcome.Success, expInFuture.Outcome,
            "exp is still in the future; only the mutual-consistency check should fail.");
    }


    [TestMethod]
    public async Task UnverifiedSignatureFailsOnlySignatureVerifiesClaim()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/sigfail"));

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node,
            issuedAt: now,
            expiresAt: now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Deliberately feed false — simulates the orchestrator's Jws.VerifyAsync
        //reporting a tampered signature.
        EntityStatementValidationContext context = new()
        {
            Header = minted.Header,
            Statement = minted.Statement,
            SignatureVerified = false,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        EntityStatementValidator validator = EntityStatementValidator.Default();
        ClaimIssueResult result = await validator.ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim sigClaim = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.SignatureVerifies.Code);
        Assert.AreEqual(ClaimOutcome.Failure, sigClaim.Outcome,
            "SignatureVerifies should fail when context.SignatureVerified is false.");

        //Other claims still succeed/NotApplicable — they read the statement's other fields.
        int failures = result.Claims.Count(c => c.Outcome == ClaimOutcome.Failure);
        Assert.AreEqual(1, failures,
            "Only SignatureVerifies should fail when signature is the lone anomaly.");
    }


    [TestMethod]
    public async Task EntityConfigurationWithPrivateKeyInJwksFailsPublicOnlyCheck()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/leaked-private-key"));

        //Override the published jwks with a key carrying a private EC scalar (d). A
        //published Entity Statement JWKS must be public-only — mirrors the conformance
        //suite's EnsureEntityStatementJwksDoesNotContainPrivateOrSymmetricKeys.
        Dictionary<string, object> jwksWithPrivateKey = new()
        {
            [WellKnownJwkMemberNames.Keys] = new List<object>
            {
                new Dictionary<string, object>
                {
                    [WellKnownJwkMemberNames.Kty] = "EC",
                    [WellKnownJwkMemberNames.Crv] = "P-256",
                    [WellKnownJwkMemberNames.X] = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    [WellKnownJwkMemberNames.Y] = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                    [WellKnownJwkMemberNames.D] = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
                }
            }
        };

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node,
            issuedAt: now,
            expiresAt: now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.Jwks] = jwksWithPrivateKey
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool signatureVerified = await FederationTestRing.VerifyAsync(
            node, minted.CompactJws, TestContext.CancellationToken).ConfigureAwait(false);

        EntityStatementValidationContext context = new()
        {
            Header = minted.Header,
            Statement = minted.Statement,
            SignatureVerified = signatureVerified,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await EntityStatementValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim jwksPublicOnly = result.Claims.Single(
            c => c.Id.Code == WellKnownFederationClaimIds.JwksContainsNoPrivateOrSymmetricKeys.Code);
        Assert.AreEqual(ClaimOutcome.Failure, jwksPublicOnly.Outcome,
            "A published jwks carrying a private key member (d) must fail the public-only check.");
    }


    [TestMethod]
    public async Task EntityConfigurationWithDuplicateKidInJwksFailsDistinctKidCheck()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/duplicate-kid"));

        //Two public keys sharing one kid — ambiguous key selection, contrary to
        //the JWK Set kid uniqueness expectation of RFC 7517 §4.5.
        Dictionary<string, object> jwksWithDuplicateKid = new()
        {
            [WellKnownJwkMemberNames.Keys] = new List<object>
            {
                new Dictionary<string, object>
                {
                    [WellKnownJwkMemberNames.Kty] = "EC",
                    [WellKnownJwkMemberNames.Crv] = "P-256",
                    [WellKnownJwkMemberNames.Kid] = "shared-kid",
                    [WellKnownJwkMemberNames.X] = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    [WellKnownJwkMemberNames.Y] = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                },
                new Dictionary<string, object>
                {
                    [WellKnownJwkMemberNames.Kty] = "EC",
                    [WellKnownJwkMemberNames.Crv] = "P-256",
                    [WellKnownJwkMemberNames.Kid] = "shared-kid",
                    [WellKnownJwkMemberNames.X] = "kgJp7yGmqg4ndg6cZ8m5J6FqQ5kQ9o2dWw3yqJ0aXc",
                    [WellKnownJwkMemberNames.Y] = "Tn4cP1rD8mF2gH6jK0lN3pQ7sV9wY1bE4hJ6mR8tU0"
                }
            }
        };

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node,
            issuedAt: now,
            expiresAt: now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.Jwks] = jwksWithDuplicateKid
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool signatureVerified = await FederationTestRing.VerifyAsync(
            node, minted.CompactJws, TestContext.CancellationToken).ConfigureAwait(false);

        EntityStatementValidationContext context = new()
        {
            Header = minted.Header,
            Statement = minted.Statement,
            SignatureVerified = signatureVerified,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await EntityStatementValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim distinctKids = result.Claims.Single(
            c => c.Id.Code == WellKnownFederationClaimIds.JwksKeyIdsDistinct.Code);
        Assert.AreEqual(ClaimOutcome.Failure, distinctKids.Outcome,
            "A jwks with two keys sharing a kid must fail the distinct-kid check.");
    }


    [TestMethod]
    public async Task EntityConfigurationWithUndersizedRsaKeyFailsMinimumKeyLength()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/weak-rsa"));

        //An RSA key whose modulus is far below 2048 bits. A published Entity
        //Statement must not advertise signing keys below contemporary minimum
        //strength (RFC 7518 §6.3 / NIST SP 800-57).
        Dictionary<string, object> jwksWithWeakRsaKey = new()
        {
            [WellKnownJwkMemberNames.Keys] = new List<object>
            {
                new Dictionary<string, object>
                {
                    [WellKnownJwkMemberNames.Kty] = "RSA",
                    [WellKnownJwkMemberNames.Kid] = "weak-rsa",
                    [WellKnownJwkMemberNames.N] = "AQAB",
                    [WellKnownJwkMemberNames.E] = "AQAB"
                }
            }
        };

        Claim outcome = await ValidateJwksAndReadKeyLengthClaimAsync(
            node, now, jwksWithWeakRsaKey).ConfigureAwait(false);
        Assert.AreEqual(ClaimOutcome.Failure, outcome.Outcome,
            "An RSA modulus below 2048 bits must fail the minimum-key-length check.");
    }


    [TestMethod]
    public async Task EntityConfigurationWithAdequateRsaKeyPassesMinimumKeyLength()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/strong-rsa"));

        //A base64url modulus of 344 chars decodes to 258 bytes (> 2048 bits).
        Dictionary<string, object> jwksWithAdequateRsaKey = new()
        {
            [WellKnownJwkMemberNames.Keys] = new List<object>
            {
                new Dictionary<string, object>
                {
                    [WellKnownJwkMemberNames.Kty] = "RSA",
                    [WellKnownJwkMemberNames.Kid] = "strong-rsa",
                    [WellKnownJwkMemberNames.N] = new string('A', 344),
                    [WellKnownJwkMemberNames.E] = "AQAB"
                }
            }
        };

        Claim outcome = await ValidateJwksAndReadKeyLengthClaimAsync(
            node, now, jwksWithAdequateRsaKey).ConfigureAwait(false);
        Assert.AreEqual(ClaimOutcome.Success, outcome.Outcome,
            "An RSA modulus of at least 2048 bits must pass the minimum-key-length check.");
    }


    private async ValueTask<Claim> ValidateJwksAndReadKeyLengthClaimAsync(
        FederationTestRingNode node, DateTimeOffset now, Dictionary<string, object> jwks)
    {
        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node,
            issuedAt: now,
            expiresAt: now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.Jwks] = jwks
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        EntityStatementValidationContext context = new()
        {
            Header = minted.Header,
            Statement = minted.Statement,
            SignatureVerified = true,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await EntityStatementValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        return result.Claims.Single(
            c => c.Id.Code == WellKnownFederationClaimIds.JwksKeysMeetMinimumKeyLength.Code);
    }


    [TestMethod]
    [DataRow(true, 3600)]
    [DataRow(true, 86400)]
    [DataRow(true, 30 * 86400)]
    [DataRow(false, 3600)]
    [DataRow(false, 86400)]
    [DataRow(false, 30 * 86400)]
    public async Task IatOutsideSkewWindowFailsIatInRange(bool inPast, int absSeconds)
    {
        int signedDelta = inPast ? -absSeconds : absSeconds;

        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier($"https://example.test/iat-{absSeconds}-{(inPast ? "past" : "future")}"));

        //For past-iat cases keep exp in the future so ExpInFuture isn't the failing claim;
        //for future-iat cases push exp further out.
        DateTimeOffset iat = now.AddSeconds(signedDelta);
        DateTimeOffset exp = inPast ? now.AddHours(1) : iat.AddHours(1);

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node,
            issuedAt: iat,
            expiresAt: exp,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        EntityStatementValidationContext context = new()
        {
            Header = minted.Header,
            Statement = minted.Statement,
            SignatureVerified = true,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await EntityStatementValidator.Default()
            .ValidateAsync(context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim iatClaim = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.IatInRange.Code);
        Assert.AreEqual(ClaimOutcome.Failure, iatClaim.Outcome,
            $"iat offset {signedDelta}s should fail IatInRange under 5-minute skew.");
    }


    [TestMethod]
    public async Task AlgNoneFailsAlgPresent()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/alg-none"));

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node, issuedAt: now, expiresAt: now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //RFC 7518 §3.6 / RFC 8725: an unsigned ("alg":"none") federation JWT must be
        //rejected. Only the header is adversarial; the parsed statement stays valid so
        //AlgPresent is the lone failure.
        UnverifiedJwtHeader noneHeader = new(new Dictionary<string, object>
        {
            [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.None,
            [WellKnownJoseHeaderNames.Typ] = WellKnownFederationMediaTypes.EntityStatementJwt
        });

        EntityStatementValidationContext context = new()
        {
            Header = noneHeader,
            Statement = minted.Statement,
            SignatureVerified = true,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await EntityStatementValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim algClaim = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.AlgPresent.Code);
        Assert.AreEqual(ClaimOutcome.Failure, algClaim.Outcome,
            "alg=none must fail AlgPresent — unsigned federation JWTs are forbidden.");
    }


    [TestMethod]
    public async Task AlgAbsentFailsAlgPresent()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/alg-absent"));

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node, issuedAt: now, expiresAt: now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //A header that omits alg entirely is as invalid as alg=none.
        UnverifiedJwtHeader noAlgHeader = new(new Dictionary<string, object>
        {
            [WellKnownJoseHeaderNames.Typ] = WellKnownFederationMediaTypes.EntityStatementJwt
        });

        EntityStatementValidationContext context = new()
        {
            Header = noAlgHeader,
            Statement = minted.Statement,
            SignatureVerified = true,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await EntityStatementValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim algClaim = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.AlgPresent.Code);
        Assert.AreEqual(ClaimOutcome.Failure, algClaim.Outcome,
            "A header without an alg must fail AlgPresent.");
    }


    [TestMethod]
    public async Task TrustMarkTypFailsTypMatchEntityStatement()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/typ-confusion"));

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node, issuedAt: now, expiresAt: now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Cross-JWT confusion (RFC 8725 §3.11): a trust-mark+jwt presented where an
        //entity-statement+jwt is expected must be rejected on the typ check alone.
        UnverifiedJwtHeader wrongTypHeader = new(new Dictionary<string, object>
        {
            [WellKnownJwkMemberNames.Alg] = "ES256",
            [WellKnownJoseHeaderNames.Typ] = WellKnownFederationMediaTypes.TrustMarkJwt
        });

        EntityStatementValidationContext context = new()
        {
            Header = wrongTypHeader,
            Statement = minted.Statement,
            SignatureVerified = true,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await EntityStatementValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim typClaim = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.TypMatchesEntityStatement.Code);
        Assert.AreEqual(ClaimOutcome.Failure, typClaim.Outcome,
            "A trust-mark+jwt typ must fail TypMatchesEntityStatement (cross-JWT confusion defence).");

        Claim algClaim = result.Claims.Single(c => c.Id.Code == WellKnownFederationClaimIds.AlgPresent.Code);
        Assert.AreEqual(ClaimOutcome.Success, algClaim.Outcome,
            "alg is valid; only the typ check should fail.");
    }


    [TestMethod]
    public async Task EmptyJwksFailsJwksPresentWhenSelfSigned()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/empty-jwks"));

        //A self-issued Entity Configuration whose published jwks carries an empty key
        //array advertises no verification key — Federation §3.1 requires at least one.
        Dictionary<string, object> emptyJwks = new()
        {
            [WellKnownJwkMemberNames.Keys] = new List<object>()
        };

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node, issuedAt: now, expiresAt: now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.Jwks] = emptyJwks
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        EntityStatementValidationContext context = new()
        {
            Header = minted.Header,
            Statement = minted.Statement,
            SignatureVerified = true,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await EntityStatementValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim jwksPresent = result.Claims.Single(
            c => c.Id.Code == WellKnownFederationClaimIds.JwksPresentWhenSelfSigned.Code);
        Assert.AreEqual(ClaimOutcome.Failure, jwksPresent.Outcome,
            "An empty jwks key array must fail JwksPresentWhenSelfSigned.");
    }


    [TestMethod]
    public async Task RelativeAuthorityHintFailsAuthorityHintsWellFormed()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/bad-authority-hint"));

        //authority_hints must be a list of absolute-URL strings (Federation §3.1.1); a
        //relative reference is malformed.
        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node, issuedAt: now, expiresAt: now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.AuthorityHints] = new List<object> { "not/an/absolute/url" }
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        EntityStatementValidationContext context = new()
        {
            Header = minted.Header,
            Statement = minted.Statement,
            SignatureVerified = true,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await EntityStatementValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim hints = result.Claims.Single(
            c => c.Id.Code == WellKnownFederationClaimIds.AuthorityHintsWellFormed.Code);
        Assert.AreEqual(ClaimOutcome.Failure, hints.Outcome,
            "A relative-URL authority_hints entry must fail AuthorityHintsWellFormed.");
    }


    [TestMethod]
    public async Task NonObjectMetadataFailsMetadataWellFormed()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/bad-metadata"));

        //metadata must be an object keyed by entity-type strings (Federation §3.1.1);
        //a scalar is malformed.
        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node, issuedAt: now, expiresAt: now.AddHours(1),
            extraClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.Metadata] = "not-an-object"
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        EntityStatementValidationContext context = new()
        {
            Header = minted.Header,
            Statement = minted.Statement,
            SignatureVerified = true,
            Now = now,
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        ClaimIssueResult result = await EntityStatementValidator.Default().ValidateAsync(
            context, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim metadata = result.Claims.Single(
            c => c.Id.Code == WellKnownFederationClaimIds.MetadataWellFormed.Code);
        Assert.AreEqual(ClaimOutcome.Failure, metadata.Outcome,
            "A non-object metadata claim must fail MetadataWellFormed.");
    }
}
