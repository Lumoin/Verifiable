using System.Buffers;
using Verifiable.Cbor.Sd;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose.Sd;
using Verifiable.Json.Sd;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Example-based tests for issuing selectively disclosable W3C Verifiable Credentials per
/// <see href="https://www.w3.org/TR/vc-jose-cose/">VC-JOSE-COSE</see> and
/// <see href="https://www.w3.org/TR/vc-data-model-2.0/">VC Data Model 2.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// These tests verify the <see cref="VerifiableCredential"/>-specific overloads in
/// <see cref="SdJwtExtensions"/> and <see cref="SdCwtExtensions"/> that enforce the W3C
/// requirement that only claims under <c>/credentialSubject</c> may be selectively disclosable.
/// Top-level claims like <c>issuer</c>, <c>type</c>, and <c>validFrom</c> must remain mandatory.
/// </para>
/// <para>
/// Property-based path validation tests are in
/// <see cref="CredentialSdIssuancePropertyTests"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CredentialSdIssuanceTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;


    [TestMethod]
    public async Task IssueSdJwtFromVerifiableCredentialProducesValidToken()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        VerifiableCredential credential = CredentialSecuringMaterial.Credential;
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/id"),
            CredentialPath.FromJsonPointer("/credentialSubject/degree")
        };

        SdTokenResult result = await credential.IssueSdJwtAsync(
            disclosablePaths, SaltGenerator.Create,
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            jsonOptions: CredentialSecuringMaterial.JsonOptions,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsGreaterThan(0, result.SignedToken.Length, "Signed token must not be empty.");
        Assert.HasCount(2, result.Disclosures);
    }


    [TestMethod]
    public async Task IssueSdJwtFromVerifiableCredentialWithDeeplyNestedPath()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        VerifiableCredential credential = CredentialSecuringMaterial.Credential;
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/degree/name")
        };

        SdTokenResult result = await credential.IssueSdJwtAsync(
            disclosablePaths, SaltGenerator.Create,
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            jsonOptions: CredentialSecuringMaterial.JsonOptions,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, result.Disclosures);
        Assert.AreEqual("name", result.Disclosures[0].ClaimName);
    }


    [TestMethod]
    public async Task IssueSdJwtFromVerifiableCredentialWithSingleClaimDisclosure()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        VerifiableCredential credential = CredentialSecuringMaterial.Credential;
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/id")
        };

        SdTokenResult result = await credential.IssueSdJwtAsync(
            disclosablePaths, SaltGenerator.Create,
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            jsonOptions: CredentialSecuringMaterial.JsonOptions,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, result.Disclosures);
        Assert.AreEqual("id", result.Disclosures[0].ClaimName);
    }


    [TestMethod]
    public void ValidateCredentialPathsAcceptsAllCredentialSubjectPaths()
    {
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/id"),
            CredentialPath.FromJsonPointer("/credentialSubject/degree"),
            CredentialPath.FromJsonPointer("/credentialSubject/degree/name"),
            CredentialPath.FromJsonPointer("/credentialSubject/degree/type")
        };

        SdJwtExtensions.ValidateCredentialPaths(disclosablePaths);
    }


    [TestMethod]
    public void ValidateCredentialPathsAcceptsEmptySet()
    {
        SdJwtExtensions.ValidateCredentialPaths(new HashSet<CredentialPath>());
    }


    [TestMethod]
    public void ValidateCredentialPathsRejectsIssuerPath()
    {
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/id"),
            CredentialPath.FromJsonPointer("/issuer/name")
        };

        Assert.Throws<ArgumentException>(() =>
            SdJwtExtensions.ValidateCredentialPaths(disclosablePaths));
    }


    [TestMethod]
    public void ValidateCredentialPathsRejectsTopLevelValidFrom()
    {
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/validFrom")
        };

        Assert.Throws<ArgumentException>(() =>
            SdJwtExtensions.ValidateCredentialPaths(disclosablePaths));
    }


    [TestMethod]
    public void ValidateCredentialPathsRejectsTopLevelType()
    {
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/type")
        };

        Assert.Throws<ArgumentException>(() =>
            SdJwtExtensions.ValidateCredentialPaths(disclosablePaths));
    }


    [TestMethod]
    public void ValidateCredentialPathsRejectsRootPath()
    {
        Assert.Throws<ArgumentException>(() =>
            SdJwtExtensions.ValidateCredentialPaths(new HashSet<CredentialPath> { CredentialPath.Root }));
    }


    [TestMethod]
    public void CwtValidateCredentialPathsRejectsIssuerPath()
    {
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/id"),
            CredentialPath.FromJsonPointer("/issuer")
        };

        Assert.Throws<ArgumentException>(() =>
            SdCwtExtensions.ValidateCredentialPaths(disclosablePaths));
    }
}