using Verifiable.Core.Model.Dcql;
using Verifiable.JCose.Eudi;

namespace Verifiable.Tests.Builders;

/// <summary>
/// Tests for <see cref="DcqlQueryBuilder"/> and <see cref="DcqlBuilderExtensions"/>.
/// </summary>
[TestClass]
internal class DcqlQueryBuilderTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task BuildSingleSdJwtCredentialProducesValidQuery()
    {
        var builder = new DcqlQueryBuilder()
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName]),
                 ClaimsQuery.ForPath([EudiPid.SdJwt.FamilyName])]);

        var query = await builder.BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(query.Credentials);
        Assert.HasCount(1, query.Credentials);
        Assert.AreEqual(EudiPid.DefaultCredentialQueryId, query.Credentials[0].Id);
        Assert.AreEqual(DcqlCredentialFormats.SdJwt, query.Credentials[0].Format);
        Assert.IsNotNull(query.Credentials[0].Claims);
        Assert.HasCount(2, query.Credentials[0].Claims!);
        Assert.IsNull(query.CredentialSets);
    }


    [TestMethod]
    public async Task BuildWithCredentialSetsProducesValidQuery()
    {
        var builder = new DcqlQueryBuilder()
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName]),
                 ClaimsQuery.ForPath([EudiPid.SdJwt.FamilyName])])
            .WithSdJwtCredential("email",
                [ClaimsQuery.ForPath([EudiPid.SdJwt.Email])])
            .WithSdJwtCredential("phone",
                [ClaimsQuery.ForPath([EudiPid.SdJwt.PhoneNumber])])
            .WithCredentialSet(true, [[EudiPid.DefaultCredentialQueryId], ["email", "phone"]]);

        var query = await builder.BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(query.Credentials);
        Assert.HasCount(3, query.Credentials);
        Assert.IsNotNull(query.CredentialSets);
        Assert.HasCount(1, query.CredentialSets);
        Assert.HasCount(2, query.CredentialSets[0].Options);
    }


    [TestMethod]
    public async Task BuildWithOptionalCredentialSetPreservesRequiredFalseAndPurpose()
    {
        var builder = new DcqlQueryBuilder()
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName])])
            .WithSdJwtCredential("loyalty",
                [ClaimsQuery.ForPath(["tier"])])
            .WithCredentialSet(false, "Loyalty card for personalized offers.", [["loyalty"]]);

        var query = await builder.BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(query.CredentialSets);
        Assert.IsFalse(query.CredentialSets[0].Required);
        Assert.AreEqual("Loyalty card for personalized offers.", query.CredentialSets[0].Purpose);
    }


    [TestMethod]
    public async Task BuildWithMdocCredentialIncludesMetadata()
    {
        var builder = new DcqlQueryBuilder()
            .WithMdocCredential("mdl", EudiMdl.Doctype,
                [ClaimsQuery.ForMdocPath(true, EudiMdl.Namespace, EudiMdl.Attributes.FamilyName),
                 ClaimsQuery.ForMdocPath(true, EudiMdl.Namespace, EudiMdl.Attributes.GivenName)]);

        var query = await builder.BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(query.Credentials);
        var cred = query.Credentials[0];
        Assert.AreEqual(DcqlCredentialFormats.MsoMdoc, cred.Format);
        Assert.IsNotNull(cred.Meta);
        Assert.AreEqual(EudiMdl.Doctype, cred.Meta.DoctypeValue);
        Assert.IsNotNull(cred.Claims);
        Assert.HasCount(2, cred.Claims);
        Assert.IsTrue(cred.Claims[0].IntentToRetain);
    }


    [TestMethod]
    public async Task BuildWithSdJwtVctValuesIncludesMetadata()
    {
        var builder = new DcqlQueryBuilder()
            .WithSdJwtCredential("identity",
                ["https://credentials.example/identity_credential"],
                [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName])]);

        var query = await builder.BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(query.Credentials);
        Assert.IsNotNull(query.Credentials[0].Meta);
        Assert.IsNotNull(query.Credentials[0].Meta!.VctValues);
        Assert.HasCount(1, query.Credentials[0].Meta!.VctValues!);
        Assert.AreEqual("https://credentials.example/identity_credential",
            query.Credentials[0].Meta!.VctValues![0]);
    }


    [TestMethod]
    public async Task BuildWithLdpVcCredentialSetsCorrectFormat()
    {
        var builder = new DcqlQueryBuilder()
            .WithLdpVcCredential("vc",
                [ClaimsQuery.ForPath(["credentialSubject", EudiPid.SdJwt.Email])]);

        var query = await builder.BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(query.Credentials);
        Assert.AreEqual(DcqlCredentialFormats.LdpVc, query.Credentials[0].Format);
    }


    [TestMethod]
    public async Task BuildWithNoCredentialsThrows()
    {
        var builder = new DcqlQueryBuilder();

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await builder.BuildAsync(TestContext.CancellationToken)
                .ConfigureAwait(false)).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task BuildWithInvalidCredentialSetReferenceThrows()
    {
        var builder = new DcqlQueryBuilder()
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName])])
            .WithCredentialSet(true, [[EudiPid.DefaultCredentialQueryId], ["nonexistent"]]);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await builder.BuildAsync(TestContext.CancellationToken)
                .ConfigureAwait(false)).ConfigureAwait(false);

        Assert.IsTrue(exception.Message.Contains("nonexistent", StringComparison.Ordinal));
    }


    [TestMethod]
    public async Task BuildWithDuplicateCredentialIdThrows()
    {
        var builder = new DcqlQueryBuilder()
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName])])
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [ClaimsQuery.ForPath([EudiPid.SdJwt.FamilyName])]);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await builder.BuildAsync(TestContext.CancellationToken)
                .ConfigureAwait(false)).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task BuilderIsReusableAcrossMultipleBuilds()
    {
        var builder = new DcqlQueryBuilder()
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName])]);

        var query1 = await builder.BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var query2 = await builder.BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(query1.Credentials);
        Assert.IsNotNull(query2.Credentials);
        Assert.HasCount(1, query1.Credentials);
        Assert.HasCount(1, query2.Credentials);
        Assert.AreEqual(query1.Credentials[0].Id, query2.Credentials[0].Id);
    }


    [TestMethod]
    public async Task CustomWithTransformationIsApplied()
    {
        var builder = new DcqlQueryBuilder()
            .WithSdJwtCredential(EudiPid.DefaultCredentialQueryId,
                [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName])])
            .With((query, bldr, state) =>
            {
                //Custom transformation adds a second credential.
                state!.AddCredential(new CredentialQuery
                {
                    Id = "email",
                    Format = DcqlCredentialFormats.SdJwt,
                    Claims = [ClaimsQuery.ForPath([EudiPid.SdJwt.Email])]
                });

                return ValueTask.FromResult(query);
            });

        var query = await builder.BuildAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(query.Credentials);
        Assert.HasCount(2, query.Credentials);
        Assert.AreEqual("email", query.Credentials[1].Id);
    }


    [TestMethod]
    public void ForPathCreatesConcreteKeyPath()
    {
        var claim = ClaimsQuery.ForPath(["credentialSubject", EudiPid.SdJwt.Email]);

        Assert.IsNotNull(claim.Path);
        Assert.AreEqual(2, claim.Path.Count);
        Assert.AreEqual("credentialSubject", claim.Path[0].KeyValue);
        Assert.AreEqual(EudiPid.SdJwt.Email, claim.Path[1].KeyValue);
        Assert.IsFalse(claim.Path.HasWildcards);
    }


    [TestMethod]
    public void ForPathWithValuesIncludesConstraints()
    {
        var claim = ClaimsQuery.ForPathWithValues(
            ["issuer"],
            ["did:web:university.example", "did:web:college.example"]);

        Assert.IsNotNull(claim.Values);
        Assert.HasCount(2, claim.Values);
        Assert.AreEqual("did:web:university.example", claim.Values[0]);
        Assert.AreEqual("did:web:college.example", claim.Values[1]);
    }


    [TestMethod]
    public void ForWildcardPathCreatesPatternWithWildcard()
    {
        var claim = ClaimsQuery.ForWildcardPath(["citizenship", null, "country"]);

        Assert.IsNotNull(claim.Path);
        Assert.AreEqual(3, claim.Path.Count);
        Assert.AreEqual("citizenship", claim.Path[0].KeyValue);
        Assert.IsTrue(claim.Path[1].IsWildcard);
        Assert.AreEqual("country", claim.Path[2].KeyValue);
        Assert.IsTrue(claim.Path.HasWildcards);
    }


    [TestMethod]
    public void ForMdocPathSetsIntentToRetain()
    {
        var claim = ClaimsQuery.ForMdocPath(true, EudiMdl.Namespace, EudiMdl.Attributes.FamilyName);

        Assert.IsNotNull(claim.IntentToRetain);
        Assert.IsTrue(claim.IntentToRetain.Value);
        Assert.IsNotNull(claim.Path);
        Assert.AreEqual(2, claim.Path.Count);
        Assert.AreEqual(EudiMdl.Namespace, claim.Path[0].KeyValue);
        Assert.AreEqual(EudiMdl.Attributes.FamilyName, claim.Path[1].KeyValue);
    }


    [TestMethod]
    public void ForWildcardPathWithEmptySegmentsThrows()
    {
        Assert.Throws<ArgumentException>(
            () => ClaimsQuery.ForWildcardPath([]));
    }


    [TestMethod]
    public void SingleCreatesQueryWithOneCredential()
    {
        var query = DcqlQuery.Single(new CredentialQuery
        {
            Id = EudiPid.DefaultCredentialQueryId,
            Format = DcqlCredentialFormats.SdJwt,
            Claims = [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName])]
        });

        Assert.IsNotNull(query.Credentials);
        Assert.HasCount(1, query.Credentials);
        Assert.AreEqual(EudiPid.DefaultCredentialQueryId, query.Credentials[0].Id);
        Assert.IsNull(query.CredentialSets);
    }


    [TestMethod]
    public void AllCreatesQueryWithMultipleCredentials()
    {
        var query = DcqlQuery.All(
            [new CredentialQuery
            {
                Id = EudiPid.DefaultCredentialQueryId,
                Format = DcqlCredentialFormats.SdJwt,
                Claims = [ClaimsQuery.ForPath([EudiPid.SdJwt.GivenName])]
            },
            new CredentialQuery
            {
                Id = "email",
                Format = DcqlCredentialFormats.SdJwt,
                Claims = [ClaimsQuery.ForPath([EudiPid.SdJwt.Email])]
            }]);

        Assert.IsNotNull(query.Credentials);
        Assert.HasCount(2, query.Credentials);
        Assert.AreEqual(EudiPid.DefaultCredentialQueryId, query.Credentials[0].Id);
        Assert.AreEqual("email", query.Credentials[1].Id);
    }


    [TestMethod]
    public void FormatConstantsAreNonEmptyAndDistinct()
    {
        string[] formats =
        [
            DcqlCredentialFormats.SdJwt,
            DcqlCredentialFormats.MsoMdoc,
            DcqlCredentialFormats.LdpVc,
            DcqlCredentialFormats.JwtVcJson
        ];

        foreach(var format in formats)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(format));
        }

        Assert.HasCount(formats.Length, new HashSet<string>(formats));
    }
}