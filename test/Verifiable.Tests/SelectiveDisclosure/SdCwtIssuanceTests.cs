using System.Buffers;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Example-based tests for SD-CWT issuance of generic CWT claim sets per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt</see>.
/// </summary>
/// <remarks>
/// <para>
/// These tests exercise the <see cref="SdCwtIssuanceExtensions"/> POCO-based issuance API.
/// The serializer delegate uses <see cref="CborValueConverter.WriteValue"/> which handles
/// <c>Dictionary&lt;int, object&gt;</c> natively, matching the system's standard CBOR
/// serialization path.
/// </para>
/// <para>
/// Property-based tests for the same invariants are in
/// <see cref="SdCwtIssuancePropertyTests"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SdCwtIssuanceTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    [TestMethod]
    public async Task IssueSdCwtFromDictionaryProducesValidToken()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = "https://issuer.example",
            [WellKnownCwtClaimNames.Sub] = "https://device.example",
            [WellKnownCwtClaimNames.Iat] = 1725244200L,
            [500] = true,
            [501] = "ABCD-123456"
        };
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/501")
        };

        SdTokenResult result = await claims.IssueSdCwtAsync(
            SdCwtWireFixtures.SerializeCwtClaimMap, SdCwtIssuance.IssueVerboseAsync, disclosablePaths, TestSalts.DefaultGenerator(),
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsGreaterThan(0, result.SignedToken.Length, "Signed token must not be empty.");
        Assert.HasCount(1, result.Disclosures);
    }


    [TestMethod]
    public async Task IssueSdCwtWithNoDisclosablePathsProducesZeroDisclosures()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = "https://issuer.example",
            [WellKnownCwtClaimNames.Iat] = 1700000000L
        };

        SdTokenResult result = await claims.IssueSdCwtAsync(
            SdCwtWireFixtures.SerializeCwtClaimMap, SdCwtIssuance.IssueVerboseAsync, new HashSet<CredentialPath>(), TestSalts.DefaultGenerator(),
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(0, result.Disclosures);
        Assert.IsGreaterThan(0, result.SignedToken.Length, "Token must still be produced.");
    }


    [TestMethod]
    public async Task IssueSdCwtWithMultipleDisclosablesProducesCorrectCount()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = "https://issuer.example",
            [500] = "value-a",
            [501] = "value-b",
            [502] = "value-c"
        };
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/500"),
            CredentialPath.FromJsonPointer("/501"),
            CredentialPath.FromJsonPointer("/502")
        };

        SdTokenResult result = await claims.IssueSdCwtAsync(
            SdCwtWireFixtures.SerializeCwtClaimMap, SdCwtIssuance.IssueVerboseAsync, disclosablePaths, TestSalts.DefaultGenerator(),
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, result.Disclosures);
    }


    [TestMethod]
    public async Task IssueVerboseExposesRedactedPayload()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = "https://issuer.example",
            [WellKnownCwtClaimNames.Iat] = 1725244200L,
            [501] = "ABCD-123456"
        };
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/501")
        };

        byte[] cborBytes = SdCwtWireFixtures.SerializeCwtClaimMap(claims).ToArray();

        (SdTokenResult result, ReadOnlyMemory<byte> redactedPayload) = await SdCwtIssuance.IssueVerboseAsync(
            cborBytes, disclosablePaths, TestSalts.DefaultGenerator(),
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsGreaterThan(0, result.SignedToken.Length, "Signed token must not be empty.");
        Assert.HasCount(1, result.Disclosures);
        Assert.IsGreaterThan(0, redactedPayload.Length, "The redacted payload must be exposed.");

        //The disclosable claim was redacted out of the payload, so the signed bytes differ from
        //the original CBOR — confirming the exposed value is the post-redaction payload.
        Assert.IsFalse(redactedPayload.Span.SequenceEqual(cborBytes), "Redaction must have transformed the payload.");
    }


    [TestMethod]
    public async Task IssueSdCwtTokenVerboseExposesTokenAndRedactedPayload()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = "https://issuer.example",
            [501] = "ABCD-123456"
        };
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/501")
        };

        (SdToken<ReadOnlyMemory<byte>> token, ReadOnlyMemory<byte> redactedPayload) = await claims.IssueSdCwtTokenVerboseAsync(
            SdCwtWireFixtures.SerializeCwtClaimMap, SdCwtIssuance.IssueVerboseAsync, disclosablePaths, TestSalts.DefaultGenerator(),
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using(token)
        {
            Assert.IsGreaterThan(0, token.IssuerSigned.Length, "The token must carry the signed COSE_Sign1 bytes.");
            Assert.HasCount(1, token.Disclosures);
            Assert.IsGreaterThan(0, redactedPayload.Length, "The redacted payload must be exposed alongside the token.");
        }
    }
}
