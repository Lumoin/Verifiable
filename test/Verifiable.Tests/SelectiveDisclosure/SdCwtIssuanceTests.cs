using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
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
/// These tests exercise the <see cref="SdCwtExtensions"/> POCO-based issuance API.
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

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;


    [TestMethod]
    public async Task IssueSdCwtFromDictionaryProducesValidToken()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaims.Iss] = "https://issuer.example",
            [WellKnownCwtClaims.Sub] = "https://device.example",
            [WellKnownCwtClaims.Iat] = 1725244200L,
            [500] = true,
            [501] = "ABCD-123456"
        };
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/501")
        };

        SdTokenResult result = await claims.IssueSdCwtAsync(
            SerializeCwtClaimMap, disclosablePaths, SaltGenerator.Create,
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
            [WellKnownCwtClaims.Iss] = "https://issuer.example",
            [WellKnownCwtClaims.Iat] = 1700000000L
        };

        SdTokenResult result = await claims.IssueSdCwtAsync(
            SerializeCwtClaimMap, new HashSet<CredentialPath>(), SaltGenerator.Create,
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
            [WellKnownCwtClaims.Iss] = "https://issuer.example",
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
            SerializeCwtClaimMap, disclosablePaths, SaltGenerator.Create,
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, result.Disclosures);
    }


    /// <summary>
    /// Serializes a CWT claim map using the system's standard <see cref="CborValueConverter"/>.
    /// This is the same serialization path used by production code.
    /// </summary>
    private static byte[] SerializeCwtClaimMap(Dictionary<int, object> claims)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        CborValueConverter.WriteValue(writer, claims);
        return writer.Encode();
    }
}