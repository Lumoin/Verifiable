using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// End-to-end W3C Bitstring Status List flow secured with a Data Integrity proof
/// (<c>eddsa-jcs-2022</c>, <c>application/vc</c>): an issuer encodes a status list into a
/// <c>BitstringStatusListCredential</c> and signs it in-graph; a verifier, holding only the
/// published credential JSON and the issuer DID document, verifies the proof, decodes the
/// <c>encodedList</c>, and reads a credential's status. Runs across each key type the existing
/// DID-web provider exercises, over the existing Data Integrity surface — no new signer.
/// </summary>
[TestClass]
internal sealed class BitstringStatusListCredentialDataIntegrityTests
{
    private const int Example4Index = 94567;
    private const int UnsetIndex = 5;
    private const string StatusListCredentialUrl = "https://example.com/credentials/status/3";
    private const string IssuerDomain = "issuer.example";
    private const string IssuerDidWeb = "did:web:issuer.example";

    private static readonly DateTimeOffset Now = new(2024, 6, 15, 12, 0, 0, TimeSpan.Zero);
    private static readonly ExchangeContext EmptyContext = new();

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static CredentialBuilder CredentialBuilder { get; } = new CredentialBuilder();
    private static WebDidBuilder WebDidBuilder { get; } = new WebDidBuilder();

    public TestContext TestContext { get; set; } = null!;

    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
    {
        string canonical = Jcs.Canonicalize(json);

        return ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = canonical });
    };

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential => JsonSerializerExtensions.Serialize(credential, JsonOptions);
    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized => JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;
    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } = ProofOptionsSerializer.Create(JsonOptions);


    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task IssueResolveVerifyAndReadStatusViaDataIntegrity(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        //Issuer side: revoke one credential's index, encode the list into a status list credential.
        using var statusList = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        statusList[Example4Index] = 1;
        string encodedList = BitstringStatusListCodec.EncodeList(statusList);

        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = "https://example.com/status/3#list",
            Claims = new Dictionary<string, object>
            {
                ["type"] = BitstringStatusListConstants.SubjectType,
                ["statusPurpose"] = BitstringStatusListConstants.RevocationPurpose,
                ["encodedList"] = encodedList
            }
        };

        DateTime validFrom = Now.UtcDateTime;
        var unsignedCredential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            validFrom,
            additionalTypes: [BitstringStatusListConstants.CredentialType],
            validUntil: validFrom.AddYears(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var signedCredential = await unsignedCredential.SignAsync(
            privateKey,
            issuerVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            validFrom,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            Pool,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Publish to the wire.
        string published = JsonSerializerExtensions.Serialize(signedCredential, JsonOptions);

        //Verifier side, firewalled: only the published JSON and the issuer DID document are in scope.
        var resolvedCredential = JsonSerializerExtensions.Deserialize<DataIntegritySecuredCredential>(published, JsonOptions)!;

        var verificationResult = await resolvedCredential.VerifyAsync(
            issuerDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            Pool,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid, "The status list credential proof must verify.");

        IDictionary<string, object> subjectData = resolvedCredential.CredentialSubject![0].AdditionalData!;
        string resolvedEncodedList = ReadString(subjectData, BitstringStatusListConstants.EncodedListProperty);
        string[] purposes = [ReadString(subjectData, BitstringStatusListConstants.StatusPurposeProperty)];

        using var resolvedList = BitstringStatusListCodec.DecodeList(resolvedEncodedList, StatusListBitSize.OneBit, Pool);

        BitstringStatusListStatus revoked = BitstringStatusListValidation.GetStatus(RevocationEntry(Example4Index), resolvedList, purposes, Now);
        BitstringStatusListStatus active = BitstringStatusListValidation.GetStatus(RevocationEntry(UnsetIndex), resolvedList, purposes, Now);

        Assert.IsFalse(revoked.IsValid, "The revoked credential's index must read as invalid.");
        Assert.IsTrue(active.IsValid, "An unset index must read as valid.");
    }


    private static BitstringStatusListEntry RevocationEntry(int index) => new()
    {
        StatusPurpose = BitstringStatusListConstants.RevocationPurpose,
        StatusListIndex = index,
        StatusListCredential = StatusListCredentialUrl
    };


    private static string ReadString(IDictionary<string, object> data, string key)
    {
        object value = data[key];

        return value switch
        {
            string s => s,
            JsonElement element => element.GetString()!,
            _ => value.ToString()!
        };
    }
}
