using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// End-to-end W3C Bitstring Status List flow secured with JOSE enveloping (<c>application/vc+jwt</c>):
/// an issuer encodes a status list into a <c>BitstringStatusListCredential</c> and signs it; a
/// verifier, holding only the published JWS and the issuer public key, verifies the proof, decodes
/// the <c>encodedList</c>, and reads a credential's status. This exercises the whole presentation
/// over the existing JWS credential surface — no new signer.
/// </summary>
[TestClass]
internal sealed class BitstringStatusListCredentialJwsTests
{
    private const int Example4Index = 94567;
    private const int UnsetIndex = 5;
    private static readonly DateTimeOffset Now = StatusListTestConstants.BitstringValidationReferenceTime;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// An unsigned <c>BitstringStatusListCredential</c> with a placeholder <c>encodedList</c> that
    /// the test overwrites with a freshly encoded list.
    /// </summary>
    private const string StatusListCredentialTemplate = /*lang=json,strict*/ """
    {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "https://example.com/credentials/status/3",
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
        "validFrom": "2024-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "https://example.com/status/3#list",
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": "u"
        }
    }
    """;


    [TestMethod]
    public async Task IssueResolveVerifyAndReadStatusViaJoseEnveloping()
    {
        //Issuer side: revoke one credential's index, encode the list, embed it in a status list credential.
        using var statusList = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        statusList[Example4Index] = 1;
        string encodedList = BitstringStatusListCodec.EncodeList(statusList);

        VerifiableCredential statusListCredential = StatusListTokenJwtFixtures.BuildStatusListCredential(StatusListCredentialTemplate, encodedList);

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        using var publicKey = CredentialSecuringMaterial.DecodeEd25519PublicKey();

        JwsMessage jws = await statusListCredential.SignJwsAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string published = JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);

        //Verifier side, firewalled: only the published JWS and the issuer public key are in scope.
        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            published,
            publicKey,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The status list credential proof must verify.");

        VerifiableCredential resolved = result.Credential!.Value.Value;
        IDictionary<string, object> subject = resolved.CredentialSubject![0].AdditionalData!;
        string resolvedEncodedList = ReadString(subject, BitstringStatusListConstants.EncodedListProperty);
        string[] purposes = [ReadString(subject, BitstringStatusListConstants.StatusPurposeProperty)];

        using var resolvedList = BitstringStatusListCodec.DecodeList(resolvedEncodedList, StatusListBitSize.OneBit, Pool);

        BitstringStatusListStatus revoked = BitstringStatusListValidation.GetStatus(RevocationEntry(Example4Index), resolvedList, purposes, Now);
        BitstringStatusListStatus active = BitstringStatusListValidation.GetStatus(RevocationEntry(UnsetIndex), resolvedList, purposes, Now);

        Assert.IsFalse(revoked.IsValid, "The revoked credential's index must read as invalid.");
        Assert.IsTrue(active.IsValid, "An unset index must read as valid.");
    }


    [TestMethod]
    public async Task TamperedStatusListCredentialFailsVerification()
    {
        using var statusList = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        statusList[Example4Index] = 1;
        VerifiableCredential statusListCredential = StatusListTokenJwtFixtures.BuildStatusListCredential(StatusListCredentialTemplate, BitstringStatusListCodec.EncodeList(statusList));

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        using var publicKey = CredentialSecuringMaterial.DecodeEd25519PublicKey();

        JwsMessage jws = await statusListCredential.SignJwsAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string published = JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);

        //An attacker flips a middle character of the payload segment (the encoded credential) to clear
        //the revocation. A middle character stays base64url-valid, so the tampered payload alters the
        //signing input and the signature deterministically fails to verify.
        string[] parts = published.Split('.');
        int tamperIndex = parts[1].Length / 2;
        char flipped = parts[1][tamperIndex] == 'A' ? 'B' : 'A';
        parts[1] = string.Concat(parts[1].AsSpan(0, tamperIndex), flipped.ToString(), parts[1].AsSpan(tamperIndex + 1));
        string tampered = string.Join('.', parts);

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            tampered,
            publicKey,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A tampered status list credential must not verify.");
    }


    private static BitstringStatusListEntry RevocationEntry(int index) => new()
    {
        StatusPurpose = BitstringStatusListConstants.RevocationPurpose,
        StatusListIndex = index,
        StatusListCredential = "https://example.com/credentials/status/3"
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


    private static ReadOnlySpan<byte> CredentialSerializer(VerifiableCredential credential) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(credential, CredentialSecuringMaterial.JsonOptions);

    private static ReadOnlySpan<byte> HeaderSerializer(Dictionary<string, object> header) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(header, CredentialSecuringMaterial.JsonOptions);

    private static Dictionary<string, object>? HeaderDeserializer(ReadOnlySpan<byte> headerBytes) =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(headerBytes, CredentialSecuringMaterial.JsonOptions);

    private static VerifiableCredential CredentialDeserializer(ReadOnlySpan<byte> credentialBytes) =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(credentialBytes, CredentialSecuringMaterial.JsonOptions)!;
}
