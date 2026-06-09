using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.SecurityEvents;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// A single credential-revocation trigger fanning out, over real HTTP, to BOTH status-list
/// channels: the pull channel (flip the status bit, re-sign the BitstringStatusListCredential, and
/// republish it so a polling verifier sees the revocation) AND the push channel (a CAEP
/// <c>credential-change</c> Security Event Token delivered to a Shared Signals Receiver). The
/// application composes both behind the <see cref="UpdateCredentialStatusDelegate"/> seam — the
/// credential-side analog of the global token-revocation fan-out in
/// <see cref="OAuth.GlobalLogoutDualChannelHttpTests"/>.
/// </summary>
/// <remarks>
/// Firewalled: the verifier holds only the issuer public key and the fetched credential bytes; the
/// SSF Receiver holds only the issuer public key and the pushed SET bytes. No signing key or
/// in-memory object crosses a boundary.
/// </remarks>
[TestClass]
internal sealed class BitstringStatusListRevocationDualChannelHttpTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private const string Issuer = "https://issuer.example/";
    private const string ReceiverAudience = "https://receiver.example/ssf";
    private const string StatusListPath = "/credentials/status/3";
    private const string StatusListCredentialUrl = "https://issuer.example/credentials/status/3";
    private const string RevokedHolderSubject = "holder-123";
    private const string VerificationMethodId = "did:web:issuer.example#status-key";
    private const int Example4Index = 94567;

    private const string StatusListCredentialTemplate = /*lang=json,strict*/ """
    {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "https://issuer.example/credentials/status/3",
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": "https://issuer.example/",
        "validFrom": "2026-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "https://issuer.example/status/3#list",
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": "u"
        }
    }
    """;


    [TestMethod]
    public async Task RevocationFlipsBitAndPushesCaepCredentialChangeOverHttp()
    {
        CancellationToken ct = TestContext.CancellationToken;

        //The issuer's signing key: the private half signs both the status list credential and the
        //SET; the public half is the only issuer secret any receiver holds.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;

        //The issuer's working status list — initially every credential is valid (bit 0).
        using var statusList = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);

        async Task<string> PublishAsync(CancellationToken token)
        {
            string encodedList = BitstringStatusListCodec.EncodeList(statusList);
            VerifiableCredential credential = BuildStatusListCredential(encodedList);
            JwsMessage signed = await credential.SignJwsAsync(
                issuerPrivate,
                VerificationMethodId,
                SerializeCredential,
                SerializeCredentialHeader,
                TestSetup.Base64UrlEncoder,
                Pool,
                cancellationToken: token).ConfigureAwait(false);

            return JwsSerialization.SerializeCompact(signed, TestSetup.Base64UrlEncoder);
        }

        //Channel 1 — the published status list credential a polling verifier dereferences.
        string publishedCredential = await PublishAsync(ct).ConfigureAwait(false);

        Task<MinimalHttpResponse> StatusListHandler(MinimalHttpRequest request, CancellationToken token)
        {
            if(string.Equals(request.Method, "GET", StringComparison.Ordinal) && string.Equals(request.Path, StatusListPath, StringComparison.Ordinal))
            {
                return Task.FromResult(new MinimalHttpResponse { StatusCode = 200, ContentType = "application/vc+jwt", Body = publishedCredential });
            }

            return Task.FromResult(new MinimalHttpResponse { StatusCode = 404 });
        }

        await using MinimalHttpHost statusListHost = await MinimalHttpHost.StartAsync(StatusListHandler, ct).ConfigureAwait(false);

        //Channel 2 — the Shared Signals Receiver: each push is one SET verified from the wire bytes
        //plus the issuer public key alone through the full reception pipeline.
        SecurityEventToken? receivedToken = null;
        HashSet<string> seenJtis = new(StringComparer.Ordinal);
        IsSecurityEventTokenJtiSeenDelegate isSeen = (jti, _, _) => ValueTask.FromResult(!seenJtis.Add(jti));

        async Task<MinimalHttpResponse> ReceiverPushHandler(MinimalHttpRequest request, CancellationToken token)
        {
            if(request.ContentType is null
                || !request.ContentType.StartsWith(WellKnownMediaTypes.Application.SecEventJwt, StringComparison.OrdinalIgnoreCase))
            {
                return new MinimalHttpResponse { StatusCode = 400 };
            }

            SsfDeliveryDecision decision = await SecurityEventTokenReception.ReceiveAsync(
                request.Body, issuerPublic, Issuer, ReceiverAudience,
                SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
                TestSetup.Base64UrlDecoder, isSeen, new ExchangeContext(), Pool, token).ConfigureAwait(false);

            if(decision.Outcome is SsfDeliveryOutcome.Accepted or SsfDeliveryOutcome.AcceptedDuplicate)
            {
                receivedToken = decision.Token;
                return new MinimalHttpResponse { StatusCode = 202 };
            }

            return new MinimalHttpResponse { StatusCode = 400 };
        }

        await using MinimalHttpHost ssfReceiver = await MinimalHttpHost.StartAsync(ReceiverPushHandler, ct).ConfigureAwait(false);

        using HttpClient verifierClient = new();
        using HttpClient transmitterClient = new();

        async Task<BitstringStatusListStatus> CheckStatusAsync(int index, CancellationToken token)
        {
            using HttpResponseMessage response = await verifierClient.GetAsync(new Uri(statusListHost.BaseAddress, StatusListPath), token).ConfigureAwait(false);
            Assert.AreEqual(200, (int)response.StatusCode);
            string jws = await response.Content.ReadAsStringAsync(token).ConfigureAwait(false);

            JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
                jws, issuerPublic, TestSetup.Base64UrlDecoder, DeserializeCredentialHeader, DeserializeCredential, Pool, token).ConfigureAwait(false);
            Assert.IsTrue(result.IsValid, "The fetched status list credential must verify.");

            VerifiableCredential resolved = result.Credential!.Value.Value;
            IDictionary<string, object> subjectData = resolved.CredentialSubject![0].AdditionalData!;
            string encodedList = ReadString(subjectData, BitstringStatusListConstants.EncodedListProperty);
            string[] purposes = [ReadString(subjectData, BitstringStatusListConstants.StatusPurposeProperty)];

            using var resolvedList = BitstringStatusListCodec.DecodeList(encodedList, StatusListBitSize.OneBit, Pool);

            return BitstringStatusListValidation.GetStatus(RevocationEntry(index), resolvedList, purposes, TimeProvider.GetUtcNow());
        }

        //Before the trigger the credential reads valid on the pull channel.
        BitstringStatusListStatus before = await CheckStatusAsync(Example4Index, ct).ConfigureAwait(false);
        Assert.IsTrue(before.IsValid, "The credential must read valid before revocation.");

        //The single trigger: the issuer revokes the credential through the seam, fanning out to both
        //channels exactly as a deployment would compose them.
        UpdateCredentialStatusesDelegate revoke = async (changes, token) =>
        {
            //Channel 1 (pull): flip every change's bit, then re-sign and republish the list once.
            foreach(CredentialStatusChange change in changes)
            {
                statusList[change.Entry.StatusListIndex] = change.NewStatus;
            }

            publishedCredential = await PublishAsync(token).ConfigureAwait(false);

            //Channel 2 (push): emit a CAEP credential-change SET about the revoked credential.
            var credentialChange = new CaepCredentialChangeEvent
            {
                CredentialType = CaepCredentialTypeValues.VerifiableCredential,
                ChangeType = CaepChangeTypeValues.Revoke,
                Common = new CaepEventClaims
                {
                    EventTimestamp = TimeProvider.GetUtcNow(),
                    InitiatingEntity = CaepInitiatingEntityValues.Admin,
                    ReasonAdmin = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["en"] = "Status list bit flipped to revoked."
                    }
                }
            };

            string set = await SecurityEventTokenIssuance.IssueAsync(
                Issuer,
                [ReceiverAudience],
                jwtId: Guid.NewGuid().ToString("N"),
                issuedAt: TimeProvider.GetUtcNow(),
                [credentialChange.ToSecurityEvent()],
                issuerPrivate,
                TestSetup.Base64UrlEncoder,
                SecurityEventTestJson.HeaderSerializer,
                SecurityEventTestJson.PayloadSerializer,
                Pool,
                token,
                signingKeyId: "status-key-1",
                subjectId: SubjectIdentifier.IssuerSubject(Issuer, RevokedHolderSubject)).ConfigureAwait(false);

            using StringContent setContent = new(set, Encoding.UTF8, WellKnownMediaTypes.Application.SecEventJwt);
            using HttpResponseMessage push = await transmitterClient.PostAsync(new Uri(ssfReceiver.BaseAddress, "/ssf/push"), setContent, token).ConfigureAwait(false);
            Assert.AreEqual(202, (int)push.StatusCode, "The SSF Receiver must accept the credential-change SET.");

            return CredentialStatusUpdateOutcome.Updated;
        };

        CredentialStatusUpdateOutcome outcome = await revoke([new CredentialStatusChange(RevocationEntry(Example4Index), 1)], ct).ConfigureAwait(false);
        Assert.AreEqual(CredentialStatusUpdateOutcome.Updated, outcome);

        //Channel 1: a fresh dereference of the republished list now reads the credential as revoked.
        BitstringStatusListStatus after = await CheckStatusAsync(Example4Index, ct).ConfigureAwait(false);
        Assert.IsFalse(after.IsValid, "The credential must read revoked after the bit flip and republish.");
        Assert.AreEqual((byte)1, after.Status);

        //Channel 2: the SSF Receiver verified a conformant CAEP credential-change SET about the credential.
        Assert.IsNotNull(receivedToken, "The SSF Receiver must have verified the emitted SET.");
        Assert.HasCount(1, receivedToken.Events);
        Assert.IsTrue(CaepEventTypes.IsCredentialChange(receivedToken.Events[0].EventType), "The emitted event must be CAEP credential-change.");

        CaepCredentialChangeEvent? change = CaepCredentialChangeEvent.From(receivedToken.Events[0]);
        Assert.IsNotNull(change);
        Assert.AreEqual(CaepChangeTypeValues.Revoke, change.ChangeType);
        Assert.AreEqual(CaepCredentialTypeValues.VerifiableCredential, change.CredentialType);
        Assert.IsTrue(CaepInteropProfile.IsConformantTransmitterEvent(receivedToken.Events[0]), "The emitted event must satisfy the CAEP Interop Profile.");

        Assert.IsNotNull(receivedToken.SubjectId);
        Assert.AreEqual(RevokedHolderSubject, receivedToken.SubjectId.Members[SubjectIdentifierMemberNames.Sub], "The SET must be about exactly the revoked credential's subject.");
    }


    private static VerifiableCredential BuildStatusListCredential(string encodedList)
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(StatusListCredentialTemplate, CredentialSecuringMaterial.JsonOptions)!;
        credential.CredentialSubject![0].AdditionalData![BitstringStatusListConstants.EncodedListProperty] = encodedList;

        return credential;
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


    private static ReadOnlySpan<byte> SerializeCredential(VerifiableCredential credential) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(credential, CredentialSecuringMaterial.JsonOptions);

    private static ReadOnlySpan<byte> SerializeCredentialHeader(Dictionary<string, object> header) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(header, CredentialSecuringMaterial.JsonOptions);

    private static Dictionary<string, object>? DeserializeCredentialHeader(ReadOnlySpan<byte> headerBytes) =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(headerBytes, CredentialSecuringMaterial.JsonOptions);

    private static VerifiableCredential DeserializeCredential(ReadOnlySpan<byte> credentialBytes) =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(credentialBytes, CredentialSecuringMaterial.JsonOptions)!;
}
