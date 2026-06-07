using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

[JsonSerializable(typeof(VerifiableCredential))]
[JsonSerializable(typeof(DataIntegritySecuredCredential))]
[JsonSerializable(typeof(VerifiablePresentation))]
internal partial class VerifiableCredentialConverterTestsJsonContext: JsonSerializerContext { }

/// <summary>
/// Tests for the hand-written <see cref="Verifiable.Json.Converters.VerifiableCredentialConverter"/>
/// and <see cref="Verifiable.Json.Converters.VerifiablePresentationConverter"/>: open-world
/// <c>AdditionalData</c> round-tripping, securing-state discrimination (the unsecured
/// <see cref="VerifiableCredential"/> versus the embedded-secured
/// <see cref="DataIntegritySecuredCredential"/>), and the heterogeneous
/// <c>verifiableCredential</c> array.
/// </summary>
[TestClass]
internal sealed class VerifiableCredentialConverterTests
{
    private static JsonSerializerOptions Options { get; } = TestSetup.DefaultSerializationOptions;


    /// <summary>
    /// A root-level member the typed model does not name must round-trip through
    /// <see cref="VerifiableCredential.AdditionalData"/>, flattened at the credential root
    /// (not nested under an <c>additionalData</c> object). Without a proof member the
    /// credential deserializes as the unsecured base type.
    /// </summary>
    [TestMethod]
    public void BaseCredentialRoundTripPreservesRootExtensionData()
    {
        string json = /*lang=json,strict*/ """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential"],
                "issuer": "did:example:issuer",
                "credentialSubject": { "id": "did:example:subject" },
                "customExtension": { "foo": "bar", "count": 42 }
            }
            """;

        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(json, Options)!;

        Assert.AreEqual(typeof(VerifiableCredential), credential.GetType(), "A credential without a proof member is the unsecured base type.");
        Assert.IsNotNull(credential.AdditionalData);
        Assert.IsTrue(credential.AdditionalData.ContainsKey("customExtension"), "Unknown root members must land in AdditionalData.");

        string reserialized = JsonSerializerExtensions.Serialize(credential, Options);

        using var document = JsonDocument.Parse(reserialized);
        Assert.IsTrue(document.RootElement.TryGetProperty("customExtension", out var extension), "AdditionalData must flatten at the credential root.");
        Assert.AreEqual("bar", extension.GetProperty("foo").GetString());
        Assert.AreEqual(42, extension.GetProperty("count").GetInt32());
        Assert.IsFalse(document.RootElement.TryGetProperty("additionalData", out _), "The bucket must not surface as a nested 'additionalData' member.");
    }


    /// <summary>
    /// A credential carrying a <c>proof</c> member deserializes as
    /// <see cref="DataIntegritySecuredCredential"/> even when the requested type is the open
    /// <see cref="VerifiableCredential"/>, so the proof is never silently dropped.
    /// </summary>
    [TestMethod]
    public void CredentialWithProofMemberUpcastsToSecured()
    {
        string json = /*lang=json,strict*/ """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential"],
                "issuer": "did:example:issuer",
                "credentialSubject": { "id": "did:example:subject" },
                "proof": [
                    {
                        "type": "DataIntegrityProof",
                        "cryptosuite": "eddsa-jcs-2022",
                        "proofPurpose": "assertionMethod",
                        "verificationMethod": "did:example:issuer#key-1",
                        "proofValue": "zABC"
                    }
                ]
            }
            """;

        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(json, Options)!;

        Assert.IsInstanceOfType<DataIntegritySecuredCredential>(credential);
        var secured = (DataIntegritySecuredCredential)credential;
        Assert.IsNotNull(secured.Proof);
        Assert.HasCount(1, secured.Proof);
        Assert.AreEqual("eddsa-jcs-2022", secured.Proof[0].Cryptosuite?.CryptosuiteName);
    }


    /// <summary>
    /// A single-object <c>proof</c> (the non-chain form Data Integrity also permits) is
    /// normalized to a one-element proof list.
    /// </summary>
    [TestMethod]
    public void CredentialWithSingleProofObjectIsNormalizedToList()
    {
        string json = /*lang=json,strict*/ """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential"],
                "issuer": "did:example:issuer",
                "credentialSubject": { "id": "did:example:subject" },
                "proof": {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "proofPurpose": "assertionMethod",
                    "verificationMethod": "did:example:issuer#key-1",
                    "proofValue": "zABC"
                }
            }
            """;

        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(json, Options)!;

        Assert.IsInstanceOfType<DataIntegritySecuredCredential>(credential);
        Assert.HasCount(1, ((DataIntegritySecuredCredential)credential).Proof!);
    }


    /// <summary>
    /// A presentation's single <c>verifiableCredential</c> array is split on read into the
    /// JSON-LD credential list and the enveloping-secured credential list (discriminated by
    /// the <c>EnvelopedVerifiableCredential</c> type and the <c>data:</c> URL id), and both
    /// are merged back into the single array on write.
    /// </summary>
    [TestMethod]
    public void PresentationRoundTripsHeterogeneousCredentialArray()
    {
        string json = /*lang=json,strict*/ """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "verifiableCredential": [
                    {
                        "@context": ["https://www.w3.org/ns/credentials/v2"],
                        "type": ["VerifiableCredential"],
                        "issuer": "did:example:issuer",
                        "credentialSubject": { "id": "did:example:subject" }
                    },
                    {
                        "id": "data:application/vc+jwt,eyJhbGciOiJFZERTQSJ9.eyJ9.c2ln",
                        "type": "EnvelopedVerifiableCredential"
                    }
                ]
            }
            """;

        var presentation = JsonSerializerExtensions.Deserialize<VerifiablePresentation>(json, Options)!;

        Assert.IsNotNull(presentation.VerifiableCredential);
        Assert.HasCount(1, presentation.VerifiableCredential);
        Assert.IsNotNull(presentation.EnvelopedVerifiableCredential);
        Assert.HasCount(1, presentation.EnvelopedVerifiableCredential);
        Assert.StartsWith("data:", presentation.EnvelopedVerifiableCredential[0].Id);

        string reserialized = JsonSerializerExtensions.Serialize(presentation, Options);

        using var document = JsonDocument.Parse(reserialized);
        Assert.IsTrue(document.RootElement.TryGetProperty("verifiableCredential", out var array));
        Assert.AreEqual(2, array.GetArrayLength(), "Both lists must merge into the single verifiableCredential array.");
        Assert.IsFalse(document.RootElement.TryGetProperty("envelopedVerifiableCredential", out _), "The enveloped list must not surface as a separate member.");
    }


    /// <summary>
    /// The converter composes with a downstream-supplied combined type-info resolver (the
    /// setup a consuming application uses), and arbitrary nested extension claims survive the
    /// round-trip through <see cref="VerifiableCredential.AdditionalData"/>.
    /// </summary>
    [TestMethod]
    public void CredentialExtensionDataSurvivesUnderCombinedResolver()
    {
        var options = new JsonSerializerOptions();
        options.ApplyVerifiableDefaults();
        options.TypeInfoResolver = JsonTypeInfoResolver.Combine(
            VerifiableJsonContext.Default,
            VerifiableCredentialConverterTestsJsonContext.Default);

        string json = /*lang=json,strict*/ """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential"],
                "issuer": "did:example:issuer",
                "credentialSubject": { "id": "did:example:subject" },
                "evidenceTrail": ["step-one", "step-two"],
                "riskScore": 7
            }
            """;

        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(json, options)!;
        string reserialized = JsonSerializerExtensions.Serialize(credential, options);

        using var document = JsonDocument.Parse(reserialized);
        Assert.IsTrue(document.RootElement.TryGetProperty("evidenceTrail", out var trail));
        Assert.AreEqual(2, trail.GetArrayLength());
        Assert.AreEqual("step-one", trail[0].GetString());
        Assert.IsTrue(document.RootElement.TryGetProperty("riskScore", out var risk));
        Assert.AreEqual(7, risk.GetInt32());
    }
}
