using System.Text.Json;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Securing-state tests for the presentation side of the hand-written converters:
/// a present <c>proof</c> member discriminates the embedded-secured
/// <see cref="DataIntegritySecuredPresentation"/> from the unsecured
/// <see cref="VerifiablePresentation"/>, the enveloped types round-trip with their
/// VC-DM 2.0-mandated <c>@context</c>, and the standalone
/// <see cref="EnvelopedVerifiablePresentation"/> wire object (VC-DM 2.0 §4.13)
/// round-trips through <see cref="Verifiable.Json.Converters.EnvelopedVerifiablePresentationConverter"/>.
/// </summary>
[TestClass]
internal sealed class PresentationSecuringConverterTests
{
    private static JsonSerializerOptions Options { get; } = TestSetup.DefaultSerializationOptions;


    /// <summary>
    /// A presentation without a <c>proof</c> member is the unsecured base type; one
    /// carrying <c>proof</c> deserializes as the embedded-secured subtype even when the
    /// requested type is the open base, so the proof is never silently dropped.
    /// </summary>
    [TestMethod]
    public void ProofMemberDiscriminatesTheSecuredPresentation()
    {
        string unsecuredJson = /*lang=json,strict*/ """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "holder": "did:example:holder"
            }
            """;

        var unsecured = JsonSerializerExtensions.Deserialize<VerifiablePresentation>(unsecuredJson, Options)!;
        Assert.AreEqual(typeof(VerifiablePresentation), unsecured.GetType(),
            "A presentation without a proof member is the unsecured base type.");

        string securedJson = /*lang=json,strict*/ """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "holder": "did:example:holder",
                "proof": {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "created": "2024-06-15T12:00:00Z",
                    "verificationMethod": "did:example:holder#key-1",
                    "proofPurpose": "authentication",
                    "challenge": "challenge-1",
                    "domain": "verifier.example",
                    "proofValue": "z58DAdFfa9SkqZMVPxAQp"
                }
            }
            """;

        var secured = JsonSerializerExtensions.Deserialize<VerifiablePresentation>(securedJson, Options)!;
        Assert.IsInstanceOfType<DataIntegritySecuredPresentation>(secured,
            "A present proof member upcasts to the embedded-secured presentation.");

        var proof = ((DataIntegritySecuredPresentation)secured).Proof![0];
        Assert.AreEqual("authentication", proof.ProofPurpose);
        Assert.AreEqual("challenge-1", proof.Challenge);
        Assert.IsTrue(DataIntegrityProof.DomainSetEquals(proof.Domain, ["verifier.example"]),
            "The scalar wire domain parses into the one-element set form.");

        //The round trip emits the proof member again.
        string reserialized = JsonSerializerExtensions.Serialize(secured, Options);
        using var document = JsonDocument.Parse(reserialized);
        Assert.IsTrue(document.RootElement.TryGetProperty("proof", out _),
            "The secured presentation's proof member must round-trip.");
    }


    /// <summary>
    /// The enveloped credential carried inside a presentation round-trips its
    /// <c>@context</c> — VC-DM 2.0 mandates the member on the enveloped object itself.
    /// </summary>
    [TestMethod]
    public void EnvelopedCredentialInsidePresentationRoundTripsContext()
    {
        string json = /*lang=json,strict*/ """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "verifiableCredential": [{
                    "@context": "https://www.w3.org/ns/credentials/v2",
                    "id": "data:application/vc+sd-jwt,QzVjV...RMjU",
                    "type": "EnvelopedVerifiableCredential"
                }]
            }
            """;

        var presentation = JsonSerializerExtensions.Deserialize<VerifiablePresentation>(json, Options)!;
        var enveloped = presentation.EnvelopedVerifiableCredential![0];

        Assert.IsNotNull(enveloped.Context, "VC-DM 2.0: the enveloped object's @context MUST be present.");
        Assert.StartsWith("data:application/vc+sd-jwt,", enveloped.Id!);

        string reserialized = JsonSerializerExtensions.Serialize(presentation, Options);
        using var document = JsonDocument.Parse(reserialized);
        var element = document.RootElement.GetProperty("verifiableCredential")[0];
        Assert.IsTrue(element.TryGetProperty("@context", out _),
            "The enveloped object's @context must round-trip onto the wire.");
    }


    /// <summary>
    /// The standalone enveloped presentation (VC-DM 2.0 §4.13: <c>@context</c> MUST be
    /// present, <c>id</c> MUST be a <c>data:</c> URL carrying the secured presentation,
    /// <c>type</c> MUST be <c>EnvelopedVerifiablePresentation</c>) round-trips.
    /// </summary>
    [TestMethod]
    public void EnvelopedPresentationRoundTrips()
    {
        string json = /*lang=json,strict*/ """
            {
                "@context": "https://www.w3.org/ns/credentials/v2",
                "id": "data:application/vp+jwt,eyJraWQiO.zhwGfQ",
                "type": "EnvelopedVerifiablePresentation"
            }
            """;

        var enveloped = JsonSerializerExtensions.Deserialize<EnvelopedVerifiablePresentation>(json, Options)!;

        Assert.IsNotNull(enveloped.Context);
        Assert.StartsWith("data:application/vp+jwt,", enveloped.Id!);
        Assert.Contains(CredentialConstants.EnvelopedVerifiablePresentationType, enveloped.Type!);

        string reserialized = JsonSerializerExtensions.Serialize(enveloped, Options);
        using var document = JsonDocument.Parse(reserialized);
        Assert.IsTrue(document.RootElement.TryGetProperty("@context", out _));
        Assert.AreEqual("data:application/vp+jwt,eyJraWQiO.zhwGfQ", document.RootElement.GetProperty("id").GetString());
    }


    /// <summary>
    /// Building the enveloped presentation from a model instance emits the three
    /// VC-DM 2.0-mandated members.
    /// </summary>
    [TestMethod]
    public void EnvelopedPresentationBuildsFromModel()
    {
        var enveloped = new EnvelopedVerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Id = "data:application/vp+jwt,abc.def.ghi",
            Type = [CredentialConstants.EnvelopedVerifiablePresentationType]
        };

        string json = JsonSerializerExtensions.Serialize(enveloped, Options);
        using var document = JsonDocument.Parse(json);

        Assert.IsTrue(document.RootElement.TryGetProperty("@context", out _),
            "@context MUST be present on the enveloped presentation object.");
        Assert.StartsWith("data:", document.RootElement.GetProperty("id").GetString()!);
        Assert.AreEqual(CredentialConstants.EnvelopedVerifiablePresentationType,
            document.RootElement.GetProperty("type")[0].GetString());
    }
}
