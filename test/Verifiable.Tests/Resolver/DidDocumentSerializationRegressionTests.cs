using Verifiable.Core.Model.Did;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Characterization tests that pin the current <see cref="DidDocument"/> deserialize→serialize behaviour across
/// the full member surface (<c>@context</c>, <c>id</c>, <c>alsoKnownAs</c>, <c>controller</c>,
/// <c>verificationMethod</c> with embedded keys, the verification-relationship reference arrays, and
/// <c>service</c>). They form the regression safety net for the upcoming manual <c>DidDocument</c> converter:
/// the converter MUST reproduce exactly the structural roundtrip these assert today.
/// </summary>
[TestClass]
internal sealed class DidDocumentSerializationRegressionTests
{
    /// <summary>The shared serialization options (source-gen + the DID member converters).</summary>
    private static System.Text.Json.JsonSerializerOptions Options => TestSetup.DefaultSerializationOptions;

    //A full-shaped W3C DID document touching every member converter: two @context entries, a recognized id
    //(did:web → WebDidMethod), alsoKnownAs, a two-element controller (stable array form), a verificationMethod
    //with an embedded JsonWebKey2020 publicKeyJwk, the five relationship arrays as #fragment references, and a
    //service with its own extra members. Written in the serializer's canonical shape so the roundtrip is the
    //identity on structure.
    private const string FullDidDocument =
        """
        {
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
          ],
          "id": "did:web:example.com",
          "alsoKnownAs": [
            "did:web:alt.example.com"
          ],
          "controller": [
            "did:web:example.com",
            "did:web:controller.example.com"
          ],
          "verificationMethod": [
            {
              "id": "did:web:example.com#key-0",
              "type": "JsonWebKey2020",
              "controller": "did:web:example.com",
              "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "lZq_V0eF2PaFk07maitC6e-cMcCkYxkX1ugKRzFgodQ"
              }
            }
          ],
          "authentication": [
            "did:web:example.com#key-0"
          ],
          "assertionMethod": [
            "did:web:example.com#key-0"
          ],
          "keyAgreement": [
            "did:web:example.com#key-0"
          ],
          "capabilityInvocation": [
            "did:web:example.com#key-0"
          ],
          "capabilityDelegation": [
            "did:web:example.com#key-0"
          ],
          "service": [
            {
              "id": "did:web:example.com#whois",
              "type": "LinkedVerifiablePresentation",
              "serviceEndpoint": "https://example.com/whois"
            }
          ]
        }
        """;


    /// <summary>The full-shaped document survives a deserialize→serialize cycle with its structure intact.</summary>
    [TestMethod]
    public void FullDidDocumentRoundtripsStructurally()
    {
        var (deserialized, reserialized) = JsonSerializationUtilities.PerformSerializationCycle<DidDocument>(FullDidDocument, Options);

        Assert.IsNotNull(deserialized);
        Assert.IsTrue(
            JsonSerializationUtilities.CompareJsonElements(FullDidDocument, reserialized),
            $"DidDocument roundtrip changed structure. Reserialized: {reserialized}");
    }


    /// <summary>The roundtrip is idempotent: a second cycle reproduces the first (the canonical form is stable).</summary>
    [TestMethod]
    public void DidDocumentRoundtripIsIdempotent()
    {
        var (_, firstPass) = JsonSerializationUtilities.PerformSerializationCycle<DidDocument>(FullDidDocument, Options);
        var (_, secondPass) = JsonSerializationUtilities.PerformSerializationCycle<DidDocument>(firstPass, Options);

        Assert.IsTrue(
            JsonSerializationUtilities.CompareJsonElements(firstPass, secondPass),
            $"DidDocument roundtrip is not idempotent.\nFirst: {firstPass}\nSecond: {secondPass}");
    }


    /// <summary>The recognized <c>id</c> deserializes to its method-specific type (here did:web → WebDidMethod).</summary>
    [TestMethod]
    public void RecognizedIdDeserializesToMethodType()
    {
        var deserialized = JsonSerializerExtensions.Deserialize<DidDocument>(FullDidDocument, Options);

        Assert.IsNotNull(deserialized);
        Assert.IsNotNull(deserialized.Id);
        Assert.AreEqual("did:web:example.com", (string)deserialized.Id);
    }


    /// <summary>
    /// A did:key document with a scalar-string <c>@context</c> (<see cref="Verifiable.Json.Converters.DidDocumentConverter"/>
    /// delegates <c>@context</c> to the same <see cref="Verifiable.Json.Converters.JsonLdContextConverter"/> regardless of DID
    /// method, so this proves the converter's scalar form survives a <see cref="DidDocument"/>-level
    /// roundtrip, not just a bare <see cref="Verifiable.Core.Model.Common.Context"/> roundtrip).
    /// </summary>
    private const string DidKeyScalarContextDocument =
        """
        {
          "@context": "https://www.w3.org/ns/did/v1",
          "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        }
        """;

    /// <summary>
    /// A did:webvh document whose <c>@context</c> array mixes an IRI with an inline definition,
    /// proving that shape survives a <see cref="DidDocument"/>-level roundtrip through the same converter.
    /// </summary>
    private const string DidWebvhArrayWithInlineDefinitionContextDocument =
        """
        {
          "@context": [
            "https://www.w3.org/ns/did/v1",
            {
              "@vocab": "https://example.com/"
            }
          ],
          "id": "did:webvh:QmExample:example.com"
        }
        """;


    /// <summary>
    /// A did:key document's scalar-string <c>@context</c> survives a deserialize→serialize cycle unchanged.
    /// </summary>
    [TestMethod]
    public void DidKeyScalarContextRoundtripsStructurally()
    {
        var (deserialized, reserialized) = JsonSerializationUtilities.PerformSerializationCycle<DidDocument>(DidKeyScalarContextDocument, Options);

        Assert.IsNotNull(deserialized);
        Assert.IsTrue(
            JsonSerializationUtilities.CompareJsonElements(DidKeyScalarContextDocument, reserialized),
            $"did:key scalar @context roundtrip changed structure. Reserialized: {reserialized}");
    }


    /// <summary>
    /// A did:webvh document's array <c>@context</c> mixing an IRI and an inline definition survives a
    /// deserialize→serialize cycle unchanged.
    /// </summary>
    [TestMethod]
    public void DidWebvhArrayWithInlineDefinitionContextRoundtripsStructurally()
    {
        var (deserialized, reserialized) = JsonSerializationUtilities.PerformSerializationCycle<DidDocument>(DidWebvhArrayWithInlineDefinitionContextDocument, Options);

        Assert.IsNotNull(deserialized);
        Assert.IsTrue(
            JsonSerializationUtilities.CompareJsonElements(DidWebvhArrayWithInlineDefinitionContextDocument, reserialized),
            $"did:webvh array-with-inline-definition @context roundtrip changed structure. Reserialized: {reserialized}");
    }
}
