using System.Collections.Immutable;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// Conformance tests for the schema-validation seam: the
/// <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>
/// tri-state, the <see href="https://www.w3.org/TR/vcalm-1.0/">VCALM 1.0</see> §3.6.1
/// <c>presentationSchema</c> envelope, and the registry dispatch.
/// </summary>
[TestClass]
internal sealed class VcalmSchemaValidationTests
{
    /// <summary>The test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    private static string EmailSchema { get; } = /*lang=json,strict*/ """
        {
          "$id": "https://example.com/schemas/email.json",
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "type": "object",
          "properties": {
            "credentialSubject": {
              "type": "object",
              "properties": { "emailAddress": { "type": "string" } },
              "required": ["emailAddress"]
            }
          },
          "required": ["credentialSubject"]
        }
        """;

    private static string ConformingDocument { get; } = /*lang=json,strict*/ """
        { "credentialSubject": { "emailAddress": "subject@example.com" } }
        """;

    private static string ViolatingDocument { get; } = /*lang=json,strict*/ """
        { "credentialSubject": { "givenName": "JANE" } }
        """;


    /// <summary>
    /// A conforming document evaluates Success.
    /// See <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ConformingDocumentEvaluatesSuccess()
    {
        var validate = SchemaValidationTestUtilities.CreateVeritasSchemaValidator();

        var result = await validate(EmailSchema, ConformingDocument, TestContext.CancellationToken);

        Assert.AreEqual(CredentialSchemaValidationOutcome.Success, result.Outcome);
        Assert.IsEmpty(result.Errors);
    }


    /// <summary>
    /// A violating document evaluates Failure with pointer-located errors.
    /// See <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ViolatingDocumentEvaluatesFailureWithLocatedErrors()
    {
        var validate = SchemaValidationTestUtilities.CreateVeritasSchemaValidator();

        var result = await validate(EmailSchema, ViolatingDocument, TestContext.CancellationToken);

        Assert.AreEqual(CredentialSchemaValidationOutcome.Failure, result.Outcome);
        Assert.IsNotEmpty(result.Errors);
        Assert.Contains("/credentialSubject", result.Errors[0].KeywordLocation, "The failing keyword must be located inside the schema's credentialSubject subschema.");
    }


    /// <summary>
    /// A schema declaring an unsupported version MUST evaluate Indeterminate.
    /// See <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>:
    /// "Implementers MUST return this outcome when they encounter a schema whose version they do
    /// not support."
    /// </summary>
    [TestMethod]
    public async Task UnsupportedSchemaVersionEvaluatesIndeterminate()
    {
        var validate = SchemaValidationTestUtilities.CreateVeritasSchemaValidator();
        string draft7Schema = /*lang=json,strict*/ """
            { "$schema": "http://json-schema.org/draft-07/schema#", "type": "object" }
            """;

        var result = await validate(draft7Schema, ConformingDocument, TestContext.CancellationToken);

        Assert.AreEqual(CredentialSchemaValidationOutcome.Indeterminate, result.Outcome);
    }


    /// <summary>
    /// The registry dispatches by mechanism type and reports registration; an unregistered type
    /// throws on direct validation, and the callers treat it as unevaluable
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/">VCALM 1.0</see> §3.6.1 admits alternate
    /// mechanism types beyond the specification's scope).
    /// </summary>
    [TestMethod]
    public async Task RegistryDispatchesByMechanismType()
    {
        var registry = SchemaValidationTestUtilities.CreateSchemaRegistry();

        Assert.IsTrue(registry.IsRegistered(VcalmSchemaValidatorRegistry.JsonSchemaType));
        Assert.IsFalse(registry.IsRegistered("VendorMechanism"));

        var result = await registry.ValidateAsync(
            VcalmSchemaValidatorRegistry.JsonSchemaType, EmailSchema, ConformingDocument, TestContext.CancellationToken);
        Assert.AreEqual(CredentialSchemaValidationOutcome.Success, result.Outcome);

        await Assert.ThrowsExactlyAsync<KeyNotFoundException>(async () =>
            await registry.ValidateAsync("VendorMechanism", EmailSchema, ConformingDocument, TestContext.CancellationToken));
    }


    /// <summary>
    /// The §3.6.1 <c>presentationSchema</c> envelope parses to its mechanism type and inline
    /// <c>jsonSchema</c> text; the type MUST be a string, and a missing type is malformed.
    /// See <see href="https://www.w3.org/TR/vcalm-1.0/">VCALM 1.0 §3.6.1</see>.
    /// </summary>
    [TestMethod]
    public void PresentationSchemaEnvelopeParsesTypeAndInlineSchema()
    {
        var parse = VcalmJsonParsing.CreatePresentationSchemaParser();

        var jsonSchemaEnvelope = parse("""{ "type": "JsonSchema", "jsonSchema": { "type": "object" } }""");
        Assert.IsNotNull(jsonSchemaEnvelope);
        Assert.AreEqual(VcalmSchemaValidatorRegistry.JsonSchemaType, jsonSchemaEnvelope.Type);
        Assert.IsNotNull(jsonSchemaEnvelope.SchemaJson);
        Assert.Contains("\"object\"", jsonSchemaEnvelope.SchemaJson);

        var alternateEnvelope = parse("""{ "type": "VendorMechanism", "vendorPayload": true }""");
        Assert.IsNotNull(alternateEnvelope);
        Assert.AreEqual("VendorMechanism", alternateEnvelope.Type);
        Assert.IsNull(alternateEnvelope.SchemaJson);

        Assert.IsNull(parse("""{ "jsonSchema": { } }"""), "A missing type is malformed (§3.6.1: type is required).");
        Assert.IsNull(parse("not json"), "A non-JSON envelope is malformed.");
        Assert.IsNull(parse("""["JsonSchema"]"""), "A non-object envelope is malformed.");
    }


    /// <summary>
    /// An embedded-map resolver returns the seeded schema text and <see langword="null"/> for an
    /// unknown id, which evaluation reports as Indeterminate rather than asserting conformance.
    /// </summary>
    [TestMethod]
    public async Task EmbeddedSchemaResolverResolvesSeededIdsOnly()
    {
        var resolve = SchemaValidationTestUtilities.CreateEmbeddedSchemaResolver(
            new Dictionary<string, string> { ["https://example.com/schemas/email.json"] = EmailSchema });
        var context = new ExchangeContext();

        string? resolved = await resolve("https://example.com/schemas/email.json", context, TestContext.CancellationToken);
        Assert.IsNotNull(resolved);

        string? missing = await resolve("https://example.com/schemas/unknown.json", context, TestContext.CancellationToken);
        Assert.IsNull(missing);
    }
}
