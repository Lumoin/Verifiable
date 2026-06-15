using System.Collections.Generic;
using Verifiable.JsonPointer.Jsonata;
using Verifiable.Vcalm;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// Tests for the W3C VCALM 1.0 §3.6.1 credential-template evaluation seam
/// (<see cref="VcalmTemplateEvaluatorRegistry"/>): a <c>jsonata</c>-typed credential template is
/// evaluated through the seam to the expected credential body by the minimal in-repo engine, and an
/// application can register a replacement evaluator for <c>jsonata</c> to supersede the built-in one
/// (the integration point a deployment uses to wire the full engine from <c>Lumoin.Veritas</c>).
/// </summary>
[TestClass]
internal sealed class VcalmTemplateEvaluatorTests
{
    //Builds an input object value from a set of members, preserving order.
    private static JsonataValue Variables(params (string Key, JsonataValue Value)[] members)
    {
        var map = new Dictionary<string, JsonataValue>(StringComparer.Ordinal);
        foreach((string key, JsonataValue value) in members)
        {
            map[key] = value;
        }

        return JsonataValue.FromObject(map);
    }


    [TestMethod]
    public void DefaultRegistryWiresJsonataAndLiteral()
    {
        var registry = new VcalmTemplateEvaluatorRegistry();

        Assert.IsTrue(registry.IsRegistered(VcalmTemplateEvaluatorRegistry.JsonataTemplateType));
        Assert.IsTrue(registry.IsRegistered(VcalmTemplateEvaluatorRegistry.LiteralTemplateType));
    }


    [TestMethod]
    public void JsonataTemplateEvaluatesThroughSeamToCredentialBody()
    {
        //VCALM Appendix-D Example 27 (Minimal Credential Template) shape: the §3.6.1 'template' body
        //maps the 'name' variable into the credential body.
        var template = new VcalmCredentialTemplate
        {
            TemplateType = VcalmTemplateEvaluatorRegistry.JsonataTemplateType,
            Template =
                "{\"@context\": [\"https://www.w3.org/ns/credentials/v2\"]," +
                "\"type\": [\"VerifiableCredential\",\"ExampleNameCredential\"]," +
                "\"credentialSubject\": {\"name\": name}}"
        };

        var registry = new VcalmTemplateEvaluatorRegistry();
        JsonataValue body = registry.Evaluate(template, Variables(("name", JsonataValue.FromString("Example Name"))));

        IReadOnlyDictionary<string, JsonataValue> credential = body.AsObject();
        Assert.AreEqual("https://www.w3.org/ns/credentials/v2", credential["@context"].AsArray()[0].AsString());
        Assert.AreEqual("VerifiableCredential", credential["type"].AsArray()[0].AsString());
        Assert.AreEqual("Example Name", credential["credentialSubject"].AsObject()["name"].AsString());
    }


    [TestMethod]
    public void RegisteredReplacementSupersedesBuiltInJsonataEvaluator()
    {
        var registry = new VcalmTemplateEvaluatorRegistry();

        //A deployment registers its own evaluator for the jsonata type — here a stand-in that ignores
        //the template body and returns a fixed marker, proving the seam routes to the replacement
        //rather than the minimal in-repo engine.
        var replacement = JsonataValue.FromObject(
            new Dictionary<string, JsonataValue>(StringComparer.Ordinal) { ["evaluatedBy"] = JsonataValue.FromString("veritas") });
        registry.Register(
            VcalmTemplateEvaluatorRegistry.JsonataTemplateType,
            (_, _) => replacement);

        var template = new VcalmCredentialTemplate
        {
            TemplateType = VcalmTemplateEvaluatorRegistry.JsonataTemplateType,
            Template = "{ \"name\": name }"
        };

        JsonataValue body = registry.Evaluate(template, Variables(("name", JsonataValue.FromString("ignored"))));

        Assert.AreEqual("veritas", body.AsObject()["evaluatedBy"].AsString());
    }


    [TestMethod]
    public void UnregisteredTemplateTypeRaisesKeyNotFound()
    {
        var registry = new VcalmTemplateEvaluatorRegistry();
        var template = new VcalmCredentialTemplate
        {
            TemplateType = "unsupported-type",
            Template = "{}"
        };

        Assert.Throws<KeyNotFoundException>(() => registry.Evaluate(template, JsonataValue.Null));
    }


    [TestMethod]
    public void IntegrationDefaultsTemplateEvaluatorsRegistry()
    {
        var integration = new VcalmIntegration();

        Assert.IsNotNull(integration.VcalmTemplateEvaluators);
        Assert.IsTrue(integration.VcalmTemplateEvaluators.IsRegistered(VcalmTemplateEvaluatorRegistry.JsonataTemplateType));
    }


    [TestMethod]
    public void LiteralTemplateEvaluatesConstantBody()
    {
        var registry = new VcalmTemplateEvaluatorRegistry();
        var template = new VcalmCredentialTemplate
        {
            TemplateType = VcalmTemplateEvaluatorRegistry.LiteralTemplateType,
            Template = "{ \"type\": [\"VerifiableCredential\"] }"
        };

        JsonataValue body = registry.Evaluate(template, JsonataValue.Null);

        Assert.AreEqual("VerifiableCredential", body.AsObject()["type"].AsArray()[0].AsString());
    }
}
