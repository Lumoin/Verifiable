using Lumoin.Veritas.Jsonata;
using System.Text;
using System.Text.Json;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// The Lumoin.Veritas JSONata engine registered on the W3C VCALM 1.0 §3.6.1 credential-template
/// seam, evaluating through the byte-typed <see cref="VcalmTemplateEvaluator"/>: the Appendix D
/// template shape, the <c>$name</c> variable convention carried by the engine's caller bindings, the
/// JSONata reference semantics for null and undefined, the integer round-trip through the one
/// JSONata number type, and the engine's own bounds.
/// See <see href="https://www.w3.org/TR/vcalm-1.0/">VCALM 1.0 §3.6.1</see>.
/// </summary>
[TestClass]
internal sealed class VcalmVeritasTemplateEvaluatorTests
{
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>Builds a §3.6.1 <c>jsonata</c> credential template carrying <paramref name="template"/> as its source.</summary>
    /// <param name="template">The template's JSONata source text.</param>
    /// <returns>The <c>jsonata</c>-typed credential template.</returns>
    private static VcalmCredentialTemplate JsonataTemplate(string template) => new()
    {
        TemplateType = VcalmTemplateEvaluatorRegistry.JsonataTemplateType,
        Template = template
    };


    /// <summary>
    /// Renders a template through the Veritas-wired registry and hands back the rendered credential
    /// body as a parsed document; the pooled result buffer is decoded to a string (and disposed)
    /// before parsing, so the document owns independent memory.
    /// </summary>
    /// <param name="registry">The Veritas-wired registry to evaluate through.</param>
    /// <param name="template">The credential template to evaluate.</param>
    /// <param name="variablesJson">The exchange variables, as UTF-8 JSON text.</param>
    /// <returns>The rendered credential body, parsed for assertion.</returns>
    private static JsonDocument Render(
        VcalmTemplateEvaluatorRegistry registry, VcalmCredentialTemplate template, string variablesJson)
    {
        VcalmTemplateEvaluationResult result = registry.Evaluate(
            template, Encoding.UTF8.GetBytes(variablesJson), Pool, CancellationToken.None);
        Assert.IsTrue(result.IsSuccess, result.FailureDetail);
        using PooledMemory? rendered = result.Rendered;
        Assert.IsNotNull(rendered);

        return JsonDocument.Parse(Encoding.UTF8.GetString(rendered.AsReadOnlySpan()));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#example-minimal-credential-template">VCALM 1.0
    /// Appendix D.1 Example 29 (Minimal Credential Template)</see> shape: the §3.6.1 <c>template</c>
    /// body maps the <c>name</c> variable into the credential body.
    /// </summary>
    [TestMethod]
    public void VeritasEngineRendersAppendixDTemplate()
    {
        var template = JsonataTemplate(
            "{\"@context\": [\"https://www.w3.org/ns/credentials/v2\"]," +
            "\"type\": [\"VerifiableCredential\",\"ExampleNameCredential\"]," +
            "\"credentialSubject\": {\"name\": name}}");

        using JsonDocument body = Render(
            JsonataTestUtilities.CreateVeritasTemplateRegistry(), template, "{\"name\":\"Example Name\"}");

        JsonElement root = body.RootElement;
        Assert.AreEqual("https://www.w3.org/ns/credentials/v2", root.GetProperty("@context")[0].GetString());
        Assert.AreEqual("VerifiableCredential", root.GetProperty("type")[0].GetString());
        Assert.AreEqual("Example Name", root.GetProperty("credentialSubject").GetProperty("name").GetString());
    }


    /// <summary>
    /// The <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see>
    /// <c>$name</c> variable convention resolves through the engine's caller bindings (each top-level
    /// exchange variable bound under its bare name), and the bare-path form resolves through the
    /// input document — both spellings reach the same variable.
    /// </summary>
    [TestMethod]
    public void VariablesResolveAsBindingsAndAsInputPaths()
    {
        VcalmTemplateEvaluatorRegistry registry = JsonataTestUtilities.CreateVeritasTemplateRegistry();
        const string variables = "{\"name\":\"Example Name\"}";

        using JsonDocument bound = Render(registry, JsonataTemplate("{ \"name\": $name }"), variables);
        using JsonDocument pathed = Render(registry, JsonataTemplate("{ \"name\": name }"), variables);

        Assert.AreEqual("Example Name", bound.RootElement.GetProperty("name").GetString(), "$name resolves through the bindings.");
        Assert.AreEqual("Example Name", pathed.RootElement.GetProperty("name").GetString(), "The bare path resolves through the input.");
    }


    /// <summary>
    /// The Veritas engine evaluates the full JSONata surface, including function calls, over a
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see> credential
    /// template — the point of wiring a real engine behind the seam instead of a minimal substitute.
    /// </summary>
    [TestMethod]
    public void VeritasEngineEvaluatesFunctionCalls()
    {
        using JsonDocument body = Render(
            JsonataTestUtilities.CreateVeritasTemplateRegistry(),
            JsonataTemplate("{ \"shout\": $uppercase($name) }"),
            "{\"name\":\"example\"}");

        Assert.AreEqual("EXAMPLE", body.RootElement.GetProperty("shout").GetString());
    }


    /// <summary>
    /// JSON <c>null</c> is a value: an explicitly null exchange variable survives into the
    /// constructed credential body as a null member, per the JSONata reference semantics the engine
    /// implements. See <see href="https://docs.jsonata.org/processing">JSONata processing</see>.
    /// </summary>
    [TestMethod]
    public void ExplicitNullVariableSurvivesAsNullMember()
    {
        using JsonDocument body = Render(
            JsonataTestUtilities.CreateVeritasTemplateRegistry(),
            JsonataTemplate("{ \"middleName\": $middleName, \"name\": $name }"),
            "{\"middleName\":null,\"name\":\"Example\"}");

        JsonElement root = body.RootElement;
        Assert.IsTrue(root.TryGetProperty("middleName", out JsonElement middleName), "An explicit null is a value and its member is constructed.");
        Assert.AreEqual(JsonValueKind.Null, middleName.ValueKind);
        Assert.AreEqual("Example", root.GetProperty("name").GetString());
    }


    /// <summary>
    /// An undefined result is absence: a template member whose value refers to a variable that does
    /// not exist is omitted from the constructed body.
    /// See <see href="https://docs.jsonata.org/processing">JSONata processing</see>.
    /// </summary>
    [TestMethod]
    public void UndefinedVariableOmitsTheMember()
    {
        using JsonDocument body = Render(
            JsonataTestUtilities.CreateVeritasTemplateRegistry(),
            JsonataTemplate("{ \"absent\": $missing, \"name\": $name }"),
            "{\"name\":\"Example\"}");

        JsonElement root = body.RootElement;
        Assert.IsFalse(root.TryGetProperty("absent", out _), "An undefined member is omitted.");
        Assert.AreEqual("Example", root.GetProperty("name").GetString());
    }


    /// <summary>
    /// JSONata has one number type; a whole-valued arithmetic result over a
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see> credential
    /// template round-trips as an integer while a fractional one keeps its decimal form, matching the
    /// JSONata reference semantics.
    /// </summary>
    [TestMethod]
    public void IntegerVariablesRoundTripThroughArithmetic()
    {
        using JsonDocument body = Render(
            JsonataTestUtilities.CreateVeritasTemplateRegistry(),
            JsonataTemplate("{ \"twice\": $count * 2, \"half\": $count / 2 }"),
            "{\"count\":21}");

        JsonElement root = body.RootElement;
        Assert.AreEqual(42L, root.GetProperty("twice").GetInt64());
        Assert.AreEqual(10.5d, root.GetProperty("half").GetDouble());
    }


    /// <summary>
    /// A template longer than the engine's expression bound is refused by the engine itself — the
    /// wirer's own limit, distinct from the seam's <see cref="VcalmTemplateLimits.MaxTemplateBytes"/>.
    /// The engine's <see cref="JsonataLimitExceededException"/> is caught at the
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see> seam and
    /// surfaces as a typed <see cref="VcalmTemplateEvaluationResult.IsSuccess"/> refusal, never as a
    /// thrown exception escaping the library.
    /// </summary>
    [TestMethod]
    public void OversizedTemplateIsRefusedByTheExpressionBound()
    {
        string padding = new(' ', JsonataLimits.MaxExpressionLength);
        var template = JsonataTemplate("{ \"name\": $name }" + padding);
        var registry = JsonataTestUtilities.CreateVeritasTemplateRegistry();
        registry.Limits = new VcalmTemplateLimits { MaxTemplateBytes = int.MaxValue };

        VcalmTemplateEvaluationResult result = registry.Evaluate(
            template, Encoding.UTF8.GetBytes("{\"name\":\"Example\"}"), Pool, CancellationToken.None);

        Assert.IsFalse(result.IsSuccess);
        Assert.IsNull(result.Rendered);
        Assert.IsNotNull(result.FailureDetail);
    }


    /// <summary>
    /// A caller binding whose name is not a bare JSONata name (a <c>$</c>-prefixed key) is refused by
    /// the engine rather than silently shadowing or misbinding — the measured contract of the
    /// bindings parameter. The engine's <see cref="ArgumentException"/> is caught at the
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see> seam and
    /// surfaces as a typed <see cref="VcalmTemplateEvaluationResult.IsSuccess"/> refusal, never as a
    /// thrown exception escaping the library.
    /// </summary>
    [TestMethod]
    public void DollarPrefixedVariableNameIsRefused()
    {
        var template = JsonataTemplate("{ \"name\": $name }");
        var registry = JsonataTestUtilities.CreateVeritasTemplateRegistry();

        VcalmTemplateEvaluationResult result = registry.Evaluate(
            template, Encoding.UTF8.GetBytes("{\"$name\":\"Example\"}"), Pool, CancellationToken.None);

        Assert.IsFalse(result.IsSuccess);
        Assert.IsNull(result.Rendered);
        Assert.IsNotNull(result.FailureDetail);
    }
}
