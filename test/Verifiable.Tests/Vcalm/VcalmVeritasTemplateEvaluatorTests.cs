using Lumoin.Veritas.Jsonata;
using System.Collections.Generic;
using Verifiable.JsonPointer.Jsonata;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// The Lumoin.Veritas JSONata engine registered on the W3C VCALM 1.0 §3.6.1 credential-template
/// seam: parity with the built-in evaluator on the Appendix D template shape, the <c>$name</c>
/// variable convention carried by the engine's caller bindings, the JSONata reference semantics
/// for null and undefined, the integer round-trip through the one JSONata number type, and the
/// engine's bounds.
/// </summary>
[TestClass]
internal sealed class VcalmVeritasTemplateEvaluatorTests
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


    private static VcalmCredentialTemplate JsonataTemplate(string template) => new()
    {
        TemplateType = VcalmTemplateEvaluatorRegistry.JsonataTemplateType,
        Template = template
    };

    //Structural equality over the neutral value model (its own equality is by instance for
    //containers): same kind, and for containers the same members with deep-equal values.
    private static bool DeepEquals(JsonataValue left, JsonataValue right)
    {
        if(left.Kind != right.Kind)
        {
            return false;
        }

        return left.Kind switch
        {
            JsonataValueKind.Object => left.AsObject().Count == right.AsObject().Count
                && left.AsObject().All(member => right.AsObject().TryGetValue(member.Key, out JsonataValue other) && DeepEquals(member.Value, other)),
            JsonataValueKind.Array => left.AsArray().Count == right.AsArray().Count
                && left.AsArray().Zip(right.AsArray()).All(pair => DeepEquals(pair.First, pair.Second)),
            _ => left.Equals(right)
        };
    }



    /// <summary>
    /// The VCALM Appendix D Example 27 template shape evaluates to the same credential body through
    /// the Veritas engine as through the built-in evaluator, so registering the engine supersedes
    /// the built-in one without changing the seam's output.
    /// See <see href="https://www.w3.org/TR/vcalm-1.0/">VCALM 1.0 §3.6.1</see>.
    /// </summary>
    [TestMethod]
    public void VeritasEngineMatchesBuiltInOnAppendixDTemplate()
    {
        var template = JsonataTemplate(
            "{\"@context\": [\"https://www.w3.org/ns/credentials/v2\"]," +
            "\"type\": [\"VerifiableCredential\",\"ExampleNameCredential\"]," +
            "\"credentialSubject\": {\"name\": name}}");
        JsonataValue variables = Variables(("name", JsonataValue.FromString("Example Name")));

        JsonataValue builtIn = new VcalmTemplateEvaluatorRegistry().Evaluate(template, variables);
        JsonataValue veritas = JsonataTestUtilities.CreateVeritasTemplateRegistry().Evaluate(template, variables);

        Assert.IsTrue(DeepEquals(builtIn, veritas), "The two engines must produce the same credential body.");
        Assert.AreEqual("Example Name", veritas.AsObject()["credentialSubject"].AsObject()["name"].AsString());
    }


    /// <summary>
    /// The VCALM <c>$name</c> variable convention resolves through the engine's caller bindings
    /// (each top-level exchange variable bound under its bare name), and the bare-path form
    /// resolves through the input document — both spellings reach the same variable.
    /// </summary>
    [TestMethod]
    public void VariablesResolveAsBindingsAndAsInputPaths()
    {
        var registry = JsonataTestUtilities.CreateVeritasTemplateRegistry();
        JsonataValue variables = Variables(("name", JsonataValue.FromString("Example Name")));

        JsonataValue bound = registry.Evaluate(JsonataTemplate("{ \"name\": $name }"), variables);
        JsonataValue pathed = registry.Evaluate(JsonataTemplate("{ \"name\": name }"), variables);

        Assert.AreEqual("Example Name", bound.AsObject()["name"].AsString(), "$name resolves through the bindings.");
        Assert.AreEqual("Example Name", pathed.AsObject()["name"].AsString(), "The bare path resolves through the input.");
    }


    /// <summary>
    /// The Veritas engine evaluates the JSONata surface beyond the built-in evaluator's subset —
    /// a function call — which is the point of superseding it.
    /// </summary>
    [TestMethod]
    public void VeritasEngineEvaluatesFunctionCallsTheBuiltInCannot()
    {
        var template = JsonataTemplate("{ \"shout\": $uppercase($name) }");
        JsonataValue variables = Variables(("name", JsonataValue.FromString("example")));

        JsonataValue body = JsonataTestUtilities.CreateVeritasTemplateRegistry().Evaluate(template, variables);

        Assert.AreEqual("EXAMPLE", body.AsObject()["shout"].AsString());
        Assert.Throws<Verifiable.JsonPointer.Jsonata.JsonataUnsupportedFeatureException>(() => new VcalmTemplateEvaluatorRegistry().Evaluate(template, variables),
            "The built-in evaluator declares function calls unsupported.");
    }


    /// <summary>
    /// JSON <c>null</c> is a value: an explicitly null exchange variable survives into the
    /// constructed credential body as a null member, per the JSONata reference semantics the
    /// engine implements. See <see href="https://docs.jsonata.org/processing">JSONata processing</see>.
    /// </summary>
    [TestMethod]
    public void ExplicitNullVariableSurvivesAsNullMember()
    {
        var template = JsonataTemplate("{ \"middleName\": $middleName, \"name\": $name }");
        JsonataValue variables = Variables(("middleName", JsonataValue.Null), ("name", JsonataValue.FromString("Example")));

        JsonataValue body = JsonataTestUtilities.CreateVeritasTemplateRegistry().Evaluate(template, variables);

        IReadOnlyDictionary<string, JsonataValue> members = body.AsObject();
        Assert.IsTrue(members.ContainsKey("middleName"), "An explicit null is a value and its member is constructed.");
        Assert.IsTrue(members["middleName"].IsNull);
        Assert.AreEqual("Example", members["name"].AsString());
    }


    /// <summary>
    /// An undefined result is absence: a template member whose value refers to a variable that
    /// does not exist is omitted from the constructed body.
    /// See <see href="https://docs.jsonata.org/processing">JSONata processing</see>.
    /// </summary>
    [TestMethod]
    public void UndefinedVariableOmitsTheMember()
    {
        var template = JsonataTemplate("{ \"absent\": $missing, \"name\": $name }");
        JsonataValue variables = Variables(("name", JsonataValue.FromString("Example")));

        JsonataValue body = JsonataTestUtilities.CreateVeritasTemplateRegistry().Evaluate(template, variables);

        IReadOnlyDictionary<string, JsonataValue> members = body.AsObject();
        Assert.IsFalse(members.ContainsKey("absent"), "An undefined member is omitted.");
        Assert.AreEqual("Example", members["name"].AsString());
    }


    /// <summary>
    /// JSONata has one number type; a whole-valued result adapts back to the neutral integer kind
    /// so integer variables round-trip through arithmetic without becoming floating-point noise.
    /// </summary>
    [TestMethod]
    public void IntegerVariablesRoundTripThroughArithmetic()
    {
        var template = JsonataTemplate("{ \"twice\": $count * 2, \"half\": $count / 2 }");
        JsonataValue variables = Variables(("count", JsonataValue.FromInteger(21)));

        JsonataValue body = JsonataTestUtilities.CreateVeritasTemplateRegistry().Evaluate(template, variables);

        IReadOnlyDictionary<string, JsonataValue> members = body.AsObject();
        Assert.AreEqual(JsonataValueKind.Integer, members["twice"].Kind);
        Assert.AreEqual(42L, members["twice"].AsInteger());
        Assert.AreEqual(JsonataValueKind.Number, members["half"].Kind);
        Assert.AreEqual(10.5d, members["half"].AsNumber());
    }


    /// <summary>
    /// A template longer than the engine's expression bound (64 KiB) is refused with the bound
    /// named, on every lexer route.
    /// </summary>
    [TestMethod]
    public void OversizedTemplateIsRefusedByTheExpressionBound()
    {
        string padding = new string(' ', Lumoin.Veritas.Jsonata.JsonataLimits.MaxExpressionLength);
        var template = JsonataTemplate("{ \"name\": $name }" + padding);
        JsonataValue variables = Variables(("name", JsonataValue.FromString("Example")));

        Assert.Throws<JsonataLimitExceededException>(() =>
            JsonataTestUtilities.CreateVeritasTemplateRegistry().Evaluate(template, variables));
    }


    /// <summary>
    /// A caller binding whose name is not a bare JSONata name (a <c>$</c>-prefixed key) is refused
    /// by the engine rather than silently shadowing or misbinding — the measured contract of the
    /// bindings parameter.
    /// </summary>
    [TestMethod]
    public void DollarPrefixedVariableNameIsRefused()
    {
        var template = JsonataTemplate("{ \"name\": $name }");
        JsonataValue variables = Variables(("$name", JsonataValue.FromString("Example")));

        Assert.Throws<ArgumentException>(() =>
            JsonataTestUtilities.CreateVeritasTemplateRegistry().Evaluate(template, variables));
    }
}
