using System.Collections.Generic;
using Verifiable.JsonPointer.Jsonata;

namespace Verifiable.Tests.JsonPointer.Jsonata;

/// <summary>
/// Tests for the minimal in-repo JSONata evaluator (<see cref="JsonataEvaluator"/>) — the subset that
/// makes the W3C VCALM §3.6 <c>credentialTemplates</c> feature function: field / path navigation,
/// object construction, array construction, string concatenation, literals, and the context /
/// variable reference. Out-of-scope constructs are proven to raise
/// <see cref="JsonataUnsupportedFeatureException"/>, malformed text to raise
/// <see cref="JsonataParseException"/>, and the bounds to raise
/// <see cref="JsonataEvaluationLimitException"/>, so the evaluator errors rather than constructs a
/// wrong credential. The full engine from <c>Lumoin.Veritas</c> supersedes this one in production.
/// </summary>
[TestClass]
internal sealed class JsonataEvaluatorTests
{
    private static readonly string[] ExpectedOrderedKeys = ["id", "kind"];


    //Builds an input object value from a set of members, preserving order.
    private static JsonataValue Object(params (string Key, JsonataValue Value)[] members)
    {
        var map = new Dictionary<string, JsonataValue>(StringComparer.Ordinal);
        foreach((string key, JsonataValue value) in members)
        {
            map[key] = value;
        }

        return JsonataValue.FromObject(map);
    }


    [TestMethod]
    public void StringLiteralEvaluatesToString()
    {
        JsonataValue result = JsonataEvaluator.Evaluate("\"hello\"", JsonataValue.Null);

        Assert.AreEqual(JsonataValueKind.String, result.Kind);
        Assert.AreEqual("hello", result.AsString());
    }


    [TestMethod]
    public void SingleQuotedStringLiteralEvaluatesToString()
    {
        //VCALM Appendix-D Example 28 uses single-quoted string literals.
        JsonataValue result = JsonataEvaluator.Evaluate("'world'", JsonataValue.Null);

        Assert.AreEqual("world", result.AsString());
    }


    [TestMethod]
    public void IntegerLiteralEvaluatesToInteger()
    {
        JsonataValue result = JsonataEvaluator.Evaluate("42", JsonataValue.Null);

        Assert.AreEqual(JsonataValueKind.Integer, result.Kind);
        Assert.AreEqual(42L, result.AsInteger());
    }


    [TestMethod]
    public void FractionalLiteralEvaluatesToNumber()
    {
        JsonataValue result = JsonataEvaluator.Evaluate("3.5", JsonataValue.Null);

        Assert.AreEqual(JsonataValueKind.Number, result.Kind);
        Assert.AreEqual(3.5, result.AsNumber());
    }


    [TestMethod]
    public void BooleanAndNullLiteralsEvaluate()
    {
        Assert.IsTrue(JsonataEvaluator.Evaluate("true", JsonataValue.Null).AsBoolean());
        Assert.IsFalse(JsonataEvaluator.Evaluate("false", JsonataValue.Null).AsBoolean());
        Assert.IsTrue(JsonataEvaluator.Evaluate("null", JsonataValue.Null).IsNull);
    }


    [TestMethod]
    public void FieldNavigationReadsTopLevelMember()
    {
        JsonataValue input = Object(("name", JsonataValue.FromString("Alice")));

        JsonataValue result = JsonataEvaluator.Evaluate("name", input);

        Assert.AreEqual("Alice", result.AsString());
    }


    [TestMethod]
    public void DottedPathNavigatesNestedMembers()
    {
        JsonataValue input = Object(
            ("credentialSubject", Object(
                ("achievement", Object(
                    ("name", JsonataValue.FromString("Sample Achievement")))))));

        JsonataValue result = JsonataEvaluator.Evaluate("credentialSubject.achievement.name", input);

        Assert.AreEqual("Sample Achievement", result.AsString());
    }


    [TestMethod]
    public void MissingPathNavigatesToNull()
    {
        JsonataValue input = Object(("present", JsonataValue.FromString("x")));

        JsonataValue result = JsonataEvaluator.Evaluate("absent.deeper", input);

        Assert.IsTrue(result.IsNull);
    }


    [TestMethod]
    public void ContextReferenceReturnsInput()
    {
        JsonataValue input = JsonataValue.FromString("the-context");

        JsonataValue result = JsonataEvaluator.Evaluate("$", input);

        Assert.AreEqual("the-context", result.AsString());
    }


    [TestMethod]
    public void VariableReferenceReadsMemberOfContext()
    {
        JsonataValue input = Object(("name", JsonataValue.FromString("Bob")));

        JsonataValue result = JsonataEvaluator.Evaluate("$name", input);

        Assert.AreEqual("Bob", result.AsString());
    }


    [TestMethod]
    public void ObjectConstructionBuildsMembersInOrder()
    {
        JsonataValue input = Object(("id", JsonataValue.FromString("urn:1")));

        JsonataValue result = JsonataEvaluator.Evaluate("{ \"id\": id, \"kind\": \"credential\" }", input);

        Assert.AreEqual(JsonataValueKind.Object, result.Kind);
        IReadOnlyDictionary<string, JsonataValue> members = result.AsObject();
        Assert.AreEqual("urn:1", members["id"].AsString());
        Assert.AreEqual("credential", members["kind"].AsString());
        Assert.AreSequenceEqual(ExpectedOrderedKeys, members.Keys.ToArray());
    }


    [TestMethod]
    public void ObjectConstructionOmitsMembersWhosePathIsAbsent()
    {
        JsonataValue input = Object(("present", JsonataValue.FromString("x")));

        JsonataValue result = JsonataEvaluator.Evaluate("{ \"a\": present, \"b\": missing }", input);

        IReadOnlyDictionary<string, JsonataValue> members = result.AsObject();
        Assert.IsTrue(members.ContainsKey("a"));
        Assert.IsFalse(members.ContainsKey("b"));
    }


    [TestMethod]
    public void ArrayConstructionBuildsElementsInOrder()
    {
        JsonataValue result = JsonataEvaluator.Evaluate("[ \"VerifiableCredential\", \"ExampleNameCredential\" ]", JsonataValue.Null);

        Assert.AreEqual(JsonataValueKind.Array, result.Kind);
        IReadOnlyList<JsonataValue> elements = result.AsArray();
        Assert.HasCount(2, elements);
        Assert.AreEqual("VerifiableCredential", elements[0].AsString());
        Assert.AreEqual("ExampleNameCredential", elements[1].AsString());
    }


    [TestMethod]
    public void StringConcatenationJoinsOperands()
    {
        JsonataValue input = Object(("given", JsonataValue.FromString("Ada")));

        JsonataValue result = JsonataEvaluator.Evaluate("given & \" Lovelace\"", input);

        Assert.AreEqual("Ada Lovelace", result.AsString());
    }


    [TestMethod]
    public void StringConcatenationChainsLeftToRight()
    {
        JsonataValue input = Object(
            ("a", JsonataValue.FromString("1")),
            ("b", JsonataValue.FromString("2")));

        JsonataValue result = JsonataEvaluator.Evaluate("a & \"-\" & b", input);

        Assert.AreEqual("1-2", result.AsString());
    }


    [TestMethod]
    public void ConcatenationOfAbsentPathContributesEmptyString()
    {
        JsonataValue input = Object(("prefix", JsonataValue.FromString("X")));

        JsonataValue result = JsonataEvaluator.Evaluate("prefix & missing", input);

        Assert.AreEqual("X", result.AsString());
    }


    [TestMethod]
    public void EvaluationIsDeterministic()
    {
        JsonataValue input = Object(("v", JsonataValue.FromString("z")));

        JsonataValue first = JsonataEvaluator.Evaluate("{ \"k\": v }", input);
        JsonataValue second = JsonataEvaluator.Evaluate("{ \"k\": v }", input);

        Assert.AreEqual(first.AsObject()["k"].AsString(), second.AsObject()["k"].AsString());
    }


    [TestMethod]
    public void MinimalVcalmCredentialTemplateEvaluatesCorrectly()
    {
        //VCALM Appendix-D Example 27 (Minimal Credential Template), with the inner template body the
        //§3.6.1 'template' string carries: it maps the 'name' variable into a credential body.
        const string template =
            "{\"@context\": [\"https://www.w3.org/ns/credentials/v2\", \"https://www.w3.org/ns/credentials/examples/v2\"]," +
            "\"type\": [\"VerifiableCredential\",\"ExampleNameCredential\"]," +
            "\"credentialSubject\": {\"name\": name}}";

        JsonataValue input = Object(("name", JsonataValue.FromString("Example Name")));

        JsonataValue result = JsonataEvaluator.Evaluate(template, input);

        IReadOnlyDictionary<string, JsonataValue> credential = result.AsObject();
        IReadOnlyList<JsonataValue> context = credential["@context"].AsArray();
        Assert.AreEqual("https://www.w3.org/ns/credentials/v2", context[0].AsString());
        Assert.AreEqual("https://www.w3.org/ns/credentials/examples/v2", context[1].AsString());

        IReadOnlyList<JsonataValue> types = credential["type"].AsArray();
        Assert.AreEqual("VerifiableCredential", types[0].AsString());
        Assert.AreEqual("ExampleNameCredential", types[1].AsString());

        IReadOnlyDictionary<string, JsonataValue> subject = credential["credentialSubject"].AsObject();
        Assert.AreEqual("Example Name", subject["name"].AsString());
    }


    [TestMethod]
    public void AppendixDAchievementTemplatePatternEvaluates()
    {
        //VCALM Appendix-D Example 12 pattern: dotted-path navigation into the 'sampleAchievementCredential'
        //variable mapping its members into the credential body.
        const string template =
            "{\"id\": sampleAchievementCredential.id," +
            "\"name\": sampleAchievementCredential.credentialSubject.name," +
            "\"achievementName\": sampleAchievementCredential.credentialSubject.achievement.name}";

        JsonataValue input = Object(
            ("sampleAchievementCredential", Object(
                ("id", JsonataValue.FromString("urn:cred:1")),
                ("credentialSubject", Object(
                    ("name", JsonataValue.FromString("Pat")),
                    ("achievement", Object(
                        ("name", JsonataValue.FromString("Robotics 101")))))))));

        IReadOnlyDictionary<string, JsonataValue> credential = JsonataEvaluator.Evaluate(template, input).AsObject();
        Assert.AreEqual("urn:cred:1", credential["id"].AsString());
        Assert.AreEqual("Pat", credential["name"].AsString());
        Assert.AreEqual("Robotics 101", credential["achievementName"].AsString());
    }


    [TestMethod]
    public void FunctionCallRaisesUnsupportedFeature()
    {
        Assert.Throws<JsonataUnsupportedFeatureException>(
            () => JsonataEvaluator.Evaluate("$uppercase(name)", JsonataValue.Null));
    }


    [TestMethod]
    public void PredicateRaisesUnsupportedFeature()
    {
        Assert.Throws<JsonataUnsupportedFeatureException>(
            () => JsonataEvaluator.Evaluate("items[0]", JsonataValue.Null));
    }


    [TestMethod]
    public void ArithmeticOperatorRaisesUnsupportedFeature()
    {
        Assert.Throws<JsonataUnsupportedFeatureException>(
            () => JsonataEvaluator.Evaluate("a + b", Object(("a", JsonataValue.FromInteger(1)), ("b", JsonataValue.FromInteger(2)))));
    }


    [TestMethod]
    public void ConditionalRaisesUnsupportedFeature()
    {
        Assert.Throws<JsonataUnsupportedFeatureException>(
            () => JsonataEvaluator.Evaluate("a ? b : c", JsonataValue.Null));
    }


    [TestMethod]
    public void WildcardRaisesUnsupportedFeature()
    {
        Assert.Throws<JsonataUnsupportedFeatureException>(
            () => JsonataEvaluator.Evaluate("foo.*", JsonataValue.Null));
    }


    [TestMethod]
    public void UnterminatedStringRaisesParseException()
    {
        Assert.Throws<JsonataParseException>(
            () => JsonataEvaluator.Evaluate("\"unterminated", JsonataValue.Null));
    }


    [TestMethod]
    public void UnterminatedObjectRaisesParseException()
    {
        Assert.Throws<JsonataParseException>(
            () => JsonataEvaluator.Evaluate("{ \"a\": 1", JsonataValue.Null));
    }


    [TestMethod]
    public void MissingColonInObjectRaisesParseException()
    {
        Assert.Throws<JsonataParseException>(
            () => JsonataEvaluator.Evaluate("{ \"a\" 1 }", JsonataValue.Null));
    }


    [TestMethod]
    public void TrailingTextRaisesParseException()
    {
        Assert.Throws<JsonataParseException>(
            () => JsonataEvaluator.Evaluate("name extra", Object(("name", JsonataValue.FromString("x")))));
    }


    [TestMethod]
    public void DeeplyNestedExpressionHitsParseDepthLimit()
    {
        //A source nested past MaxParseDepth trips the parse-depth bound rather than overflowing the
        //stack, proving the bound is real.
        int depth = JsonataLimits.MaxParseDepth + 5;
        string source = string.Concat(Enumerable.Repeat("[", depth)) + "1" + string.Concat(Enumerable.Repeat("]", depth));

        var exception = Assert.Throws<JsonataEvaluationLimitException>(
            () => JsonataEvaluator.Evaluate(source, JsonataValue.Null));
        Assert.AreEqual(JsonataLimit.ParseDepth, exception.Limit);
    }


    [TestMethod]
    public void DeeplyNestedInputDoesNotOverflowAndPathStaysBounded()
    {
        //A deeply-nested input navigated by a deep dotted path stays within the evaluation bounds: a
        //path is a single evaluation node, so this proves navigation does not recurse per input level.
        var leaf = JsonataValue.FromString("deep");
        JsonataValue input = leaf;
        var steps = new List<string>();
        for(int i = 0; i < 50; i++)
        {
            string key = $"k{i}";
            steps.Insert(0, key);
            input = JsonataValue.FromObject(new Dictionary<string, JsonataValue>(StringComparer.Ordinal) { [key] = input });
        }

        string path = string.Join('.', steps);
        JsonataValue result = JsonataEvaluator.Evaluate(path, input);

        Assert.AreEqual("deep", result.AsString());
    }


    [TestMethod]
    public void ExcessiveExpressionLengthHitsLengthLimit()
    {
        string source = "\"" + new string('x', JsonataLimits.MaxExpressionLength) + "\"";

        var exception = Assert.Throws<JsonataEvaluationLimitException>(
            () => JsonataEvaluator.Evaluate(source, JsonataValue.Null));
        Assert.AreEqual(JsonataLimit.ExpressionLength, exception.Limit);
    }
}
