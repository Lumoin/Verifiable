using System.Text;
using Verifiable.Vcalm;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// Tests for the W3C VCALM 1.0 §3.6.1 credential-template evaluation seam
/// (<see cref="VcalmTemplateEvaluatorRegistry"/>): the seam carries raw UTF-8 JSON bytes, ships no
/// <c>jsonata</c> evaluator of its own, evaluates the <c>literal</c> pass-through without any engine,
/// lets a deployment register a replacement evaluator, and fails closed — rather than throwing — on
/// an unregistered template type or an input/output that exceeds <see cref="VcalmTemplateLimits"/>.
/// </summary>
[TestClass]
internal sealed class VcalmTemplateEvaluatorTests
{
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see>:
    /// <c>credentialTemplates[].type</c> selects the evaluation mechanism. This library ships no
    /// <c>jsonata</c> evaluator — only the engine-free <c>literal</c> pass-through is wired by default.
    /// </summary>
    [TestMethod]
    public void DefaultRegistryWiresOnlyLiteral()
    {
        var registry = new VcalmTemplateEvaluatorRegistry();

        Assert.IsFalse(registry.IsRegistered(VcalmTemplateEvaluatorRegistry.JsonataTemplateType));
        Assert.IsTrue(registry.IsRegistered(VcalmTemplateEvaluatorRegistry.LiteralTemplateType));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see>: the
    /// <c>literal</c> template type carries a constant credential body — its UTF-8 encoded source IS
    /// the rendered result, read back byte-identically without any evaluation engine.
    /// </summary>
    [TestMethod]
    public void LiteralTemplateEvaluatesConstantBody()
    {
        var registry = new VcalmTemplateEvaluatorRegistry();
        var template = new VcalmCredentialTemplate
        {
            TemplateType = VcalmTemplateEvaluatorRegistry.LiteralTemplateType,
            Template = "{\"type\":[\"VerifiableCredential\"]}"
        };

        VcalmTemplateEvaluationResult result = registry.Evaluate(
            template, ReadOnlyMemory<byte>.Empty, Pool, CancellationToken.None);

        Assert.IsTrue(result.IsSuccess);
        using PooledMemory? rendered = result.Rendered;
        Assert.IsNotNull(rendered);
        Assert.AreEqual(template.Template, Encoding.UTF8.GetString(rendered.AsReadOnlySpan()));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see>: a
    /// deployment registers its own evaluator for <c>jsonata</c> through <see cref="VcalmTemplateEvaluatorRegistry.Register"/>
    /// — the seam routes to it rather than any built-in mechanism.
    /// </summary>
    [TestMethod]
    public void RegisteredReplacementEvaluatorIsUsed()
    {
        var registry = new VcalmTemplateEvaluatorRegistry();
        registry.Register(VcalmTemplateEvaluatorRegistry.JsonataTemplateType,
            (_, _, pool, _) => PooledMemory.FromBytes("{\"evaluatedBy\":\"replacement\"}"u8, pool, BufferTags.Json));

        var template = new VcalmCredentialTemplate
        {
            TemplateType = VcalmTemplateEvaluatorRegistry.JsonataTemplateType,
            Template = "{ \"name\": name }"
        };

        VcalmTemplateEvaluationResult result = registry.Evaluate(
            template, ReadOnlyMemory<byte>.Empty, Pool, CancellationToken.None);

        Assert.IsTrue(result.IsSuccess);
        using PooledMemory? rendered = result.Rendered;
        Assert.IsNotNull(rendered);
        Assert.AreEqual("{\"evaluatedBy\":\"replacement\"}", Encoding.UTF8.GetString(rendered.AsReadOnlySpan()));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see>: a
    /// template naming a type with no registered evaluator fails the evaluation closed — a typed
    /// refusal, not a thrown exception — rather than being run by a substitute mechanism.
    /// </summary>
    [TestMethod]
    public void UnregisteredTemplateTypeFailsClosed()
    {
        var registry = new VcalmTemplateEvaluatorRegistry();
        var template = new VcalmCredentialTemplate
        {
            TemplateType = VcalmTemplateEvaluatorRegistry.JsonataTemplateType,
            Template = "{}"
        };

        VcalmTemplateEvaluationResult result = registry.Evaluate(
            template, ReadOnlyMemory<byte>.Empty, Pool, CancellationToken.None);

        Assert.IsFalse(result.IsSuccess);
        Assert.IsNull(result.Rendered);
        Assert.IsNotNull(result.FailureDetail);
    }


    /// <summary>
    /// <see cref="VcalmTemplateLimits.MaxTemplateBytes"/> is a local hardening bound this seam places
    /// over the <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see>
    /// <c>credentialTemplates[].template</c> body, distinct from any registered engine's own limits:
    /// it is enforced BEFORE the evaluator runs, so an over-limit template source refuses without
    /// invoking the registered evaluator at all.
    /// </summary>
    [TestMethod]
    public void OversizedTemplateRefusesBeforeEvaluation()
    {
        bool evaluatorInvoked = false;
        var registry = new VcalmTemplateEvaluatorRegistry
        {
            Limits = new VcalmTemplateLimits { MaxTemplateBytes = 4 }
        };
        registry.Register(VcalmTemplateEvaluatorRegistry.JsonataTemplateType, (_, _, pool, _) =>
        {
            evaluatorInvoked = true;

            return PooledMemory.FromBytes("{}"u8, pool, BufferTags.Json);
        });

        var template = new VcalmCredentialTemplate
        {
            TemplateType = VcalmTemplateEvaluatorRegistry.JsonataTemplateType,
            Template = "{ \"name\": name }"
        };

        VcalmTemplateEvaluationResult result = registry.Evaluate(
            template, ReadOnlyMemory<byte>.Empty, Pool, CancellationToken.None);

        Assert.IsFalse(result.IsSuccess);
        Assert.IsFalse(evaluatorInvoked);
    }


    /// <summary>
    /// <see cref="VcalmTemplateLimits.MaxVariablesBytes"/> is a local hardening bound this seam places
    /// over the <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see>
    /// exchange variables fed to a template evaluation: it is enforced BEFORE the evaluator runs, so
    /// an over-limit variables fragment refuses without invoking the registered evaluator at all.
    /// </summary>
    [TestMethod]
    public void OversizedVariablesRefuseBeforeEvaluation()
    {
        bool evaluatorInvoked = false;
        var registry = new VcalmTemplateEvaluatorRegistry
        {
            Limits = new VcalmTemplateLimits { MaxVariablesBytes = 2 }
        };
        registry.Register(VcalmTemplateEvaluatorRegistry.JsonataTemplateType, (_, _, pool, _) =>
        {
            evaluatorInvoked = true;

            return PooledMemory.FromBytes("{}"u8, pool, BufferTags.Json);
        });

        var template = new VcalmCredentialTemplate
        {
            TemplateType = VcalmTemplateEvaluatorRegistry.JsonataTemplateType,
            Template = "{}"
        };

        VcalmTemplateEvaluationResult result = registry.Evaluate(
            template, Encoding.UTF8.GetBytes("{\"name\":\"value\"}"), Pool, CancellationToken.None);

        Assert.IsFalse(result.IsSuccess);
        Assert.IsFalse(evaluatorInvoked);
    }


    /// <summary>
    /// <see cref="VcalmTemplateLimits.MaxResultBytes"/> is a local hardening bound this seam places
    /// over the rendered body a registered evaluator produces for a
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see> credential
    /// template: it is enforced AFTER the evaluator runs, so an over-limit rendered result refuses
    /// and the oversized buffer is disposed rather than returned to the caller.
    /// </summary>
    [TestMethod]
    public void OversizedResultRefusesAfterEvaluationAndIsDisposed()
    {
        var registry = new VcalmTemplateEvaluatorRegistry
        {
            Limits = new VcalmTemplateLimits { MaxResultBytes = 2 }
        };
        PooledMemory? oversized = null;
        registry.Register(VcalmTemplateEvaluatorRegistry.JsonataTemplateType, (_, _, pool, _) =>
        {
            oversized = PooledMemory.FromBytes("{\"tooLarge\":true}"u8, pool, BufferTags.Json);

            return oversized;
        });

        var template = new VcalmCredentialTemplate
        {
            TemplateType = VcalmTemplateEvaluatorRegistry.JsonataTemplateType,
            Template = "{}"
        };

        VcalmTemplateEvaluationResult result = registry.Evaluate(
            template, ReadOnlyMemory<byte>.Empty, Pool, CancellationToken.None);

        Assert.IsFalse(result.IsSuccess);
        Assert.IsNull(result.Rendered);
        Assert.IsNotNull(oversized);
        PooledMemory disposedBuffer = oversized;
        _ = Assert.Throws<ObjectDisposedException>(() => disposedBuffer.AsReadOnlySpan());
    }


    /// <summary>
    /// <see cref="VcalmIntegration.VcalmTemplateEvaluators"/> defaults to a registry, so an unwired
    /// integration still evaluates the <c>literal</c>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see> credential
    /// template type without any application-level wiring.
    /// </summary>
    [TestMethod]
    public void IntegrationDefaultsTemplateEvaluatorsRegistry()
    {
        var integration = new VcalmIntegration();

        Assert.IsNotNull(integration.VcalmTemplateEvaluators);
        Assert.IsTrue(integration.VcalmTemplateEvaluators.IsRegistered(VcalmTemplateEvaluatorRegistry.LiteralTemplateType));
    }
}


/// <summary>
/// Tests for <see cref="VcalmJsonShape"/>: the byte-level object-shape check the §3.6 credential-
/// template evaluation path uses in place of a JSON parser (<c>Verifiable.Vcalm</c> bans
/// <c>System.Text.Json</c>).
/// </summary>
[TestClass]
internal sealed class VcalmJsonShapeTests
{
    /// <summary>
    /// A JSON object — optionally preceded by RFC 8259 §2 whitespace — is recognised by its leading
    /// <c>{</c>.
    /// </summary>
    [TestMethod]
    public void ObjectAfterWhitespaceIsRecognised()
    {
        Assert.IsTrue(VcalmJsonShape.IsObject("  \t\r\n{\"a\":1}"u8));
    }


    /// <summary>
    /// A JSON array is refused — only an object shape splices as sibling members in the §3.6 template
    /// evaluation path.
    /// </summary>
    [TestMethod]
    public void ArrayIsRefused()
    {
        Assert.IsFalse(VcalmJsonShape.IsObject("[1,2,3]"u8));
    }


    /// <summary>
    /// A bare JSON scalar (here, a quoted string — VCALM 1.0 §3.6.1's bare top-level variable NAME
    /// case) is refused; it does not have object members to splice.
    /// </summary>
    [TestMethod]
    public void ScalarIsRefused()
    {
        Assert.IsFalse(VcalmJsonShape.IsObject("\"myVariableName\""u8));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see>: the
    /// <see cref="ReadOnlySpan{Char}"/> overload agrees with the UTF-8 byte overload on the same
    /// shape decision, so a per-request <c>variables</c> string can be shape-checked directly without
    /// an intermediate UTF-8 byte-array allocation.
    /// </summary>
    [TestMethod]
    public void CharOverloadAgreesWithByteOverload()
    {
        Assert.IsTrue(VcalmJsonShape.IsObject("  \t\r\n{\"a\":1}".AsSpan()));
        Assert.IsFalse(VcalmJsonShape.IsObject("[1,2,3]".AsSpan()));
        Assert.IsFalse(VcalmJsonShape.IsObject("\"myVariableName\"".AsSpan()));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#example-a-basic-workflow">VCALM 1.0 Example 13</see>
    /// ("A Basic Workflow") wraps the credential under a <c>credential</c> member alongside other
    /// siblings; the member is located regardless of position, and its value's own nested strings
    /// (containing structural characters) and nested objects/arrays are skipped as a whole rather than
    /// stopping at their first inner delimiter.
    /// </summary>
    [TestMethod]
    public void TopLevelMemberIsLocatedAmongSiblingsWithNestedStructure()
    {
        const string json =
            "{\"before\":[\"a}b\",{\"x\":1}],\"credential\":{\"id\":\"urn:1\",\"note\":\"a \\\"quoted}\\\" text\"," +
            "\"nested\":{\"deep\":[1,2,{\"z\":true}]}},\"after\":42}";
        byte[] jsonUtf8 = Encoding.UTF8.GetBytes(json);

        bool found = VcalmJsonShape.TryGetTopLevelMemberValue(jsonUtf8, "credential"u8, out Range valueRange);

        Assert.IsTrue(found);
        string value = Encoding.UTF8.GetString(jsonUtf8.AsSpan()[valueRange]);
        Assert.AreEqual(
            "{\"id\":\"urn:1\",\"note\":\"a \\\"quoted}\\\" text\",\"nested\":{\"deep\":[1,2,{\"z\":true}]}}", value);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#example-minimal-credential-template">VCALM 1.0
    /// Appendix D.1 Example 29</see> renders the bare credential directly, with no <c>credential</c>
    /// wrapper member — the lookup reports absence rather than a false match, so the engine signs the
    /// rendered object as-is.
    /// </summary>
    [TestMethod]
    public void AbsentTopLevelMemberIsNotFound()
    {
        const string json = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"]}";

        bool found = VcalmJsonShape.TryGetTopLevelMemberValue(Encoding.UTF8.GetBytes(json), "credential"u8, out _);

        Assert.IsFalse(found);
    }
}
