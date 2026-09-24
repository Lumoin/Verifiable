using System.Text;
using Verifiable.Json;
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
    /// <summary>The pool every evaluation of these tests renders into.</summary>
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


}


/// <summary>
/// Tests for the JSON leaf's top-level member lookup (<see cref="VcalmJsonParsing.CreateMemberFinder"/>), the reading
/// the §3.6 workflow engine decides the <c>credential</c> wrapper of a rendered template and the reserved
/// <c>results</c> variable from: a member is found by its decoded name among the object's own top-level members only,
/// and input the lookup cannot read as one object whose members it could name is answered
/// <see cref="VcalmJsonMemberLookup.Unreadable"/>.
/// </summary>
/// <remarks>
/// Each test proves the JSON leaf directly, in-process; the issuing step's answers over the real wire are the
/// <see cref="VcalmMultiStepExchangeTests"/> issuance tests.
/// </remarks>
[TestClass]
internal sealed class VcalmJsonMemberFinderTests
{
    /// <summary>The lookup under test, the one the default JSON wiring sets on the integration.</summary>
    private static FindVcalmJsonMemberDelegate FindMember { get; } = VcalmJsonParsing.CreateMemberFinder();

    /// <summary>
    /// The value of the <c>credential</c> member the sibling case locates: nested strings holding structural
    /// characters and escaped quotes, and nested objects and arrays, so a lookup that stopped at an inner delimiter
    /// would locate less than the whole value.
    /// </summary>
    private const string NestedCredentialValue =
        "{\"id\":\"urn:1\",\"note\":\"a \\\"quoted}\\\" text\",\"nested\":{\"deep\":[1,2,{\"z\":true}]}}";


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#get-workflow-configuration">VCALM 1.0 §3.6.2</see>: "The template
    /// string should render to an object containing a credential field, which holds the credential template". The field
    /// is found among its siblings wherever it stands, under its plain spelling and under one written with an escape
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 §7</see>: "Any character may be escaped"),
    /// and its value is located whole.
    /// </summary>
    /// <param name="spelledName">The member name as the object writes it, JSON escapes included.</param>
    [TestMethod]
    [DataRow("credential")]
    [DataRow("cred\\u0065ntial")]
    public void MemberAmongSiblingsIsFoundWithItsWholeValue(string spelledName)
    {
        byte[] json = Encoding.UTF8.GetBytes(
            "{\"before\":[\"a}b\",{\"x\":1}],\"" + spelledName + "\":" + NestedCredentialValue + ",\"after\":42}");

        VcalmJsonMemberLookup lookup = FindMember(json, "credential", out Range valueRange);

        Assert.AreEqual(VcalmJsonMemberLookup.Found, lookup);
        Assert.AreEqual(NestedCredentialValue, Encoding.UTF8.GetString(json.AsSpan()[valueRange]));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#get-workflow-configuration">VCALM 1.0 §3.6.2</see>: "The template
    /// string should render to an object containing a credential field". A template may render the bare credential
    /// instead, an object read to its end that carries no such field, and the lookup answers that the field is absent,
    /// never a false match, so the engine signs the object as rendered.
    /// </summary>
    [TestMethod]
    public void MemberTheObjectDoesNotCarryIsAbsent()
    {
        byte[] json = Encoding.UTF8.GetBytes("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"]}");

        VcalmJsonMemberLookup lookup = FindMember(json, "credential", out Range valueRange);

        Assert.AreEqual(VcalmJsonMemberLookup.Absent, lookup);
        Assert.AreEqual(default, valueRange, "An absent member locates no value.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#get-workflow-configuration">VCALM 1.0 §3.6.2</see>: "The template
    /// string should render to an object containing a credential field", a field of the rendered object itself. The name
    /// met below the top level, as a member of a nested object, as a member of an object inside an array, or as a string
    /// value, is not that field, so the lookup answers that the object's own field is absent.
    /// </summary>
    /// <param name="json">An object carrying the name only below its top level.</param>
    [TestMethod]
    [DataRow("{\"outer\":{\"credential\":{\"id\":\"urn:1\"}}}")]
    [DataRow("{\"list\":[\"credential\",{\"credential\":{\"id\":\"urn:1\"}}]}")]
    [DataRow("{\"note\":\"credential\"}")]
    public void NameBelowTheTopLevelIsAbsent(string json)
    {
        VcalmJsonMemberLookup lookup = FindMember(Encoding.UTF8.GetBytes(json), "credential", out _);

        Assert.AreEqual(VcalmJsonMemberLookup.Absent, lookup);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 §4</see>: "When the names within an object
    /// are not unique, the behavior of software that receives such an object is unpredictable. Many implementations report
    /// the last name/value pair only. Other implementations report an error or fail to parse the object, and some
    /// implementations report all of the name/value pairs, including duplicates." An object carrying the looked-up member
    /// twice, under one spelling or under two spellings of the same decoded name, is unreadable: the lookup answers with
    /// neither the first nor the last value, since which of them a later parser of the same text reads is unpredictable.
    /// </summary>
    /// <param name="json">An object carrying the member twice.</param>
    [TestMethod]
    [DataRow("{\"credential\":{\"id\":\"urn:1\"},\"credential\":{\"id\":\"urn:2\"}}")]
    [DataRow("{\"credential\":{\"id\":\"urn:1\"},\"cred\\u0065ntial\":{\"id\":\"urn:2\"}}")]
    public void MemberCarriedTwiceIsUnreadable(string json)
    {
        VcalmJsonMemberLookup lookup = FindMember(Encoding.UTF8.GetBytes(json), "credential", out Range valueRange);

        Assert.AreEqual(VcalmJsonMemberLookup.Unreadable, lookup);
        Assert.AreEqual(default, valueRange, "An unreadable object locates no value.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.2">RFC 8259 §8.2</see>: "However, the ABNF in this
    /// specification allows member names and string values to contain bit sequences that cannot encode Unicode
    /// characters; for example, "\uDEAD" (a single unpaired UTF-16 surrogate)." and "The behavior of software that
    /// receives JSON texts containing such values is unpredictable". A top-level member name whose escapes spell an
    /// unpaired surrogate is unreadable, whether it could read as the looked-up name or as another one, so the lookup
    /// answers neither found nor absent for the object that carries it.
    /// </summary>
    /// <param name="json">An object carrying a top-level member name that spells no Unicode string.</param>
    [TestMethod]
    [DataRow("{\"r\\udc00esults\":true}")]
    [DataRow("{\"x\\ud800\":true}")]
    [DataRow("{\"a\":1,\"\\udc00\":2}")]
    public void NameThatSpellsNoUnicodeStringIsUnreadable(string json)
    {
        VcalmJsonMemberLookup lookup = FindMember(Encoding.UTF8.GetBytes(json), "results", out _);

        Assert.AreEqual(VcalmJsonMemberLookup.Unreadable, lookup);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 §2</see>: "A JSON text is a serialized
    /// value." The lookup reads the object to its end before it answers, so input that is not one well-formed object, an
    /// array, a truncated object, an object followed by more text, or two objects, is unreadable rather than read as
    /// carrying or lacking the member.
    /// </summary>
    /// <param name="json">Input that is not one well-formed JSON object.</param>
    [TestMethod]
    [DataRow("[{\"credential\":{}}]")]
    [DataRow("{\"credential\":{}")]
    [DataRow("{\"credential\":{}} trailing")]
    [DataRow("{\"credential\":{}}{\"credential\":{}}")]
    public void InputThatIsNotOneObjectIsUnreadable(string json)
    {
        VcalmJsonMemberLookup lookup = FindMember(Encoding.UTF8.GetBytes(json), "credential", out _);

        Assert.AreEqual(VcalmJsonMemberLookup.Unreadable, lookup);
    }
}
