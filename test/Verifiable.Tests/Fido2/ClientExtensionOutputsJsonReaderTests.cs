using System.Text;
using Verifiable.Fido2;
using Verifiable.Json;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="ClientExtensionOutputsJsonReader"/>: the JSON codec for
/// <c>clientExtensionResults</c>, per WebAuthn L3
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">section 9: WebAuthn Extensions</see>.
/// Every malformed-input rejection is a <see cref="Fido2FormatException"/>.
/// </summary>
[TestClass]
internal sealed class ClientExtensionOutputsJsonReaderTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A <c>clientExtensionResults</c> object carrying a boolean <c>appid</c> output and an unknown
    /// extension's object-shaped output captures both, in wire order, with each value's raw bytes
    /// preserved rather than interpreted.
    /// </summary>
    [TestMethod]
    public void AppidAndUnknownExtensionCapturesEachRawValueInWireOrder()
    {
        const string json = """{"appid":true,"credProps":{"rk":false}}""";

        IReadOnlyList<Fido2ExtensionOutput> outputs = ClientExtensionOutputsJsonReader.Read(Encoding.UTF8.GetBytes(json));

        Assert.HasCount(2, outputs);
        Assert.AreEqual("appid", outputs[0].Identifier);
        Assert.AreEqual("true", Encoding.UTF8.GetString(outputs[0].Value.Span));
        Assert.AreEqual("credProps", outputs[1].Identifier);
        Assert.AreEqual("""{"rk":false}""", Encoding.UTF8.GetString(outputs[1].Value.Span));
    }


    /// <summary>
    /// A nested-object extension output value is captured byte-for-byte, preserving its own nested
    /// structure rather than being flattened, truncated, or re-serialized.
    /// </summary>
    [TestMethod]
    public void NestedObjectValueIsCapturedRawByteForByte()
    {
        const string nestedValue = """{"a":{"b":1}}""";
        string json = $$"""{"ext":{{nestedValue}}}""";

        IReadOnlyList<Fido2ExtensionOutput> outputs = ClientExtensionOutputsJsonReader.Read(Encoding.UTF8.GetBytes(json));

        Assert.HasCount(1, outputs);
        Assert.AreEqual("ext", outputs[0].Identifier);
        Assert.AreEqual(nestedValue, Encoding.UTF8.GetString(outputs[0].Value.Span));
    }


    /// <summary>A duplicate top-level member (here, two <c>appid</c> members) is rejected.</summary>
    [TestMethod]
    public void DuplicateTopLevelMemberIsRejected()
    {
        const string json = """{"appid":true,"appid":false}""";

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => ClientExtensionOutputsJsonReader.Read(Encoding.UTF8.GetBytes(json)));

        Assert.Contains("appid", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>Trailing content after an otherwise well-formed top-level object is rejected.</summary>
    [TestMethod]
    public void TrailingContentAfterTheObjectIsRejected()
    {
        const string json = """{"appid":true} garbage""";

        Assert.ThrowsExactly<Fido2FormatException>(() => ClientExtensionOutputsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>A top-level JSON array, rather than an object, is rejected.</summary>
    [TestMethod]
    public void TopLevelJsonArrayIsRejected()
    {
        const string json = """[1,2,3]""";

        Assert.ThrowsExactly<Fido2FormatException>(() => ClientExtensionOutputsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>Malformed JSON bytes that do not parse at all are rejected.</summary>
    [TestMethod]
    public void MalformedJsonBytesAreRejected()
    {
        const string json = "{not json";

        Assert.ThrowsExactly<Fido2FormatException>(() => ClientExtensionOutputsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>
    /// An extension output value nested beyond the reader's depth bound is rejected rather than
    /// exhausting the call stack. <see cref="ClientExtensionOutputsJsonReader"/> bounds
    /// <see cref="System.Text.Json.JsonReaderOptions.MaxDepth"/> at 8, so untrusted wire input
    /// cannot force unbounded recursion even inside a single extension's own output value.
    /// </summary>
    [TestMethod]
    public void DeeplyNestedExtensionValueBeyondTheDepthBoundIsRejected()
    {
        string deeplyNestedArray = Fido2TestVectors.BuildDeeplyNestedArray(depth: 70);
        string json = "{\"deep\":" + deeplyNestedArray + "}";

        Assert.ThrowsExactly<Fido2FormatException>(() => ClientExtensionOutputsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }
}
