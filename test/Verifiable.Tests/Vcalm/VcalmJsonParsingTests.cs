using System.Text.Json;
using Verifiable.Core;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// The reason each VCALM request parser of the JSON leaf (<see cref="VcalmJsonParsing"/>) reports for a body it refuses.
/// A body the JSON reader cannot read is not a JSON text and reports <see cref="VcalmParseFailure.Unparseable"/>, the
/// failure the endpoints answer with the
/// <see href="https://www.w3.org/TR/vc-data-model-2.0/#PARSING_ERROR">VC Data Model 2.0 Section 7.2</see> parsing-error
/// type; a JSON text whose content the parser refuses reports <see cref="VcalmParseFailure.Malformed"/>, answered with
/// the malformed-value type.
/// </summary>
[TestClass]
internal sealed class VcalmJsonParsingTests
{
    /// <summary>The MSTest context of the running test; its cancellation token bounds every parse in this class.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The serializer options carrying the credential, presentation and DCQL converters the parsers read with.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see>: "A JSON text is a
    /// serialized value." with the grammar <c>JSON-text = ws value ws</c>. The text <c>{</c> opens an object it never
    /// closes, so the JSON reader refuses it and each request parser reports
    /// <see cref="VcalmParseFailure.Unparseable"/>.
    /// </summary>
    /// <param name="parser">The name of the <see cref="VcalmJsonParsing"/> factory whose parser reads the text.</param>
    [TestMethod]
    [DataRow("CreateCredentialParser")]
    [DataRow("CreatePresentationParser")]
    [DataRow("CreateIssueParser")]
    [DataRow("CreateDeriveParser")]
    [DataRow("CreateCreatePresentationParser")]
    [DataRow("CreateUpdateStatusParser")]
    [DataRow("CreateStatusListParser")]
    [DataRow("CreateExchangeParser")]
    [DataRow("CreateExchangeMessageParser")]
    [DataRow("CreateWorkflowParser")]
    [DataRow("CreateCallbackParser")]
    [DataRow("CreateInviteRequestParser")]
    public async Task TextThatDoesNotReadIsUnparseable(string parser)
    {
        VcalmParseFailure failure = await ParseAsync(parser, "{").ConfigureAwait(false);

        Assert.AreEqual(VcalmParseFailure.Unparseable, failure, parser);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-9">RFC 8259 Section 9</see>: "An implementation may set
    /// limits on the maximum depth of nesting." The text of 65 nested arrays around <c>0</c> is a JSON text by
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see>'s grammar, nested beyond
    /// the depth of 64 the JSON reader admits, so the reader refuses it and the credential verify parser reports
    /// <see cref="VcalmParseFailure.Unparseable"/>, the failure the endpoints answer with the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#PARSING_ERROR">VC Data Model 2.0 Section 7.2</see> type
    /// "There was an error while parsing input."
    /// </summary>
    [TestMethod]
    public async Task TextNestedBeyondTheReaderDepthIsUnparseable()
    {
        string text = new string('[', 65) + "0" + new string(']', 65);

        VcalmParseFailure failure = await ParseAsync("CreateCredentialParser", text).ConfigureAwait(false);

        Assert.AreEqual(VcalmParseFailure.Unparseable, failure);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>:
    /// "The value associated with a particular property is malformed." The text <c>[]</c> reads as a JSON text, an array
    /// where every VCALM request body is an object, so each request parser reports
    /// <see cref="VcalmParseFailure.Malformed"/>.
    /// </summary>
    /// <param name="parser">The name of the <see cref="VcalmJsonParsing"/> factory whose parser reads the text.</param>
    [TestMethod]
    [DataRow("CreateCredentialParser")]
    [DataRow("CreatePresentationParser")]
    [DataRow("CreateIssueParser")]
    [DataRow("CreateDeriveParser")]
    [DataRow("CreateCreatePresentationParser")]
    [DataRow("CreateUpdateStatusParser")]
    [DataRow("CreateStatusListParser")]
    [DataRow("CreateExchangeParser")]
    [DataRow("CreateExchangeMessageParser")]
    [DataRow("CreateWorkflowParser")]
    [DataRow("CreateCallbackParser")]
    [DataRow("CreateInviteRequestParser")]
    public async Task TopLevelArrayIsMalformed(string parser)
    {
        VcalmParseFailure failure = await ParseAsync(parser, "[]").ConfigureAwait(false);

        Assert.AreEqual(VcalmParseFailure.Malformed, failure, parser);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>:
    /// "The value associated with a particular property is malformed." Each text reads as a JSON object one of whose
    /// members is a number where its request names an object or a string, so the request parser reports
    /// <see cref="VcalmParseFailure.Malformed"/>.
    /// </summary>
    /// <param name="parser">The name of the <see cref="VcalmJsonParsing"/> factory whose parser reads the text.</param>
    /// <param name="text">The JSON text with the member of the wrong kind.</param>
    [TestMethod]
    [DataRow("CreateCredentialParser", "{\"verifiableCredential\":7}")]
    [DataRow("CreatePresentationParser", "{\"presentation\":7}")]
    [DataRow("CreateIssueParser", "{\"credential\":7}")]
    [DataRow("CreateDeriveParser", "{\"verifiableCredential\":7}")]
    [DataRow("CreateCreatePresentationParser", "{\"presentation\":7}")]
    [DataRow("CreateUpdateStatusParser", "{\"credentialId\":7,\"credentialStatus\":{},\"status\":true}")]
    [DataRow("CreateStatusListParser", "{\"statusPurpose\":7}")]
    [DataRow("CreateExchangeMessageParser", "{\"redirectUrl\":7}")]
    [DataRow("CreateWorkflowParser", "{\"initialStep\":7,\"steps\":{}}")]
    [DataRow("CreateCallbackParser", "{\"event\":7}")]
    [DataRow("CreateInviteRequestParser", "{\"url\":7}")]
    public async Task MemberOfTheWrongKindIsMalformed(string parser, string text)
    {
        VcalmParseFailure failure = await ParseAsync(parser, text).ConfigureAwait(false);

        Assert.AreEqual(VcalmParseFailure.Malformed, failure, parser);
    }


    /// <summary>
    /// Reads <paramref name="text"/> with the parser the <see cref="VcalmJsonParsing"/> factory named
    /// <paramref name="parser"/> builds, bounded by this test's cancellation token, and returns the failure it reports.
    /// </summary>
    /// <param name="parser">The name of the factory.</param>
    /// <param name="text">The request body text.</param>
    /// <returns>The parse failure the request carries.</returns>
    private async Task<VcalmParseFailure> ParseAsync(string parser, string text)
    {
        ExchangeContext context = new();
        CancellationToken cancellationToken = TestContext.CancellationToken;

        return parser switch
        {
            "CreateCredentialParser" =>
                (await VcalmJsonParsing.CreateCredentialParser(JsonOptions)(text, context, cancellationToken).ConfigureAwait(false))!.Failure,
            "CreatePresentationParser" =>
                (await VcalmJsonParsing.CreatePresentationParser(JsonOptions)(text, context, cancellationToken).ConfigureAwait(false))!.Failure,
            "CreateIssueParser" =>
                (await VcalmJsonParsing.CreateIssueParser(JsonOptions)(text, context, cancellationToken).ConfigureAwait(false))!.Failure,
            "CreateDeriveParser" =>
                (await VcalmJsonParsing.CreateDeriveParser(JsonOptions)(text, context, cancellationToken).ConfigureAwait(false))!.Failure,
            "CreateCreatePresentationParser" =>
                (await VcalmJsonParsing.CreateCreatePresentationParser(JsonOptions)(text, context, cancellationToken).ConfigureAwait(false))!.Failure,
            "CreateUpdateStatusParser" =>
                (await VcalmJsonParsing.CreateUpdateStatusParser()(text, context, cancellationToken).ConfigureAwait(false))!.Failure,
            "CreateStatusListParser" =>
                (await VcalmJsonParsing.CreateStatusListParser()(text, context, cancellationToken).ConfigureAwait(false))!.Failure,
            "CreateExchangeParser" =>
                (await VcalmJsonParsing.CreateExchangeParser()(text, context, cancellationToken).ConfigureAwait(false))!.Failure,
            "CreateExchangeMessageParser" =>
                (await VcalmJsonParsing.CreateExchangeMessageParser(JsonOptions)(text, context, cancellationToken).ConfigureAwait(false))!.Failure,
            "CreateWorkflowParser" =>
                (await VcalmJsonParsing.CreateWorkflowParser()(text, context, cancellationToken).ConfigureAwait(false))!.Failure,
            "CreateCallbackParser" =>
                (await VcalmJsonParsing.CreateCallbackParser()(text, context, cancellationToken).ConfigureAwait(false))!.Failure,
            "CreateInviteRequestParser" =>
                (await VcalmJsonParsing.CreateInviteRequestParser()(text, context, cancellationToken).ConfigureAwait(false))!.Failure,
            _ => throw new ArgumentOutOfRangeException(nameof(parser), parser, "No VCALM request parser factory has that name.")
        };
    }
}
