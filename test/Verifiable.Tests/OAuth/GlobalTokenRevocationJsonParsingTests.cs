using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.Json;
using Verifiable.OAuth.Logout;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Unit tests for the default System.Text.Json Global Token Revocation request
/// parser (<see cref="GlobalTokenRevocationJsonParsing"/>) — the JSON side of the
/// serialization firewall. STRICT: anything that is not a JSON object carrying a
/// well-formed <c>sub_id</c> Subject Identifier parses to <see langword="null"/>
/// (the endpoint then answers HTTP 400), and the parser never throws.
/// </summary>
[TestClass]
internal sealed class GlobalTokenRevocationJsonParsingTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Invokes the parser with a fresh per-call context.</summary>
    private async ValueTask<GlobalTokenRevocationRequest?> ParseAsync(string body) =>
        await GlobalTokenRevocationJsonParsing.ParseGlobalTokenRevocationRequest(
            body, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>An <c>iss_sub</c> sub_id projects to the issuer/subject members.</summary>
    [TestMethod]
    public async Task ParsesIssuerSubjectSubId()
    {
        GlobalTokenRevocationRequest? request = await ParseAsync(
            /*lang=json,strict*/ "{\"sub_id\":{\"format\":\"iss_sub\",\"iss\":\"https://issuer.test\",\"sub\":\"abc\"}}")
            .ConfigureAwait(false);

        Assert.IsNotNull(request);
        Assert.IsTrue(SubjectIdentifierFormats.IsIssuerSubject(request.SubId.Format));
        Assert.IsTrue(request.SubId.IsValidForKnownFormat());
        Assert.AreEqual("https://issuer.test", request.SubId.Members[SubjectIdentifierMemberNames.Iss]);
        Assert.AreEqual("abc", request.SubId.Members[SubjectIdentifierMemberNames.Sub]);
    }


    /// <summary>An <c>email</c> sub_id parses and validates.</summary>
    [TestMethod]
    public async Task ParsesEmailSubId()
    {
        GlobalTokenRevocationRequest? request = await ParseAsync(
            /*lang=json,strict*/ "{\"sub_id\":{\"format\":\"email\",\"email\":\"user@example.test\"}}")
            .ConfigureAwait(false);

        Assert.IsNotNull(request);
        Assert.IsTrue(SubjectIdentifierFormats.IsEmail(request.SubId.Format));
        Assert.IsTrue(request.SubId.IsValidForKnownFormat());
    }


    /// <summary>An <c>opaque</c> sub_id parses and validates.</summary>
    [TestMethod]
    public async Task ParsesOpaqueSubId()
    {
        GlobalTokenRevocationRequest? request = await ParseAsync(
            /*lang=json,strict*/ "{\"sub_id\":{\"format\":\"opaque\",\"id\":\"opaque-123\"}}")
            .ConfigureAwait(false);

        Assert.IsNotNull(request);
        Assert.IsTrue(SubjectIdentifierFormats.IsOpaque(request.SubId.Format));
        Assert.IsTrue(request.SubId.IsValidForKnownFormat());
    }


    /// <summary>A missing <c>sub_id</c> (required, §3) parses to null.</summary>
    [TestMethod]
    public async Task ReturnsNullWhenSubIdMissing() =>
        Assert.IsNull(await ParseAsync(/*lang=json,strict*/ "{\"other\":1}").ConfigureAwait(false));


    /// <summary>A non-object <c>sub_id</c> parses to null.</summary>
    [TestMethod]
    public async Task ReturnsNullWhenSubIdNotAnObject() =>
        Assert.IsNull(await ParseAsync(/*lang=json,strict*/ "{\"sub_id\":\"nope\"}").ConfigureAwait(false));


    /// <summary>A <c>sub_id</c> object without <c>format</c> is not a valid Subject Identifier.</summary>
    [TestMethod]
    public async Task ReturnsNullWhenSubIdLacksFormat() =>
        Assert.IsNull(await ParseAsync(
            /*lang=json,strict*/ "{\"sub_id\":{\"email\":\"user@example.test\"}}").ConfigureAwait(false));


    /// <summary>A body that is not a JSON object parses to null.</summary>
    [TestMethod]
    public async Task ReturnsNullWhenBodyNotAnObject() =>
        Assert.IsNull(await ParseAsync(/*lang=json,strict*/ "[1,2,3]").ConfigureAwait(false));


    /// <summary>Malformed JSON parses to null rather than throwing.</summary>
    [TestMethod]
    public async Task ReturnsNullOnMalformedJson() =>
        Assert.IsNull(await ParseAsync("not json").ConfigureAwait(false));
}
