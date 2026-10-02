using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Core.SecurityEvents;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Logout;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Server-side Global Token Revocation (draft-parecki-oauth-global-token-revocation),
/// driven through the real dispatch pipeline. The library owns the wire — client
/// authentication, body read, the §3 status-code mapping, and the fail-closed
/// candidate gate; the application owns the parse (the serialization firewall) and
/// the revoke-subject fan-out behind <see cref="RevokeSubjectTokensDelegate"/>. The
/// <c>sub_id</c> is the neutral <see cref="SubjectIdentifier"/> reused from the
/// Shared Signals subsystem. The parse seam here is supplied by the test, exactly
/// as the all-capabilities suite supplies the AuthZEN/SSF parse lambdas.
/// </summary>
[TestClass]
internal sealed class GlobalTokenRevocationServerTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The client identifier registered for the tests.</summary>
    private const string ClientId = "https://gtr.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static Uri ClientBaseUri { get; } = new("https://gtr.client.test");

    /// <summary>The single capability the Global Token Revocation endpoint requires.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> GtrCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation);

    /// <summary>A representative iss_sub request body.</summary>
    private const string SubIdJson =
        /*lang=json,strict*/ "{\"sub_id\":{\"format\":\"iss_sub\",\"iss\":\"https://issuer.test\",\"sub\":\"subject-123\"}}";


    /// <summary>
    /// A wired endpoint authenticates the client, delivers the JSON body to the
    /// parse seam, relays the parsed Subject Identifier to the revoke-subject
    /// seam, and answers §3 with 204 when revocation is initiated.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationInitiatedReturns204AndRelaysSubject()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, GtrCapabilities).ConfigureAwait(false);

        SubjectIdentifier? revokedSubject = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);


            //Exercise the PRODUCTION JSON parser (Verifiable.Json) end-to-end — the
            //body's sub_id is parsed by the default parser, not a test lambda.

            _ = candidateIntegration.UseDefaultGlobalTokenRevocationJsonParsing();


            candidateIntegration.RevokeSubjectTokensAsync = (subId, _, _, _) =>
            {
                revokedSubject = subId;

                return ValueTask.FromResult(GlobalTokenRevocationOutcome.Initiated);
            };
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.GlobalTokenRevocation,
            "POST",
            new RequestFields(),
            SubIdJson,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(204, response.StatusCode, response.Body);
        Assert.AreEqual(string.Empty, response.Body);
        Assert.IsNotNull(revokedSubject);
        Assert.IsTrue(SubjectIdentifierFormats.IsIssuerSubject(revokedSubject.Format),
            "The default parser must project sub_id into the iss_sub format.");
        Assert.IsTrue(revokedSubject.IsValidForKnownFormat());
        Assert.AreEqual("https://issuer.test", revokedSubject.Members[SubjectIdentifierMemberNames.Iss]);
        Assert.AreEqual("subject-123", revokedSubject.Members[SubjectIdentifierMemberNames.Sub]);
    }


    /// <summary>
    /// §3.5: an unauthenticated request is rejected 401 <c>invalid_client</c>
    /// before the body is parsed or any token is revoked.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationRejectsUnauthenticatedClient()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, GtrCapabilities).ConfigureAwait(false);

        bool parseInvoked = false;
        bool revokeInvoked = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(false);

            candidateIntegration.ParseGlobalTokenRevocationRequestAsync = (_, _, _) =>
            {
                parseInvoked = true;

                return ValueTask.FromResult<GlobalTokenRevocationRequest?>(null);
            };

            candidateIntegration.RevokeSubjectTokensAsync = (_, _, _, _) =>
            {
                revokeInvoked = true;

                return ValueTask.FromResult(GlobalTokenRevocationOutcome.Initiated);
            };
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.GlobalTokenRevocation,
            "POST",
            new RequestFields(),
            SubIdJson,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidClient, response.Body, StringComparison.Ordinal);
        Assert.IsFalse(parseInvoked, "Authentication must gate the body parse.");
        Assert.IsFalse(revokeInvoked, "A failed authentication must not revoke anything.");
    }


    /// <summary>
    /// §3 status-code mapping: the application-determined outcomes
    /// (<see cref="GlobalTokenRevocationOutcome.SubjectNotFound"/> /
    /// <see cref="GlobalTokenRevocationOutcome.Forbidden"/> /
    /// <see cref="GlobalTokenRevocationOutcome.Unprocessable"/>) map to 404 / 403 / 422.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationMapsOutcomesToStatusCodes()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, GtrCapabilities).ConfigureAwait(false);

        GlobalTokenRevocationOutcome outcome = GlobalTokenRevocationOutcome.SubjectNotFound;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.ParseGlobalTokenRevocationRequestAsync = static (_, _, _) =>
                ValueTask.FromResult<GlobalTokenRevocationRequest?>(new GlobalTokenRevocationRequest
                {
                    SubId = SubjectIdentifier.Email("user@example.test")
                });

            candidateIntegration.RevokeSubjectTokensAsync = (_, _, _, _) => ValueTask.FromResult(outcome);
        }).ConfigureAwait(false);

        async ValueTask<int> DispatchStatusAsync()
        {
            ServerHttpResponse response = await host.DispatchAtEndpointAsync(
                material.Registration.TenantId.Value,
                WellKnownEndpointNames.GlobalTokenRevocation,
                "POST",
                new RequestFields(),
                SubIdJson,
                [],
                TestContext.CancellationToken).ConfigureAwait(false);

            return response.StatusCode;
        }

        outcome = GlobalTokenRevocationOutcome.SubjectNotFound;
        Assert.AreEqual(404, await DispatchStatusAsync().ConfigureAwait(false));

        outcome = GlobalTokenRevocationOutcome.Forbidden;
        Assert.AreEqual(403, await DispatchStatusAsync().ConfigureAwait(false));

        outcome = GlobalTokenRevocationOutcome.Unprocessable;
        Assert.AreEqual(422, await DispatchStatusAsync().ConfigureAwait(false));
    }


    /// <summary>
    /// §3: a body that does not parse (the seam returns <see langword="null"/>)
    /// is a 400 <c>invalid_request</c> — the revoke seam is never reached.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationReturns400OnUnparseableBody()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, GtrCapabilities).ConfigureAwait(false);

        bool revokeInvoked = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.ParseGlobalTokenRevocationRequestAsync = static (_, _, _) =>
                ValueTask.FromResult<GlobalTokenRevocationRequest?>(null);

            candidateIntegration.RevokeSubjectTokensAsync = (_, _, _, _) =>
            {
                revokeInvoked = true;

                return ValueTask.FromResult(GlobalTokenRevocationOutcome.Initiated);
            };
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.GlobalTokenRevocation,
            "POST",
            new RequestFields(),
            "not json",
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body, StringComparison.Ordinal);
        Assert.IsFalse(revokeInvoked);
    }


    /// <summary>
    /// §3: a parsed request whose <c>sub_id</c> is not a well-formed, known-format
    /// Subject Identifier is a 400 — the library validates the identifier before
    /// dropping out to the revoke seam.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationReturns400OnInvalidSubjectIdentifier()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, GtrCapabilities).ConfigureAwait(false);

        bool revokeInvoked = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);


            //An "email" format with no email member fails IsValidForKnownFormat().

            candidateIntegration.ParseGlobalTokenRevocationRequestAsync = static (_, _, _) =>
                ValueTask.FromResult<GlobalTokenRevocationRequest?>(new GlobalTokenRevocationRequest
                {
                    SubId = new SubjectIdentifier
                    {
                        Format = SubjectIdentifierFormats.Email,
                        Members = new Dictionary<string, object>(StringComparer.Ordinal)
                    }
                });

            candidateIntegration.RevokeSubjectTokensAsync = (_, _, _, _) =>
            {
                revokeInvoked = true;

                return ValueTask.FromResult(GlobalTokenRevocationOutcome.Initiated);
            };
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.GlobalTokenRevocation,
            "POST",
            new RequestFields(),
            SubIdJson,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.IsFalse(revokeInvoked, "An invalid sub_id must not reach the revoke seam.");
    }


    /// <summary>
    /// A posted <c>sub_id</c> that carries a member its format does not describe, or an <c>aliases</c> element
    /// whose format is blank, is answered 400 <c>invalid_request</c>, and the revoke seam is not called. The
    /// body is posted over the host's loopback listener and read by the default JSON parser, so the identifier
    /// reaches the endpoint as the wire carries it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "Every member
    /// within a Subject Identifier MUST match the rules specified for that member by this specification or by
    /// a Subject Identifier's Identifier Format. A Subject Identifier MUST NOT contain any members prohibited
    /// or not described by its Identifier Format and MUST contain all members required by its Identifier
    /// Format." The check covers the members present, their JSON types, the members a format does not describe
    /// and the reserved <c>format</c> member, and the rules on a member's value are the caller's, which
    /// <see cref="SubjectIdentifier.IsValidForKnownFormat"/> names. A blank value names no format: "A Subject
    /// Identifier MUST conform to a specific Identifier Format and MUST contain a "format" member whose value
    /// is the name of that Identifier Format."
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.2">OpenID Shared Signals Framework 1.0 Section 3.5.2</see>:
    /// "Subject Identifiers of this format MUST contain the following members:" <c>issuer</c> and
    /// <c>assertion_id</c>.
    /// </summary>
    /// <param name="subIdJson">The request body posted to the endpoint.</param>
    [TestMethod]
    [DataRow(/*lang=json,strict*/ "{\"sub_id\":{\"format\":\"iss_sub\",\"iss\":\"https://issuer.test\",\"sub\":\"subject-123\",\"extra\":\"x\"}}", DisplayName = "an iss_sub identifier with an extra member")]
    [DataRow(/*lang=json,strict*/ "{\"sub_id\":{\"format\":\"jwt_id\",\"iss\":\"https://issuer.test\",\"jti\":\"jwt-123\",\"extra\":\"x\"}}", DisplayName = "a jwt_id identifier with an extra member")]
    [DataRow(/*lang=json,strict*/ "{\"sub_id\":{\"format\":\"aliases\",\"identifiers\":[{\"format\":\" \",\"email\":\"alice@example.com\"}]}}", DisplayName = "an aliases identifier whose one element has a blank format")]
    [DataRow(/*lang=json,strict*/ "{\"sub_id\":{\"format\":\"saml_assertion_id\",\"issuer\":\"https://idp.test\",\"assertion_id\":\"_8e8dc5f69a98\",\"extra\":\"x\"}}", DisplayName = "a saml_assertion_id identifier with an extra member")]
    public async Task ASubjectIdentifierWithAMemberItsFormatDoesNotDescribeIsRefusedAsync(string subIdJson)
    {
        (int statusCode, string body, int revokeCallCount, _) = await PostOverTheLoopbackListenerAsync(subIdJson).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        using JsonDocument error = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_request", error.RootElement.GetProperty("error").GetString(), body);
        Assert.AreEqual(0, revokeCallCount, "A sub_id that breaks the rules of its format must not reach the revoke seam.");
    }


    /// <summary>
    /// A posted <c>sub_id</c> whose shape breaks its format is answered 400 <c>invalid_request</c>, and the
    /// revoke seam is not called: an <c>ip-addresses</c> member that is a string, and a <c>complex</c>
    /// subject whose member is itself <c>complex</c>. The body is posted over the host's loopback listener and
    /// read by the default JSON parser.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.3">OpenID Shared Signals Framework 1.0 Section 3.5.3</see>:
    /// "The value MUST be in the format of an array of strings, each one of which represents the [RFC4001]
    /// string representation of an IP address."
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3">Section 3.3</see>:
    /// "A Complex Subject Member has a name and a value that is a JSON [RFC7159] object that has a format
    /// field, and one or more Simple Subject Members."
    /// </summary>
    /// <param name="subIdJson">The request body posted to the endpoint.</param>
    [TestMethod]
    [DataRow(/*lang=json,strict*/ "{\"sub_id\":{\"format\":\"ip-addresses\",\"ip-addresses\":\"10.0.0.1\"}}", DisplayName = "an ip-addresses identifier whose member is a string")]
    [DataRow(/*lang=json,strict*/ "{\"sub_id\":{\"format\":\"complex\",\"user\":{\"format\":\"complex\",\"user\":{\"format\":\"email\",\"email\":\"bar@example.com\"}}}}", DisplayName = "a complex subject whose user member is itself complex")]
    public async Task ASubjectIdentifierWhoseShapeBreaksItsFormatIsRefusedAsync(string subIdJson)
    {
        (int statusCode, string body, int revokeCallCount, _) = await PostOverTheLoopbackListenerAsync(subIdJson).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        using JsonDocument error = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_request", error.RootElement.GetProperty("error").GetString(), body);
        Assert.AreEqual(0, revokeCallCount, "A sub_id whose shape breaks its format must not reach the revoke seam.");
    }


    /// <summary>
    /// A posted <c>sub_id</c> that is a well-formed <c>ip-addresses</c> or <c>aliases</c> identifier, read by
    /// the default JSON parser from the body the host's loopback listener received, reaches the revoke seam
    /// once with an identifier of that format, and the endpoint answers 204 with an empty body.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-parecki-oauth-global-token-revocation-06#section-3.4.1">draft-parecki-oauth-global-token-revocation-06 Section 3.4.1</see>:
    /// "To indicate that the request was successful and revocation of the requested set of tokens has begun,
    /// the server returns an HTTP 204 response."
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.3">OpenID Shared Signals Framework 1.0 Section 3.5.3</see>:
    /// "The value MUST be in the format of an array of strings, each one of which represents the [RFC4001]
    /// string representation of an IP address."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 Section 3.2.8</see>: "Subject
    /// Identifiers in this format MUST contain an "identifiers" member whose value is a JSON array containing one
    /// or more Subject Identifiers." and ""aliases" Subject Identifiers MUST NOT be nested, i.e., the
    /// "identifiers" member of an "aliases" Subject Identifier MUST NOT contain a Subject Identifier in the
    /// Aliases Identifier Format." The second sentence forbids that nesting only, so an <c>aliases</c>
    /// identifier whose one element is a <c>complex</c> subject of
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3">OpenID Shared Signals Framework 1.0 Section 3.3</see>
    /// reaches the revoke seam.
    /// </summary>
    /// <param name="subIdJson">The request body posted to the endpoint.</param>
    /// <param name="expectedFormat">The format of the identifier the revoke seam receives.</param>
    [TestMethod]
    [DataRow(/*lang=json,strict*/ "{\"sub_id\":{\"format\":\"ip-addresses\",\"ip-addresses\":[\"10.29.37.75\",\"2001:db8::1\"]}}", "ip-addresses", DisplayName = "an ip-addresses identifier of two addresses")]
    [DataRow(/*lang=json,strict*/ "{\"sub_id\":{\"format\":\"aliases\",\"identifiers\":[{\"format\":\"email\",\"email\":\"user@example.com\"},{\"format\":\"iss_sub\",\"iss\":\"https://issuer.test\",\"sub\":\"subject-123\"}]}}", "aliases", DisplayName = "an aliases identifier of an email and an iss_sub identifier")]
    [DataRow(/*lang=json,strict*/ "{\"sub_id\":{\"format\":\"aliases\",\"identifiers\":[{\"format\":\"complex\",\"user\":{\"format\":\"email\",\"email\":\"bar@example.com\"}}]}}", "aliases", DisplayName = "an aliases identifier whose one element is a complex subject")]
    public async Task AWellFormedIpAddressesOrAliasesIdentifierReachesTheRevokeSeamAsync(string subIdJson, string expectedFormat)
    {
        (int statusCode, string body, int revokeCallCount, SubjectIdentifier? revokedSubject) =
            await PostOverTheLoopbackListenerAsync(subIdJson).ConfigureAwait(false);

        Assert.AreEqual(204, statusCode, body);
        Assert.AreEqual(string.Empty, body);
        Assert.AreEqual(1, revokeCallCount);
        Assert.IsNotNull(revokedSubject);
        Assert.AreEqual(expectedFormat, revokedSubject.Format);
        Assert.IsTrue(revokedSubject.IsValidForKnownFormat());
    }


    /// <summary>
    /// A posted <c>sub_id</c> that is a chain of 32 Subject Identifiers, <c>aliases</c> and <c>complex</c>
    /// alternating with an <c>aliases</c> identifier outermost and an <c>email</c> identifier innermost, read by
    /// the default JSON parser from the body the host's loopback listener received, reaches the revoke seam
    /// once as an <c>aliases</c> identifier, and the endpoint answers 204 with an empty body. The innermost
    /// identifier stands at depth 32, at the nesting bound of <see cref="SubjectIdentifier.IsValidForKnownFormat"/>,
    /// this library's resource rule; each link is one the texts admit.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-parecki-oauth-global-token-revocation-06#section-3.4.1">draft-parecki-oauth-global-token-revocation-06 Section 3.4.1</see>:
    /// "To indicate that the request was successful and revocation of the requested set of tokens has begun,
    /// the server returns an HTTP 204 response."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 Section 3.2.8</see>:
    /// ""aliases" Subject Identifiers MUST NOT be nested, i.e., the "identifiers" member of an "aliases"
    /// Subject Identifier MUST NOT contain a Subject Identifier in the Aliases Identifier Format." The sentence
    /// forbids that nesting only, and
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3">OpenID Shared Signals Framework 1.0 Section 3.3</see>
    /// makes each member of a complex subject a Subject Identifier.
    /// </summary>
    [TestMethod]
    public async Task AChainOfAliasesAndComplexAtTheNestingBoundReachesTheRevokeSeamAsync()
    {
        (int statusCode, string body, int revokeCallCount, SubjectIdentifier? revokedSubject) =
            await PostOverTheLoopbackListenerAsync(WriteAlternatingChainBody(32)).ConfigureAwait(false);

        Assert.AreEqual(204, statusCode, body);
        Assert.AreEqual(string.Empty, body);
        Assert.AreEqual(1, revokeCallCount);
        Assert.IsNotNull(revokedSubject);
        Assert.AreEqual("aliases", revokedSubject.Format);
        Assert.IsTrue(revokedSubject.IsValidForKnownFormat());
    }


    /// <summary>
    /// A posted <c>sub_id</c> that is a chain of 33 Subject Identifiers, <c>aliases</c> and <c>complex</c>
    /// alternating with an <c>aliases</c> identifier outermost and an <c>email</c> identifier innermost, is
    /// answered 400 <c>invalid_request</c>, and the revoke seam is not called. The default JSON parser reads the
    /// body at its default depth of 64, deeper than the body's 50 JSON levels, so the identifier reaches the
    /// endpoint's check whole; its innermost identifier stands at depth 33, one past the nesting bound of 32 of
    /// <see cref="SubjectIdentifier.IsValidForKnownFormat"/>, this library's resource rule, and every link
    /// above it is one the format rules admit, so the bound alone refuses it.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-parecki-oauth-global-token-revocation-06#section-3.4.2">draft-parecki-oauth-global-token-revocation-06 Section 3.4.2</see>,
    /// 400 Bad Request: "The request was malformed, e.g. an unrecognized or unsupported type of subject
    /// identifier."
    /// </summary>
    [TestMethod]
    public async Task AChainOfAliasesAndComplexPastTheNestingBoundIsRefusedAsync()
    {
        (int statusCode, string body, int revokeCallCount, _) =
            await PostOverTheLoopbackListenerAsync(WriteAlternatingChainBody(33)).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        using JsonDocument error = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_request", error.RootElement.GetProperty("error").GetString(), body);
        Assert.AreEqual(0, revokeCallCount, "A sub_id nested past the bound must not reach the revoke seam.");
    }


    /// <summary>
    /// Writes a request body whose <c>sub_id</c> is a chain of <paramref name="identifierCount"/> Subject
    /// Identifiers nested in one another: an <c>aliases</c> identifier outermost, <c>aliases</c> identifiers at
    /// the odd depths and <c>complex</c> subjects, each holding the next identifier as its <c>user</c> member,
    /// at the even depths, and an <c>email</c> identifier innermost, at depth
    /// <paramref name="identifierCount"/>. Each <c>aliases</c> level is two JSON levels (an object and an
    /// array) and every other identifier one, so the body of a chain of 33 is 50 JSON levels deep.
    /// </summary>
    /// <param name="identifierCount">The number of identifiers on the chain, two or more.</param>
    /// <returns>The JSON request body.</returns>
    private static string WriteAlternatingChainBody(int identifierCount)
    {
        string nested = /*lang=json,strict*/ "{\"format\":\"email\",\"email\":\"user@example.com\"}";
        for(int depth = identifierCount - 1; depth >= 1; depth--)
        {
            nested = (depth % 2) switch
            {
                1 => $"{{\"format\":\"aliases\",\"identifiers\":[{nested}]}}",
                _ => $"{{\"format\":\"complex\",\"user\":{nested}}}"
            };
        }

        return $"{{\"sub_id\":{nested}}}";
    }


    /// <summary>
    /// Posts <paramref name="subIdJson"/> to the Global Token Revocation endpoint over the host's loopback
    /// listener, with client authentication accepted, the default JSON parser wired and a revoke seam that
    /// counts its calls and keeps the identifier it last received.
    /// </summary>
    /// <param name="subIdJson">The request body posted to the endpoint.</param>
    /// <returns>
    /// The status code and body of the answer, the number of calls the revoke seam received and the identifier
    /// it last received (<see langword="null"/> when it was not called).
    /// </returns>
    private async Task<(int StatusCode, string Body, int RevokeCallCount, SubjectIdentifier? RevokedSubject)> PostOverTheLoopbackListenerAsync(string subIdJson)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, GtrCapabilities).ConfigureAwait(false);

        int revokeCallCount = 0;
        SubjectIdentifier? revokedSubject = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);

            _ = candidateIntegration.UseDefaultGlobalTokenRevocationJsonParsing();

            candidateIntegration.RevokeSubjectTokensAsync = (subId, _, _, _) =>
            {
                _ = Interlocked.Increment(ref revokeCallCount);
                revokedSubject = subId;

                return ValueTask.FromResult(GlobalTokenRevocationOutcome.Initiated);
            };
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer listener = host.Host("default");
        Uri endpoint = TestHostShell.ComposeEndpointUri(
            listener.HttpBaseAddress!, material.Registration.TenantId.Value, WellKnownEndpointNames.GlobalTokenRevocation);

        using StringContent content = new(subIdJson, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage response = await listener.SharedHttpClient!.PostAsync(
            endpoint, content, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return ((int)response.StatusCode, body, revokeCallCount, revokedSubject);
    }


    /// <summary>
    /// Fail-closed: declaring the capability without wiring the revoke-subject
    /// seam leaves the endpoint absent from the chain, so the request returns 404.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationEndpointAbsentWhenSeamUnwired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, GtrCapabilities).ConfigureAwait(false);

        //Client authentication and the parser are wired but the revoke-subject
        //seam is not — the gate requires all three, so the endpoint must not exist.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.ParseGlobalTokenRevocationRequestAsync = static (_, _, _) =>
                ValueTask.FromResult<GlobalTokenRevocationRequest?>(null);
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.GlobalTokenRevocation,
            "POST",
            new RequestFields(),
            SubIdJson,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "An unwired revoke-subject seam must leave the endpoint absent (fail-closed).");
    }
}
