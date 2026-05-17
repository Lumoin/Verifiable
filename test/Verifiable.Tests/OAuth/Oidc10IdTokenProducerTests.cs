using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="Oidc10IdTokenProducer"/>.
/// </summary>
/// <remarks>
/// The producer's structural shape — what claims it emits, with what
/// values, for a known input — is a wire-format contract. Relying parties
/// validate ID Tokens against fixed expectations; a silent change to the
/// emitted claim set breaks them. The baseline test below is the
/// per-claim regression catch: a fixed input set produces a canonical
/// payload that this test pins, so any future change that adds, removes,
/// renames, or alters a claim for the baseline input fails the assertion.
/// Deliberate changes (e.g. a new claim being emitted by default) need
/// a deliberate baseline update, not a silent passing test.
/// </remarks>
[TestClass]
internal sealed class Oidc10IdTokenProducerTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task PayloadCarriesExpectedClaimsForBaselineInput()
    {
        DateTimeOffset fixedTime = new(2026, 5, 17, 12, 0, 0, TimeSpan.Zero);
        FakeTimeProvider fixedTimeProvider = new();
        fixedTimeProvider.SetUtcNow(fixedTime);

        await using TestHostShell host = new(fixedTimeProvider);

        ImmutableHashSet<ServerCapabilityName> capabilities = ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.OpenIdConnect);
        using VerifierKeyMaterial keys = host.RegisterClient(
            "https://idtoken-baseline.test",
            new Uri("https://idtoken-baseline.test"),
            capabilities);

        const string fixedSubject = "subject-baseline";
        const string fixedScope = "openid";
        const string fixedNonce = "nonce-baseline";
        Uri fixedIssuer = new("https://issuer-baseline.test/");
        const string fixedClientId = "client-baseline";

        RequestContext requestContext = new();
        requestContext.SetServer(host.Server);
        requestContext.SetRegistration(keys.Registration);
        requestContext.SetIssuer(fixedIssuer);

        IssuanceContext issuanceContext = new()
        {
            Registration = keys.Registration,
            Context = requestContext,
            IssuerUri = fixedIssuer,
            Subject = fixedSubject,
            Scope = fixedScope,
            ClientId = fixedClientId,
            IssuedAt = fixedTime,
            Nonce = fixedNonce,
            AuthTime = fixedTime
        };

        TokenProducerOutput output = await Oidc10IdTokenProducer.Instance.BuildAsync(
            issuanceContext,
            new KeyId("kid-baseline"),
            WellKnownJwaValues.Es256,
            TestContext.CancellationToken).ConfigureAwait(false);

        string actualCanonical = CanonicaliseClaims(output.Payload);

        //The baseline below is the canonicalised payload for the fixed
        //inputs above. Any change that legitimately alters the payload —
        //a new claim being emitted by default, a claim type changing, a
        //value formatting change — fails this assertion. If the change is
        //intentional, regenerate the literal by uncommenting the
        //TestContext.WriteLine line below, running the test, and pasting
        //the printed value here.
        //TestContext.WriteLine(actualCanonical);

        const string ExpectedCanonical =
            """
            {"aud":"client-baseline","auth_time":1779019200,"exp":1779022800,"iat":1779019200,"iss":"https://issuer-baseline.test/","nonce":"nonce-baseline","sub":"subject-baseline"}
            """;

        Assert.AreEqual(ExpectedCanonical, actualCanonical,
            "ID Token payload diverged from the baseline. If the change is "
            + "intentional, uncomment the TestContext.WriteLine line in this "
            + "test, copy the printed canonical string, and paste it into "
            + "ExpectedCanonical above. Otherwise the producer regressed.");

        //Sanity check on the header — the test asserts only payload claims
        //since the kid value is the test's own choice, but the algorithm
        //must be what the producer was asked to use.
        Assert.AreEqual(
            WellKnownJwaValues.Es256,
            output.Header[WellKnownJwkMemberNames.Alg],
            "ID Token header must carry the algorithm the producer was asked to use.");
    }


    //Helpers go below the public surface.

    /// <summary>
    /// Serializes a <see cref="JwtPayload"/> to a canonical JSON-shaped
    /// string with claim keys sorted lexicographically. Numbers emit
    /// without quotes; strings emit with quotes. Only the shapes the ID
    /// Token producer actually produces are handled — strings and integer
    /// time values (Unix seconds).
    /// </summary>
    /// <remarks>
    /// Not a general-purpose JSON canonicaliser. It exists only to keep
    /// this regression test independent of the production serializer's
    /// implementation details: any changes to the production serializer
    /// that don't affect claim names or values are tolerated, while
    /// changes to the claim names or values fail the assertion loudly.
    /// </remarks>
    private static string CanonicaliseClaims(JwtPayload payload)
    {
        StringBuilder sb = new();
        sb.Append('{');

        bool first = true;
        foreach(KeyValuePair<string, object> entry in payload.OrderBy(
            e => e.Key, StringComparer.Ordinal))
        {
            if(!first) { sb.Append(','); }
            first = false;

            sb.Append('"').Append(entry.Key).Append("\":");

            switch(entry.Value)
            {
                case string s:
                    sb.Append('"').Append(s).Append('"');
                    break;

                case long l:
                    sb.Append(l.ToString(CultureInfo.InvariantCulture));
                    break;

                case int i:
                    sb.Append(i.ToString(CultureInfo.InvariantCulture));
                    break;

                default:
                    //Unknown shape — render through ToString so failures
                    //surface as a clear diff against the baseline.
                    sb.Append('"').Append(entry.Value).Append('"');
                    break;
            }
        }

        sb.Append('}');
        return sb.ToString();
    }
}
