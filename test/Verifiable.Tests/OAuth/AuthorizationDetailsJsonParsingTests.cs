using Verifiable.Core;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The shipped default RFC 9396 <c>authorization_details</c> parser
/// (<see cref="AuthorizationDetailsJsonParsing"/>) — the JSON side of the
/// <c>Verifiable.OAuth</c> serialization firewall. Structure-strict (array of typed objects),
/// semantics-agnostic (the library applies the per-type shape checks after the parse). It
/// produces the generic <see cref="AuthorizationDetail"/>: the §2 <c>type</c>, the §2.2 common
/// fields, and every type-specific member preserved verbatim in
/// <see cref="AuthorizationDetail.ExtensionData"/>.
/// </summary>
[TestClass]
internal sealed class AuthorizationDetailsJsonParsingTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A full <c>openid_credential</c> entry parses with its type and the RFC 9396 §2.2
    /// <c>locations</c> common field; the type-specific <c>credential_configuration_id</c> and an
    /// unknown member are preserved verbatim in the extension data for the handler to read.
    /// </summary>
    [TestMethod]
    public async Task ParsesFullEntryAndPreservesTypeSpecificMembers()
    {
        const string json = """
            [{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential",
              "locations":["https://credential-issuer.example.com"],"claims":[{"path":["degree"]}]}]
            """;

        IReadOnlyList<AuthorizationDetail>? details =
            await AuthorizationDetailsJsonParsing.ParseAuthorizationDetails(
                json, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(details);
        Assert.HasCount(1, details!);

        AuthorizationDetail detail = details![0];
        Assert.AreEqual("openid_credential", detail.Type);
        Assert.IsNotNull(detail.Locations);
        Assert.AreEqual("https://credential-issuer.example.com", detail.Locations![0]);

        //The type-specific members are carried verbatim, not promoted to typed slots.
        Assert.IsTrue(detail.ExtensionData.ContainsKey("credential_configuration_id"));
        Assert.IsTrue(detail.ExtensionData.ContainsKey("claims"));

        //The openid_credential handler reads its required field from the extension data.
        CredentialAuthorizationDetail projected = OpenIdCredentialAuthorizationDetailHandler.Project(detail);
        Assert.AreEqual("UniversityDegreeCredential", projected.CredentialConfigurationId);
        Assert.AreEqual("https://credential-issuer.example.com", projected.Locations![0]);
    }


    /// <summary>
    /// The §2.2 common fields are promoted to their typed slots and excluded from the extension
    /// data; the type-specific members remain in the extension data.
    /// </summary>
    [TestMethod]
    public async Task PromotesCommonFieldsAndPreservesExtensionData()
    {
        const string json = """
            [{"type":"payment_initiation",
              "locations":["https://example.com/payments"],
              "actions":["initiate","status","cancel"],
              "datatypes":["contacts","photos"],
              "identifier":"account-14-32-32-3",
              "privileges":["admin"],
              "instructedAmount":{"currency":"EUR","amount":"123.50"}}]
            """;

        IReadOnlyList<AuthorizationDetail>? details =
            await AuthorizationDetailsJsonParsing.ParseAuthorizationDetails(
                json, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(details);
        AuthorizationDetail detail = details![0];

        Assert.AreEqual("payment_initiation", detail.Type);
        Assert.AreEqual("https://example.com/payments", string.Join(',', detail.Locations!));
        Assert.AreEqual("initiate,status,cancel", string.Join(',', detail.Actions!));
        Assert.AreEqual("contacts,photos", string.Join(',', detail.DataTypes!));
        Assert.AreEqual("account-14-32-32-3", detail.Identifier);
        Assert.AreEqual("admin", string.Join(',', detail.Privileges!));

        //The common fields are not duplicated into the extension data; the API-specific field is.
        Assert.IsFalse(detail.ExtensionData.ContainsKey("locations"));
        Assert.IsFalse(detail.ExtensionData.ContainsKey("actions"));
        Assert.IsFalse(detail.ExtensionData.ContainsKey("identifier"));
        Assert.IsTrue(detail.ExtensionData.ContainsKey("instructedAmount"));
    }


    /// <summary>
    /// Entries of other authorization details types parse too — the parser is structure-strict
    /// only; the library's registry rejects unsupported types after.
    /// </summary>
    [TestMethod]
    public async Task ParsesForeignTypesForTheLibraryToReject()
    {
        const string json = """[{"type":"payment_initiation"}]""";

        IReadOnlyList<AuthorizationDetail>? details =
            await AuthorizationDetailsJsonParsing.ParseAuthorizationDetails(
                json, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(details);
        Assert.AreEqual("payment_initiation", details![0].Type);
        Assert.IsEmpty(details[0].ExtensionData);
    }


    /// <summary>
    /// RFC 9396 §2 structure violations yield <see langword="null"/>: a non-array value, an
    /// entry without a string <c>type</c>, a non-object entry, and malformed JSON.
    /// </summary>
    [TestMethod]
    public async Task StructureViolationsYieldNull()
    {
        string[] invalidValues =
        [
            """{"type":"openid_credential"}""",
            """[{"credential_configuration_id":"x"}]""",
            """[{"type":42}]""",
            """["just-a-string"]""",
            "{ not json"
        ];

        foreach(string invalid in invalidValues)
        {
            IReadOnlyList<AuthorizationDetail>? details =
                await AuthorizationDetailsJsonParsing.ParseAuthorizationDetails(
                    invalid, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNull(details, $"Value must not parse: {invalid}");
        }
    }


    /// <summary>
    /// An empty array parses (to an empty list) — emptiness is a §5 semantic the library rejects
    /// after the parse, not a structure violation.
    /// </summary>
    [TestMethod]
    public async Task EmptyArrayParsesToEmptyList()
    {
        IReadOnlyList<AuthorizationDetail>? details =
            await AuthorizationDetailsJsonParsing.ParseAuthorizationDetails(
                "[]", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(details);
        Assert.IsEmpty(details!);
    }


    /// <summary>
    /// A §2.2 common field present with the wrong JSON type (RFC 9396 §2.2 defines
    /// <c>locations</c> as an array of strings and <c>identifier</c> as a string) is not promoted
    /// to its typed slot and is recorded in
    /// <see cref="AuthorizationDetail.MalformedCommonFields"/> — the §5 "wrong type of a field"
    /// signal a strict handler refuses. An array element of the wrong type is likewise malformed.
    /// </summary>
    [TestMethod]
    public async Task WrongTypedCommonFieldsAreRecordedNotPromoted()
    {
        const string json = """
            [{"type":"payment_initiation",
              "locations":"https://example.com/payments",
              "identifier":42,
              "actions":["read",7]}]
            """;

        IReadOnlyList<AuthorizationDetail>? details =
            await AuthorizationDetailsJsonParsing.ParseAuthorizationDetails(
                json, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(details);
        AuthorizationDetail detail = details![0];

        Assert.IsNull(detail.Locations);
        Assert.IsNull(detail.Identifier);
        Assert.IsNull(detail.Actions);

        Assert.Contains("locations", detail.MalformedCommonFields);
        Assert.Contains("identifier", detail.MalformedCommonFields);
        Assert.Contains("actions", detail.MalformedCommonFields);

        //The wrong-typed common fields are not duplicated into the extension data either.
        Assert.IsFalse(detail.ExtensionData.ContainsKey("locations"));
        Assert.IsFalse(detail.ExtensionData.ContainsKey("identifier"));
    }


    /// <summary>
    /// Well-formed common fields leave <see cref="AuthorizationDetail.MalformedCommonFields"/>
    /// empty.
    /// </summary>
    [TestMethod]
    public async Task WellFormedCommonFieldsLeaveNoMalformedSignal()
    {
        const string json = """
            [{"type":"payment_initiation","locations":["https://example.com"],"identifier":"acct-1"}]
            """;

        IReadOnlyList<AuthorizationDetail>? details =
            await AuthorizationDetailsJsonParsing.ParseAuthorizationDetails(
                json, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(details);
        Assert.IsEmpty(details![0].MalformedCommonFields);
    }
}
