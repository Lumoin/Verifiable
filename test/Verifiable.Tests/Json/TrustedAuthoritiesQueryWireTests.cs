using System.Text.Json;
using Verifiable.Core.Model.Dcql;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Json;

/// <summary>
/// Proves the DCQL wire readers close the fail-open holes
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
/// OpenID for Verifiable Presentations 1.0, Section 6.1</see> and
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
/// Section 6.1.1</see> forbid: a <c>trusted_authorities</c> entry MUST be an object with a REQUIRED
/// string <c>type</c> and a REQUIRED non-empty array of string <c>values</c>, and a
/// <c>trusted_authorities</c> array, when present on a Credential Query, is non-empty. The three
/// Section 6.1.1 example entries round-trip; a query without <c>trusted_authorities</c> reads with a
/// null slot.
/// </summary>
[TestClass]
internal sealed class TrustedAuthoritiesQueryWireTests
{
    /// <summary>The MSTest-supplied context of the currently executing test.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see> carries a non-normative example
    /// entry for each registered type. Each reads back with its <c>type</c> and its single <c>value</c>
    /// intact, and re-serializing then re-reading it yields the same entry.
    /// </summary>
    [DataRow("aki", "s9tIpPmhxdiuNkHMEWNpYim8S8Y", DisplayName = "The Section 6.1.1.1 aki example entry.")]
    [DataRow("etsi_tl", "https://lotl.example.com", DisplayName = "The Section 6.1.1.2 etsi_tl example entry.")]
    [DataRow("openid_federation", "https://trustanchor.example.com", DisplayName = "The Section 6.1.1.3 openid_federation example entry.")]
    [TestMethod]
    public void EachRegisteredTypeExampleEntryRoundTrips(string type, string value)
    {
        JsonSerializerOptions options = new JsonSerializerOptions().ApplyVerifiableDefaults(requireDcqlMeta: false);
        string json = $$"""{"type":"{{type}}","values":["{{value}}"]}""";

        TrustedAuthoritiesQuery read = JsonSerializerExtensions.Deserialize<TrustedAuthoritiesQuery>(json, options)!;

        Assert.AreEqual(
            type,
            read.Type,
            "The entry's 'type' reads back unchanged (Section 6.1.1).");
        Assert.HasCount(
            1,
            read.Values,
            "The entry carries its single 'values' element (Section 6.1.1).");
        Assert.AreEqual(
            value,
            read.Values[0],
            "The entry's single 'values' element reads back unchanged (Section 6.1.1).");

        string reserialized = JsonSerializerExtensions.Serialize(read, options);
        TrustedAuthoritiesQuery reread = JsonSerializerExtensions.Deserialize<TrustedAuthoritiesQuery>(reserialized, options)!;

        Assert.AreEqual(
            type,
            reread.Type,
            "The 'type' survives a serialize/read round-trip (Section 6.1.1).");
        Assert.AreEqual(
            value,
            reread.Values[0],
            "The single 'values' element survives a serialize/read round-trip (Section 6.1.1).");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "values: REQUIRED. A non-empty
    /// array of strings". An entry that omits <c>values</c> is refused rather than read with an empty
    /// or defaulted slot.
    /// </summary>
    [TestMethod]
    public void AnEntryWithoutValuesIsRefused()
    {
        JsonSerializerOptions options = new JsonSerializerOptions().ApplyVerifiableDefaults(requireDcqlMeta: false);
        const string json = """{"type":"aki"}""";

        Assert.ThrowsExactly<JsonException>(
            () => JsonSerializerExtensions.Deserialize<TrustedAuthoritiesQuery>(json, options),
            "Section 6.1.1 makes 'values' REQUIRED, so an entry omitting it is refused.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "values: REQUIRED. A non-empty
    /// array of strings". An entry whose <c>values</c> array is empty expresses no acceptable
    /// identifier and is refused.
    /// </summary>
    [TestMethod]
    public void AnEntryWithAnEmptyValuesArrayIsRefused()
    {
        JsonSerializerOptions options = new JsonSerializerOptions().ApplyVerifiableDefaults(requireDcqlMeta: false);
        const string json = """{"type":"aki","values":[]}""";

        Assert.ThrowsExactly<JsonException>(
            () => JsonSerializerExtensions.Deserialize<TrustedAuthoritiesQuery>(json, options),
            "Section 6.1.1 requires a non-empty 'values' array, so an empty one is refused.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "values: REQUIRED. A non-empty
    /// array of strings". An entry whose <c>values</c> array holds a non-string element is refused.
    /// </summary>
    [TestMethod]
    public void AnEntryWhoseValuesElementIsNotAStringIsRefused()
    {
        JsonSerializerOptions options = new JsonSerializerOptions().ApplyVerifiableDefaults(requireDcqlMeta: false);
        const string json = """{"type":"aki","values":["a",1]}""";

        Assert.ThrowsExactly<JsonException>(
            () => JsonSerializerExtensions.Deserialize<TrustedAuthoritiesQuery>(json, options),
            "Section 6.1.1 requires an array of strings, so a numeric element is refused.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "type: REQUIRED. A string
    /// uniquely identifying the type". An entry whose <c>type</c> is not a string is refused.
    /// </summary>
    [TestMethod]
    public void AnEntryWhoseTypeIsNotAStringIsRefused()
    {
        JsonSerializerOptions options = new JsonSerializerOptions().ApplyVerifiableDefaults(requireDcqlMeta: false);
        const string json = """{"type":5,"values":["a"]}""";

        Assert.ThrowsExactly<JsonException>(
            () => JsonSerializerExtensions.Deserialize<TrustedAuthoritiesQuery>(json, options),
            "Section 6.1.1 requires 'type' to be a string, so a numeric 'type' is refused.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "Each entry in
    /// trusted_authorities MUST be an object with the following properties". An entry that is a JSON
    /// string rather than an object is refused.
    /// </summary>
    [TestMethod]
    public void AnEntryThatIsNotAnObjectIsRefused()
    {
        JsonSerializerOptions options = new JsonSerializerOptions().ApplyVerifiableDefaults(requireDcqlMeta: false);
        const string json = "\"aki\"";

        Assert.ThrowsExactly<JsonException>(
            () => JsonSerializerExtensions.Deserialize<TrustedAuthoritiesQuery>(json, options),
            "Section 6.1.1 requires each entry to be an object, so a bare string is refused.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "trusted_authorities: OPTIONAL. A
    /// non-empty array of objects". A Credential Query carrying an empty <c>trusted_authorities</c>
    /// array is refused rather than read as though the property were absent.
    /// </summary>
    [TestMethod]
    public void AnEmptyTrustedAuthoritiesArrayOnACredentialQueryIsRefused()
    {
        JsonSerializerOptions options = new JsonSerializerOptions().ApplyVerifiableDefaults(requireDcqlMeta: false);
        const string json = """{"id":"c","format":"mso_mdoc","trusted_authorities":[]}""";

        Assert.ThrowsExactly<JsonException>(
            () => JsonSerializerExtensions.Deserialize<CredentialQuery>(json, options),
            "Section 6.1 makes trusted_authorities a non-empty array when present, so an empty one is refused.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "trusted_authorities: OPTIONAL."
    /// A Credential Query that omits <c>trusted_authorities</c> reads with a null slot, applying no
    /// trusted-authority constraint.
    /// </summary>
    [TestMethod]
    public void ACredentialQueryWithoutTrustedAuthoritiesReadsWithNull()
    {
        JsonSerializerOptions options = new JsonSerializerOptions().ApplyVerifiableDefaults(requireDcqlMeta: false);
        const string json = """{"id":"c","format":"mso_mdoc"}""";

        CredentialQuery read = JsonSerializerExtensions.Deserialize<CredentialQuery>(json, options)!;

        Assert.IsNull(
            read.TrustedAuthorities,
            "Section 6.1: trusted_authorities is OPTIONAL, so a query omitting it reads with a null slot.");
    }
}
