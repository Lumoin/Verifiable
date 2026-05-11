using System.Text.Json;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Direct tests for <see cref="VpTokenSerializer"/>. Exercises the OID4VP
/// <c>vp_token</c> JSON-construction primitive in isolation; nothing else in
/// the wallet flow is involved.
/// </summary>
[TestClass]
internal sealed class VpTokenSerializerTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public void SerializesSdJwtVcAsArrayUnderCredentialQueryIdKey()
    {
        const string QueryId = "pid";
        const string Presentation = "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.sig~WyJzIiwibiIsInYiXQ~eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJub25jZSI6Im4ifQ.kbsig";

        string vpTokenJson = VpTokenSerializer.SerializeSingleSdJwtVc(
            QueryId, Presentation, PayloadSerializer);

        using JsonDocument document = JsonDocument.Parse(vpTokenJson);
        JsonElement root = document.RootElement;

        Assert.AreEqual(JsonValueKind.Object, root.ValueKind);
        Assert.IsTrue(root.TryGetProperty(QueryId, out JsonElement value));
        Assert.AreEqual(JsonValueKind.Array, value.ValueKind);
        Assert.AreEqual(1, value.GetArrayLength());
        Assert.AreEqual(Presentation, value[0].GetString());
    }


    [TestMethod]
    public void OutputParsesAsJsonObjectKeyedByQueryId()
    {
        const string QueryId = "my_credential";

        string vpTokenJson = VpTokenSerializer.SerializeSingleSdJwtVc(
            QueryId,
            "credential-string",
            PayloadSerializer);

        Dictionary<string, JsonElement>? parsed =
            JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(vpTokenJson);

        Assert.IsNotNull(parsed);
        Assert.HasCount(1, parsed);
        Assert.IsTrue(parsed.ContainsKey(QueryId));
        Assert.AreEqual(JsonValueKind.Array, parsed[QueryId].ValueKind);
    }
}
