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

    //Faithful to the JCose semantic type: serialize the JwtPayload directly (it is
    //registered in VerifiableJsonContext), with no downcast to Dictionary<string,object>.
    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            payload,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public void SerializesSdJwtVcAsArrayUnderCredentialQueryIdKey()
    {
        const string QueryId = "pid";
        const string Presentation = "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.sig~WyJzIiwibiIsInYiXQ~eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJub25jZSI6Im4ifQ.kbsig";

        string vpTokenJson = VpTokenSerializer.SerializeSingle(
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
    public void DirectPostJwtResponseNestsVpTokenAndState()
    {
        const string QueryId = "pid";
        const string Presentation = "presentation-string";

        Dictionary<string, string> presentations = new(StringComparer.Ordinal)
        {
            [QueryId] = Presentation
        };

        string responseJson = VpTokenSerializer.SerializeDirectPostJwtResponse(
            presentations, "state-123", PayloadSerializer);

        using JsonDocument document = JsonDocument.Parse(responseJson);
        JsonElement root = document.RootElement;

        //OID4VP 1.0 §8.3.1: vp_token + state are NAMED CLAIMS in the response JWT
        //payload; the DCQL-keyed object is NESTED under vp_token, not at the top level.
        Assert.IsTrue(root.TryGetProperty("vp_token", out JsonElement vpToken),
            $"Response payload must carry a nested vp_token claim. Actual: {responseJson}");
        Assert.AreEqual(JsonValueKind.Object, vpToken.ValueKind);
        Assert.IsTrue(vpToken.TryGetProperty(QueryId, out JsonElement presentationsArray),
            "vp_token must be the DCQL-keyed object.");
        Assert.AreEqual(JsonValueKind.Array, presentationsArray.ValueKind);
        Assert.AreEqual(Presentation, presentationsArray[0].GetString());

        Assert.IsTrue(root.TryGetProperty("state", out JsonElement state),
            "state must be a top-level claim inside the response JWT payload.");
        Assert.AreEqual("state-123", state.GetString());
    }


    [TestMethod]
    public void VerifierReadPathDescendsIntoVpTokenClaim()
    {
        //Exactly what HaipOid4VpVerifierExecutor does on the decrypted plaintext.
        const string Wrapped = "{\"vp_token\":{\"pid\":[\"PRES\"]},\"state\":\"s\"}";
        ReadOnlySpan<byte> plaintext = System.Text.Encoding.UTF8.GetBytes(Wrapped);

        string? vpTokenObjectJson = JwkJsonReader.ExtractObjectAsString(plaintext, "vp_token"u8);
        Assert.IsNotNull(vpTokenObjectJson, $"ExtractObjectAsString('vp_token') returned null. Wrapped: {Wrapped}");

        string? presentation = JwkJsonReader.ExtractFirstStringFromArrayProperty(
            System.Text.Encoding.UTF8.GetBytes(vpTokenObjectJson),
            System.Text.Encoding.UTF8.GetBytes("pid"));
        Assert.AreEqual("PRES", presentation,
            $"Descending into vp_token then reading the qid array failed. vp_token JSON: {vpTokenObjectJson}");
    }


    [TestMethod]
    public void OutputParsesAsJsonObjectKeyedByQueryId()
    {
        const string QueryId = "my_credential";

        string vpTokenJson = VpTokenSerializer.SerializeSingle(
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
