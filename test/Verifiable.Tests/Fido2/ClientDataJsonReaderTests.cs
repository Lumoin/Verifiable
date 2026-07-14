using System.Text;
using Verifiable.Fido2;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="ClientDataJsonReader"/>: the JSON codec behind
/// <see cref="ParseClientDataDelegate"/>, parsing <c>CollectedClientData</c> per WebAuthn L3
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">section 5.8.1</see>. Every malformed-input
/// rejection is a <see cref="Fido2FormatException"/> naming the member or structural violation at fault.
/// </summary>
[TestClass]
internal sealed class ClientDataJsonReaderTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A well-formed <c>webauthn.create</c> client data with every member present, including the optional
    /// <c>crossOrigin</c> and <c>topOrigin</c>, parses every property.
    /// </summary>
    [TestMethod]
    public void ValidCreateClientDataWithAllMembersParsesEveryProperty()
    {
        const string json = """{"type":"webauthn.create","challenge":"abc123_-","origin":"https://example.com","crossOrigin":true,"topOrigin":"https://top.example.com"}""";

        ClientData clientData = ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json));

        Assert.AreEqual(WellKnownClientDataTypes.Create, clientData.Type);
        Assert.AreEqual("abc123_-", clientData.Challenge);
        Assert.AreEqual("https://example.com", clientData.Origin);
        Assert.IsTrue(clientData.CrossOrigin!.Value);
        Assert.AreEqual("https://top.example.com", clientData.TopOrigin);
    }


    /// <summary>
    /// A minimal <c>webauthn.get</c> client data carrying only the required members parses, leaving
    /// <see cref="ClientData.CrossOrigin"/> and <see cref="ClientData.TopOrigin"/> <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public void ValidGetClientDataWithOnlyRequiredMembersLeavesOptionalMembersNull()
    {
        const string json = """{"type":"webauthn.get","challenge":"xyz789","origin":"https://rp.example"}""";

        ClientData clientData = ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json));

        Assert.AreEqual(WellKnownClientDataTypes.Get, clientData.Type);
        Assert.AreEqual("xyz789", clientData.Challenge);
        Assert.AreEqual("https://rp.example", clientData.Origin);
        Assert.IsNull(clientData.CrossOrigin);
        Assert.IsNull(clientData.TopOrigin);
    }


    /// <summary>
    /// Unknown members — including a nested object and a nested array — are ignored; only the members
    /// <see cref="ClientData"/> defines are surfaced.
    /// </summary>
    [TestMethod]
    public void UnknownMembersIncludingNestedObjectAndArrayAreIgnored()
    {
        const string json = """{"type":"webauthn.get","challenge":"c","origin":"o","clientExtensionResults":{"nested":{"a":1}},"list":[1,2,[3,4]]}""";

        ClientData clientData = ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json));

        Assert.AreEqual(WellKnownClientDataTypes.Get, clientData.Type);
        Assert.AreEqual("c", clientData.Challenge);
        Assert.AreEqual("o", clientData.Origin);
    }


    /// <summary>A client data JSON object missing the required <c>type</c> member is rejected.</summary>
    [TestMethod]
    public void MissingTypeMemberIsRejected()
    {
        const string json = """{"challenge":"c","origin":"o"}""";

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json)));

        Assert.Contains("type", exception.Message, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>A client data JSON object missing the required <c>challenge</c> member is rejected.</summary>
    [TestMethod]
    public void MissingChallengeMemberIsRejected()
    {
        const string json = """{"type":"webauthn.get","origin":"o"}""";

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json)));

        Assert.Contains("challenge", exception.Message, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>A client data JSON object missing the required <c>origin</c> member is rejected.</summary>
    [TestMethod]
    public void MissingOriginMemberIsRejected()
    {
        const string json = """{"type":"webauthn.get","challenge":"c"}""";

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json)));

        Assert.Contains("origin", exception.Message, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>A <c>type</c> member carrying a JSON number rather than a string is rejected.</summary>
    [TestMethod]
    public void TypeMemberAsNumberIsRejected()
    {
        const string json = """{"type":42,"challenge":"c","origin":"o"}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>A <c>crossOrigin</c> member carrying a JSON string rather than a boolean is rejected.</summary>
    [TestMethod]
    public void CrossOriginMemberAsStringIsRejected()
    {
        const string json = """{"type":"webauthn.get","challenge":"c","origin":"o","crossOrigin":"true"}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>A duplicate top-level member (here, two <c>type</c> members) is rejected.</summary>
    [TestMethod]
    public void DuplicateTopLevelMemberIsRejected()
    {
        const string json = """{"type":"webauthn.get","type":"webauthn.create","challenge":"c","origin":"o"}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>A top-level JSON array, rather than an object, is rejected.</summary>
    [TestMethod]
    public void TopLevelJsonArrayIsRejected()
    {
        const string json = """[1,2,3]""";

        Assert.ThrowsExactly<Fido2FormatException>(() => ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>Malformed JSON bytes that do not parse at all are rejected.</summary>
    [TestMethod]
    public void MalformedJsonBytesAreRejected()
    {
        const string json = "{not json";

        Assert.ThrowsExactly<Fido2FormatException>(() => ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>Trailing content after an otherwise well-formed top-level object is rejected.</summary>
    [TestMethod]
    public void TrailingContentAfterTheObjectIsRejected()
    {
        const string json = """{"type":"webauthn.get","challenge":"c","origin":"o"} garbage""";

        Assert.ThrowsExactly<Fido2FormatException>(() => ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }
}
