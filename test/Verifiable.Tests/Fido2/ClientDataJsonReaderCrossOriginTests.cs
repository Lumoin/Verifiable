using System.Text;
using Verifiable.Fido2;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Covers the <c>crossOrigin:false</c> half of <see cref="ClientDataJsonReader"/>'s boolean-type guard —
/// the other half <see cref="ClientDataJsonReaderTests"/> leaves untested. That guard rejects any
/// <c>crossOrigin</c> value that is neither JSON <c>true</c> nor JSON <c>false</c>; the suite otherwise
/// only ever supplies <c>true</c> (<c>ValidCreateClientDataWithAllMembersParsesEveryProperty</c>) or a
/// wrong-typed value (<c>CrossOriginMemberAsStringIsRejected</c>), so a mutation dropping the <c>!=
/// JsonTokenType.False</c> half of that check would reject every legitimate — arguably the most common —
/// non-cross-origin <c>CollectedClientData</c> undetected.
/// </summary>
[TestClass]
internal sealed class ClientDataJsonReaderCrossOriginTests
{
    /// <summary>A <c>"crossOrigin":false</c> member parses to a non-null, <see langword="false"/> value.</summary>
    [TestMethod]
    public void CrossOriginFalseParsesToNonNullFalseValue()
    {
        const string json = """{"type":"webauthn.get","challenge":"c","origin":"https://example.com","crossOrigin":false}""";

        ClientData clientData = ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json));

        Assert.IsNotNull(clientData.CrossOrigin);
        Assert.IsFalse(clientData.CrossOrigin!.Value);
    }
}
