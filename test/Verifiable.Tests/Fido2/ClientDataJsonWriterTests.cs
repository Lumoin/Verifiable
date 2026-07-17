using System.Buffers;
using System.Text;
using Verifiable.Fido2;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="ClientDataJsonWriter"/>: the production counterpart to
/// <see cref="ClientDataJsonReader"/>, spanning a hand-computed byte-exact vector, round trips through
/// the shipped reader, and the JSON-escaping negatives — a <c>challenge</c>/<c>origin</c> carrying a
/// double quote or backslash — that an earlier, non-escaping composition edge did not handle.
/// </summary>
[TestClass]
internal sealed class ClientDataJsonWriterTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A client data with every member present, none requiring escaping, matches a fully hand-computed
    /// UTF-8 JSON byte sequence in the writer's fixed emission order.
    /// </summary>
    [TestMethod]
    public void WritesAllMembersToHandComputedBytes()
    {
        var clientData = new ClientData(
            WellKnownClientDataTypes.Create, "abc123_-", "https://example.com", crossOrigin: true, topOrigin: "https://top.example.com");

        byte[] expected = Encoding.UTF8.GetBytes(
            """{"type":"webauthn.create","challenge":"abc123_-","origin":"https://example.com","crossOrigin":true,"topOrigin":"https://top.example.com"}""");

        var destination = new ArrayBufferWriter<byte>();
        ClientDataJsonWriter.Write(clientData, destination);

        Assert.IsTrue(destination.WrittenSpan.SequenceEqual(expected));
    }


    /// <summary>
    /// A minimal client data carrying only the required members matches a fully hand-computed UTF-8 JSON
    /// byte sequence with the optional members omitted entirely.
    /// </summary>
    [TestMethod]
    public void WritesOnlyRequiredMembersWhenOptionalMembersAreAbsent()
    {
        var clientData = new ClientData(WellKnownClientDataTypes.Get, "xyz789", "https://rp.example");

        byte[] expected = Encoding.UTF8.GetBytes("""{"type":"webauthn.get","challenge":"xyz789","origin":"https://rp.example"}""");

        var destination = new ArrayBufferWriter<byte>();
        ClientDataJsonWriter.Write(clientData, destination);

        Assert.IsTrue(destination.WrittenSpan.SequenceEqual(expected));
    }


    /// <summary>A written client data round-trips through the shipped <see cref="ClientDataJsonReader"/>.</summary>
    [TestMethod]
    public void RoundTripsThroughTheShippedReader()
    {
        var clientData = new ClientData(
            WellKnownClientDataTypes.Get, "the-challenge", "https://rp.example", crossOrigin: false, topOrigin: "https://top.example");

        var destination = new ArrayBufferWriter<byte>();
        ClientDataJsonWriter.Write(clientData, destination);

        ClientData parsed = ClientDataJsonReader.Read(destination.WrittenMemory);

        Assert.AreEqual(clientData.Type, parsed.Type);
        Assert.AreEqual(clientData.Challenge, parsed.Challenge);
        Assert.AreEqual(clientData.Origin, parsed.Origin);
        Assert.AreEqual(clientData.CrossOrigin, parsed.CrossOrigin);
        Assert.AreEqual(clientData.TopOrigin, parsed.TopOrigin);
    }


    /// <summary>
    /// A <c>challenge</c> containing a double quote and a backslash — characters that would corrupt an
    /// unescaped JSON string literal — round-trips through the shipped reader to the exact original
    /// value, the dormant escaping gap an earlier ad hoc string-interpolation composition edge left open.
    /// </summary>
    [TestMethod]
    public void ChallengeContainingQuotesAndBackslashesRoundTripsCorrectly()
    {
        const string challengeWithQuotesAndBackslashes = "abc\"def\\ghi";
        var clientData = new ClientData(WellKnownClientDataTypes.Create, challengeWithQuotesAndBackslashes, "https://rp.example");

        var destination = new ArrayBufferWriter<byte>();
        ClientDataJsonWriter.Write(clientData, destination);

        ClientData parsed = ClientDataJsonReader.Read(destination.WrittenMemory);

        Assert.AreEqual(challengeWithQuotesAndBackslashes, parsed.Challenge);
    }


    /// <summary>
    /// An <c>origin</c> containing a double quote and a backslash round-trips through the shipped reader
    /// to the exact original value.
    /// </summary>
    [TestMethod]
    public void OriginContainingQuotesAndBackslashesRoundTripsCorrectly()
    {
        const string originWithQuotesAndBackslashes = "https://rp.example/\"path\\segment";
        var clientData = new ClientData(WellKnownClientDataTypes.Get, "c", originWithQuotesAndBackslashes);

        var destination = new ArrayBufferWriter<byte>();
        ClientDataJsonWriter.Write(clientData, destination);

        ClientData parsed = ClientDataJsonReader.Read(destination.WrittenMemory);

        Assert.AreEqual(originWithQuotesAndBackslashes, parsed.Origin);
    }


    /// <summary>A <see langword="null"/> <c>clientData</c> is rejected with <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public void NullClientDataThrowsArgumentNullException()
    {
        var destination = new ArrayBufferWriter<byte>();

        Assert.ThrowsExactly<ArgumentNullException>(() => ClientDataJsonWriter.Write(null!, destination));
    }


    /// <summary>A <see langword="null"/> <c>destination</c> is rejected with <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public void NullDestinationThrowsArgumentNullException()
    {
        var clientData = new ClientData(WellKnownClientDataTypes.Get, "c", "o");

        Assert.ThrowsExactly<ArgumentNullException>(() => ClientDataJsonWriter.Write(clientData, null!));
    }
}
