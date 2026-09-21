using System.Buffers.Text;
using Verifiable.Fido2;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="PrfResultsJsonReader"/>: the separate, deliberately independent path a
/// caller takes to read the <c>prf</c> extension's SECRET <c>results</c> bytes, as opposed to
/// <see cref="PrfExtensionProcessor"/>, which never touches them.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-prf-extension">W3C Web Authentication Level 3,
/// section 10.1.4: Pseudo-random function extension (prf)</see>. Every <see cref="Fido2PrfResults"/>
/// this class receives is disposed before the test returns.
/// </remarks>
[TestClass]
internal sealed class PrfResultsJsonReaderTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A <c>prf</c> output carrying only <c>results.first</c> decodes to a <see cref="Fido2PrfResults"/>
    /// whose <see cref="Fido2PrfResults.First"/> holds exactly the expected bytes and whose
    /// <see cref="Fido2PrfResults.Second"/> is <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public void SingleResultDecodesFirstOnly()
    {
        byte[] firstBytes = Enumerable.Range(0, 32).Select(static i => (byte)i).ToArray();
        string json = $$$"""{"results":{"first":"{{{Base64Url.EncodeToString(firstBytes)}}}"}}""";

        using Fido2PrfResults? results = PrfResultsJsonReader.Read(Fido2TestVectors.Encode(json), BaseMemoryPool.Shared);

        Assert.IsNotNull(results);
        Assert.IsTrue(firstBytes.AsSpan().SequenceEqual(results.First.AsReadOnlySpan()));
        Assert.IsNull(results.Second);
    }


    /// <summary>
    /// A <c>prf</c> output carrying both <c>results.first</c> and <c>results.second</c> decodes both
    /// into independent carriers, each holding exactly its own expected bytes.
    /// </summary>
    [TestMethod]
    public void TwoResultsDecodeFirstAndSecondIndependently()
    {
        byte[] firstBytes = Enumerable.Range(0, 32).Select(static i => (byte)i).ToArray();
        byte[] secondBytes = Enumerable.Range(32, 32).Select(static i => (byte)i).ToArray();
        string json = $$$"""{"results":{"first":"{{{Base64Url.EncodeToString(firstBytes)}}}","second":"{{{Base64Url.EncodeToString(secondBytes)}}}"}}""";

        using Fido2PrfResults? results = PrfResultsJsonReader.Read(Fido2TestVectors.Encode(json), BaseMemoryPool.Shared);

        Assert.IsNotNull(results);
        Assert.IsTrue(firstBytes.AsSpan().SequenceEqual(results.First.AsReadOnlySpan()));
        Assert.IsNotNull(results.Second);
        Assert.IsTrue(secondBytes.AsSpan().SequenceEqual(results.Second.AsReadOnlySpan()));
    }


    /// <summary>A <c>prf</c> output carrying no <c>results</c> member reads as <see langword="null"/>.</summary>
    [TestMethod]
    public void AbsentResultsReadsAsNull()
    {
        using Fido2PrfResults? results = PrfResultsJsonReader.Read(Fido2TestVectors.Encode("""{"enabled":true}"""), BaseMemoryPool.Shared);

        Assert.IsNull(results);
    }


    /// <summary>A <c>results</c> object missing its required <c>first</c> member fails the family's way: closed.</summary>
    [TestMethod]
    public void ResultsPresentWithoutFirstFails()
    {
        _ = Assert.ThrowsExactly<Fido2FormatException>(
            () => PrfResultsJsonReader.Read(Fido2TestVectors.Encode("""{"results":{"second":"AQIDBA"}}"""), BaseMemoryPool.Shared));
    }


    /// <summary>
    /// An invalid base64url <c>results.first</c> value fails closed, and leaves the pool's
    /// outstanding rentals at zero — every buffer this call rented while decoding is cleared and
    /// returned before it throws.
    /// </summary>
    [TestMethod]
    public void InvalidBase64UrlFailsAndLeavesNoOutstandingPoolRentals()
    {
        using var meteredPool = new MeteredHousePool();

        _ = Assert.ThrowsExactly<Fido2FormatException>(
            () => PrfResultsJsonReader.Read(Fido2TestVectors.Encode("""{"results":{"first":"not-valid-base64url!!!"}}"""), meteredPool.Pool));

        Assert.AreEqual(0, meteredPool.OutstandingCount);
    }
}
