namespace Verifiable.Tests.StatusList;

/// <summary>
/// Shared constants for Status List tests. Provides named values for test indices,
/// URIs, and specification test vectors from draft-ietf-oauth-status-list.
/// </summary>
internal static class StatusListTestConstants
{
    /// <summary>
    /// Example Status List Token subject URI used across tests.
    /// </summary>
    internal const string ExampleTokenSubject = "https://example.com/statuslists/1";

    /// <summary>
    /// A second example Status List Token URI for multi-list scenarios.
    /// </summary>
    internal const string SecondTokenSubject = "https://example.com/statuslists/2";

    /// <summary>
    /// Example aggregation endpoint URI.
    /// </summary>
    internal const string ExampleAggregationUri = "https://example.com/aggregation";

    /// <summary>
    /// A deliberately wrong subject URI for mismatch tests.
    /// </summary>
    internal const string MismatchedSubject = "https://example.com/statuslists/wrong";

    /// <summary>
    /// A representative index used to test non-zero positions.
    /// </summary>
    internal const int SuspendedCredentialIndex = 42;

    /// <summary>
    /// Default list capacity for small test lists.
    /// </summary>
    internal const int SmallListCapacity = 16;

    /// <summary>
    /// Default list capacity for medium test lists.
    /// </summary>
    internal const int MediumListCapacity = 100;

    /// <summary>
    /// Section 4.1 one-bit spec vector compressed hex (ZLIB).
    /// Represents status values [1,0,0,1,1,1,0,1, 1,1,0,0,0,1,0,1].
    /// </summary>
    internal const string OneBitCompressedHex = "78DADBB918000217015D";

    /// <summary>
    /// Section 4.1 two-bit spec vector compressed hex (ZLIB).
    /// Represents byte array [0xC9, 0x44, 0xF9].
    /// </summary>
    internal const string TwoBitCompressedHex = "78DA3BE9F2130003DF0207";

    /// <summary>
    /// Section 4.3 one-bit CBOR spec vector hex.
    /// CBOR map with "bits":1 and "lst" containing compressed data.
    /// </summary>
    internal const string OneBitCborHex = "A2646269747301636C73744A78DADBB918000217015D";

    /// <summary>
    /// Section 4.3 two-bit CBOR spec vector hex.
    /// CBOR map with "bits":2 and "lst" containing compressed data.
    /// </summary>
    internal const string TwoBitCborHex = "A2646269747302636C73744B78DA3BE9F2130003DF0207";

    /// <summary>
    /// Section 4.2 one-bit JSON spec vector.
    /// </summary>
    internal const string OneBitJson = /*lang=json,strict*/ """{"bits":1,"lst":"eNrbuRgAAhcBXQ"}""";

    /// <summary>
    /// Section 4.2 two-bit JSON spec vector.
    /// Base64url encoding of the compressed hex <see cref="TwoBitCompressedHex"/>.
    /// </summary>
    /// <remarks>
    /// The draft-ietf-oauth-status-list example uses a different compressed form.
    /// This constant uses the base64url encoding of <see cref="TwoBitCompressedHex"/>
    /// to ensure decompression consistency across formats.
    /// </remarks>
    internal const string TwoBitJson = /*lang=json,strict*/ """{"bits":2,"lst":"eNo76fITAAPfAgc"}""";

    /// <summary>
    /// Fixed timestamp for deterministic tests. Corresponds to 2023-11-14T22:13:20Z.
    /// </summary>
    internal static readonly DateTimeOffset BaseTime = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);
}