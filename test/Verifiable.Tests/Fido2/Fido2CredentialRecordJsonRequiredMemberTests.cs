using System.Text;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Covers the 8 of 9 <see cref="Fido2CredentialRecordJsonReader"/> "member is required" guards that
/// <see cref="Fido2CredentialRecordJsonTests.MissingRequiredMemberIsRejected"/> (<c>signCount</c> only)
/// leaves individually unexercised: <c>version</c>, <c>type</c>, <c>id</c>, <c>publicKey</c>,
/// <c>uvInitialized</c>, <c>transports</c>, <c>backupEligible</c>, <c>backupState</c>, plus the nested
/// <c>publicKey.kty</c> check. Because this document shape is this codebase's own persisted-record
/// contract rather than a WebAuthn wire format, each of these guards is the sole enforcement point
/// against a hand-edited or corrupted persisted document — removing any one of them undetected would let
/// a reload silently construct a record with a wrong default in place of a required field.
/// </summary>
[TestClass]
internal sealed class Fido2CredentialRecordJsonRequiredMemberTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Omitting exactly one required top-level member is rejected, naming that member.</summary>
    /// <param name="includeVersion">Whether to include the <c>version</c> member.</param>
    /// <param name="includeType">Whether to include the <c>type</c> member.</param>
    /// <param name="includeId">Whether to include the <c>id</c> member.</param>
    /// <param name="includePublicKey">Whether to include the <c>publicKey</c> member.</param>
    /// <param name="includeUvInitialized">Whether to include the <c>uvInitialized</c> member.</param>
    /// <param name="includeTransports">Whether to include the <c>transports</c> member.</param>
    /// <param name="includeBackupEligible">Whether to include the <c>backupEligible</c> member.</param>
    /// <param name="includeBackupState">Whether to include the <c>backupState</c> member.</param>
    /// <param name="expectedMemberName">The member name the rejection message must contain.</param>
    [TestMethod]
    [DataRow(false, true, true, true, true, true, true, true, "version")]
    [DataRow(true, false, true, true, true, true, true, true, "type")]
    [DataRow(true, true, false, true, true, true, true, true, "id")]
    [DataRow(true, true, true, false, true, true, true, true, "publicKey")]
    [DataRow(true, true, true, true, false, true, true, true, "uvInitialized")]
    [DataRow(true, true, true, true, true, false, true, true, "transports")]
    [DataRow(true, true, true, true, true, true, false, true, "backupEligible")]
    [DataRow(true, true, true, true, true, true, true, false, "backupState")]
    public void MissingTopLevelMemberIsRejected(
        bool includeVersion,
        bool includeType,
        bool includeId,
        bool includePublicKey,
        bool includeUvInitialized,
        bool includeTransports,
        bool includeBackupEligible,
        bool includeBackupState,
        string expectedMemberName)
    {
        string json = BuildDocument(includeVersion, includeType, includeId, includePublicKey, includeUvInitialized, includeTransports, includeBackupEligible, includeBackupState, includePublicKeyKty: true);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => Fido2CredentialRecordJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));

        Assert.Contains(expectedMemberName, exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A document whose <c>publicKey</c> sub-object omits the required nested <c>kty</c> member is rejected.</summary>
    [TestMethod]
    public void MissingNestedKtyMemberIsRejected()
    {
        string json = BuildDocument(includeVersion: true, includeType: true, includeId: true, includePublicKey: true, includeUvInitialized: true, includeTransports: true, includeBackupEligible: true, includeBackupState: true, includePublicKeyKty: false);

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => Fido2CredentialRecordJsonReader.Read(Encoding.UTF8.GetBytes(json), BaseMemoryPool.Shared));

        Assert.Contains("kty", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Builds a structurally valid <see cref="Fido2CredentialRecordJsonReader"/> document, letting the
    /// caller omit exactly one top-level member (or the nested <c>publicKey.kty</c> member) to produce
    /// each guard's negative fixture. <c>signCount</c> always stays present — its own removal is already
    /// pinned by <see cref="Fido2CredentialRecordJsonTests.MissingRequiredMemberIsRejected"/>.
    /// </summary>
    private static string BuildDocument(
        bool includeVersion,
        bool includeType,
        bool includeId,
        bool includePublicKey,
        bool includeUvInitialized,
        bool includeTransports,
        bool includeBackupEligible,
        bool includeBackupState,
        bool includePublicKeyKty)
    {
        string publicKeyJson = includePublicKeyKty
            ? """{"kty":2,"alg":-7,"crv":1,"x":"AQIDBA","y":"AQIDBA"}"""
            : """{"alg":-7,"crv":1,"x":"AQIDBA","y":"AQIDBA"}""";

        var members = new List<string>();
        if(includeVersion)
        {
            members.Add("\"version\":1");
        }

        if(includeType)
        {
            members.Add("\"type\":\"public-key\"");
        }

        if(includeId)
        {
            members.Add("\"id\":\"AQIDBA\"");
        }

        if(includePublicKey)
        {
            members.Add($"\"publicKey\":{publicKeyJson}");
        }

        members.Add("\"signCount\":0");

        if(includeUvInitialized)
        {
            members.Add("\"uvInitialized\":false");
        }

        if(includeTransports)
        {
            members.Add("\"transports\":[]");
        }

        if(includeBackupEligible)
        {
            members.Add("\"backupEligible\":false");
        }

        if(includeBackupState)
        {
            members.Add("\"backupState\":false");
        }

        return "{" + string.Join(",", members) + "}";
    }
}
