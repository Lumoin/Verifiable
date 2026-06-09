using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Batch revocation over bitstrings: one logical issuer action flipping more than one status bit.
/// The W3C Bitstring Status List specification admits this directly — a single verifiable credential
/// may carry several <c>BitstringStatusListEntry</c> references:
/// <list type="bullet">
/// <item><description>§A.3: "This specification enables an issuer to associate multiple status lists with a single verifiable credential."</description></item>
/// <item><description>§A.4: "It is possible for a single status list to contain multiple types of status purposes."</description></item>
/// <item><description>§2.1: "Implementations SHOULD assign indexes randomly, such that inferences — such as the recency of the assignment or the size of the group — cannot be easily drawn from that position."</description></item>
/// </list>
/// These tests exercise the <see cref="UpdateCredentialStatusesDelegate"/> batch seam: changes are
/// grouped by status list and each affected list is re-encoded exactly once, never publishing a
/// half-applied intermediate.
/// </summary>
[TestClass]
internal sealed class BitstringStatusListBatchRevocationTests
{
    private const string RevocationListUrl = "https://issuer.example/status/revocation";
    private const string SuspensionListUrl = "https://issuer.example/status/suspension";

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task BatchRevokesMultipleEntriesInOneListWithASingleReEncode()
    {
        //A holder's two credentials occupy two unrelated positions in one revocation list (§2.1);
        //a third position stays untouched.
        const int indexA = 10;
        const int indexB = 94567;
        const int untouchedIndex = 5000;

        using var revocationList = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        var listsByUrl = new Dictionary<string, StatusListType>(StringComparer.Ordinal) { [RevocationListUrl] = revocationList };
        var published = new Dictionary<string, string>(StringComparer.Ordinal) { [RevocationListUrl] = BitstringStatusListCodec.EncodeList(revocationList) };
        int reEncodeCount = 0;

        UpdateCredentialStatusesDelegate revoke = MakeRevoker(listsByUrl, published, () => reEncodeCount++);

        CredentialStatusUpdateOutcome outcome = await revoke(
            [
                new CredentialStatusChange(RevocationEntry(RevocationListUrl, indexA), 1),
                new CredentialStatusChange(RevocationEntry(RevocationListUrl, indexB), 1)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialStatusUpdateOutcome.Updated, outcome);
        Assert.AreEqual(1, reEncodeCount, "Two flips in one list must re-encode the list exactly once.");

        using var republished = BitstringStatusListCodec.DecodeList(published[RevocationListUrl], StatusListBitSize.OneBit, Pool);
        Assert.AreEqual((byte)1, republished[indexA]);
        Assert.AreEqual((byte)1, republished[indexB]);
        Assert.AreEqual((byte)0, republished[untouchedIndex]);
    }


    [TestMethod]
    public async Task BatchAppliesChangesAcrossMultipleListsGroupedByList()
    {
        //§A.3 Example 6: one credential with a revocation entry in one list and a suspension entry in
        //another. One batch touches both lists; each is re-encoded once.
        const int revocationIndex = 94567;
        const int suspensionIndex = 12345;

        using var revocationList = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        using var suspensionList = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        var listsByUrl = new Dictionary<string, StatusListType>(StringComparer.Ordinal)
        {
            [RevocationListUrl] = revocationList,
            [SuspensionListUrl] = suspensionList
        };
        var published = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [RevocationListUrl] = BitstringStatusListCodec.EncodeList(revocationList),
            [SuspensionListUrl] = BitstringStatusListCodec.EncodeList(suspensionList)
        };
        int reEncodeCount = 0;

        UpdateCredentialStatusesDelegate update = MakeRevoker(listsByUrl, published, () => reEncodeCount++);

        await update(
            [
                new CredentialStatusChange(RevocationEntry(RevocationListUrl, revocationIndex), 1),
                new CredentialStatusChange(SuspensionEntry(SuspensionListUrl, suspensionIndex), 1)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(2, reEncodeCount, "Two affected lists must re-encode once each.");

        using var republishedRevocation = BitstringStatusListCodec.DecodeList(published[RevocationListUrl], StatusListBitSize.OneBit, Pool);
        using var republishedSuspension = BitstringStatusListCodec.DecodeList(published[SuspensionListUrl], StatusListBitSize.OneBit, Pool);
        Assert.AreEqual((byte)1, republishedRevocation[revocationIndex]);
        Assert.AreEqual((byte)1, republishedSuspension[suspensionIndex]);
    }


    //An application's fan-out behind the seam: flip every change into its list, then re-encode each
    //touched list exactly once (never per bit) and republish it.
    private static UpdateCredentialStatusesDelegate MakeRevoker(
        Dictionary<string, StatusListType> listsByUrl,
        Dictionary<string, string> published,
        Action onReEncode)
    {
        return (changes, _) =>
        {
            var touched = new HashSet<string>(StringComparer.Ordinal);
            foreach(CredentialStatusChange change in changes)
            {
                StatusListType target = listsByUrl[change.Entry.StatusListCredential];
                target[change.Entry.StatusListIndex] = change.NewStatus;
                touched.Add(change.Entry.StatusListCredential);
            }

            foreach(string url in touched)
            {
                published[url] = BitstringStatusListCodec.EncodeList(listsByUrl[url]);
                onReEncode();
            }

            return ValueTask.FromResult(CredentialStatusUpdateOutcome.Updated);
        };
    }


    private static BitstringStatusListEntry RevocationEntry(string listUrl, int index) => new()
    {
        StatusPurpose = BitstringStatusListConstants.RevocationPurpose,
        StatusListIndex = index,
        StatusListCredential = listUrl
    };


    private static BitstringStatusListEntry SuspensionEntry(string listUrl, int index) => new()
    {
        StatusPurpose = BitstringStatusListConstants.SuspensionPurpose,
        StatusListIndex = index,
        StatusListCredential = listUrl
    };
}
