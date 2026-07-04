using System.Collections.Generic;
using System.Text;
using Lumoin.Base;
using Verifiable.Acdc;
using Verifiable.Cryptography;
using Verifiable.Json;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Conformance tests for the ACDC transaction-event-log registry (<see cref="AcdcRegistryReader"/>,
/// <see cref="AcdcRegistry"/>) against the specification's worked non-blindable issuance/revocation registry
/// (<see cref="AcdcExampleVectors"/>): a registry inception followed by an <c>issued</c> and then a <c>revoked</c>
/// update for one ACDC. The reader folds each event from its wire bytes, each event's SAID is verified over its
/// serialization with an independent BLAKE3, and the chain's integrity — sequence, prior-event linkage, and
/// registry binding — is validated.
/// </summary>
[TestClass]
internal sealed class AcdcRegistryTests
{
    /// <summary>
    /// The registry inception folds into a typed inception event carrying the registry SAID, the Issuer AID,
    /// sequence number zero, and the datetime.
    /// </summary>
    [TestMethod]
    public void ReadsRegistryInception()
    {
        var inception = (RegistryInceptionEvent)AcdcRegistryReader.Read(Decode(AcdcExampleVectors.RegistryInceptionEventJson));

        Assert.AreEqual(AcdcMessageTypes.RegistryInception, inception.MessageType);
        Assert.AreEqual(AcdcExampleVectors.RegistryRipSaid, inception.Said);
        Assert.AreEqual(AcdcExampleVectors.RegistryIssuerAid, inception.Issuer);
        Assert.AreEqual(0, inception.SequenceNumber);
        Assert.AreEqual("0ABhY2Rjc3BlY3dvcmtyYXcz", inception.Uuid);
    }


    /// <summary>
    /// The issued update folds into a typed update event carrying the registry SAID, sequence number one, the prior
    /// event SAID, the target ACDC SAID, and the <c>issued</c> state.
    /// </summary>
    [TestMethod]
    public void ReadsRegistryUpdate()
    {
        var update = (RegistryUpdateEvent)AcdcRegistryReader.Read(Decode(AcdcExampleVectors.RegistryIssuedUpdateJson));

        Assert.AreEqual(AcdcMessageTypes.RegistryUpdate, update.MessageType);
        Assert.AreEqual(AcdcExampleVectors.RegistryIssuedUpdateSaid, update.Said);
        Assert.AreEqual(AcdcExampleVectors.RegistryRipSaid, update.RegistryDigest);
        Assert.AreEqual(1, update.SequenceNumber);
        Assert.AreEqual(AcdcExampleVectors.RegistryRipSaid, update.PriorSaid);
        Assert.AreEqual(AcdcExampleVectors.RegistryTargetAcdcSaid, update.TransactionAcdcSaid);
        Assert.AreEqual("issued", update.TransactionState);
    }


    /// <summary>
    /// Each registry event's SAID recomputes over its serialization to its published value: the events are
    /// authentic, which is what the KEL anchor seal commits to.
    /// </summary>
    [TestMethod]
    public async Task VerifiesRegistryEventSaids()
    {
        await AssertEventSaid(AcdcExampleVectors.RegistryInceptionEventJson, AcdcExampleVectors.RegistryRipSaid);
        await AssertEventSaid(AcdcExampleVectors.RegistryIssuedUpdateJson, AcdcExampleVectors.RegistryIssuedUpdateSaid);
        await AssertEventSaid(AcdcExampleVectors.RegistryRevokedUpdateJson, AcdcExampleVectors.RegistryRevokedUpdateSaid);

        static async Task AssertEventSaid(string eventJson, string expectedSaid)
        {
            using AcdcTestSupport.EncodedSerialization bytes = AcdcTestSupport.Encode(eventJson);
            Assert.AreEqual(expectedSaid, await AcdcSaid.RecomputeAsync(bytes.Memory, expectedSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
        }
    }


    /// <summary>
    /// The worked registry chain — inception, issued update, revoked update — validates: the chain returns the
    /// registry SAID, both updates target the same ACDC, and the state transitions from issued to revoked.
    /// </summary>
    [TestMethod]
    public void ValidatesRegistryChain()
    {
        var events = new List<AcdcRegistryEvent>
        {
            AcdcRegistryReader.Read(Decode(AcdcExampleVectors.RegistryInceptionEventJson)),
            AcdcRegistryReader.Read(Decode(AcdcExampleVectors.RegistryIssuedUpdateJson)),
            AcdcRegistryReader.Read(Decode(AcdcExampleVectors.RegistryRevokedUpdateJson))
        };

        string registrySaid = AcdcRegistry.ValidateChain(events);

        Assert.AreEqual(AcdcExampleVectors.RegistryRipSaid, registrySaid);

        var issued = (RegistryUpdateEvent)events[1];
        var revoked = (RegistryUpdateEvent)events[2];
        Assert.AreEqual(AcdcExampleVectors.RegistryTargetAcdcSaid, issued.TransactionAcdcSaid, "Both updates track the same ACDC.");
        Assert.AreEqual(AcdcExampleVectors.RegistryTargetAcdcSaid, revoked.TransactionAcdcSaid);
        Assert.AreEqual("issued", issued.TransactionState);
        Assert.AreEqual("revoked", revoked.TransactionState);
    }


    /// <summary>
    /// A registry whose update does not chain to its prior event fails closed.
    /// </summary>
    [TestMethod]
    public void RejectsBrokenPriorChain()
    {
        var inception = (RegistryInceptionEvent)AcdcRegistryReader.Read(Decode(AcdcExampleVectors.RegistryInceptionEventJson));
        var brokenUpdate = new RegistryUpdateEvent(
            VersionString: "ACDCCAACAAJSONAAEx.",
            Said: AcdcExampleVectors.RegistryIssuedUpdateSaid,
            RegistryDigest: AcdcExampleVectors.RegistryRipSaid,
            SequenceNumber: 1,
            PriorSaid: "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            Datetime: "2020-08-03T12:00:20.000000+00:00",
            TransactionAcdcSaid: AcdcExampleVectors.RegistryTargetAcdcSaid,
            TransactionState: "issued");

        Assert.ThrowsExactly<AcdcException>(() => AcdcRegistry.ValidateChain([inception, brokenUpdate]));
    }


    /// <summary>
    /// An update bound to a different registry (its registry SAID does not match the inception) fails closed.
    /// </summary>
    [TestMethod]
    public void RejectsUpdateBoundToDifferentRegistry()
    {
        var inception = (RegistryInceptionEvent)AcdcRegistryReader.Read(Decode(AcdcExampleVectors.RegistryInceptionEventJson));
        var foreignUpdate = new RegistryUpdateEvent(
            VersionString: "ACDCCAACAAJSONAAEx.",
            Said: AcdcExampleVectors.RegistryIssuedUpdateSaid,
            RegistryDigest: AcdcExampleVectors.RegistryRevokedUpdateSaid,
            SequenceNumber: 1,
            PriorSaid: AcdcExampleVectors.RegistryRipSaid,
            Datetime: "2020-08-03T12:00:20.000000+00:00",
            TransactionAcdcSaid: AcdcExampleVectors.RegistryTargetAcdcSaid,
            TransactionState: "issued");

        Assert.ThrowsExactly<AcdcException>(() => AcdcRegistry.ValidateChain([inception, foreignUpdate]));
    }


    /// <summary>
    /// A registry that does not begin with an inception event fails closed.
    /// </summary>
    [TestMethod]
    public void RejectsChainNotBeginningWithInception()
    {
        var update = AcdcRegistryReader.Read(Decode(AcdcExampleVectors.RegistryIssuedUpdateJson));

        Assert.ThrowsExactly<AcdcException>(() => AcdcRegistry.ValidateChain([update]));
    }


    /// <summary>
    /// A registry event whose fields are out of the fixed order is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsFieldsOutOfOrder()
    {
        //The inception with its issuer and uuid swapped out of order.
        Assert.ThrowsExactly<AcdcException>(() => AcdcRegistryReader.Read(Decode(
            """{"v":"ACDCCAACAAJSONAADa.","t":"rip","d":"d","i":"EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW","u":"0ABhY2Rjc3BlY3dvcmtyYXcz","n":"0","dt":"2025-07-04T17:53:00.000000+00:00"}""")));
    }


    /// <summary>
    /// A blindable update (<c>bup</c>) is rejected as not modeled yet.
    /// </summary>
    [TestMethod]
    public void RejectsBlindableUpdate()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcRegistryReader.Read(Decode(
            """{"v":"ACDCCAACAAJSONAADa.","t":"bup","d":"d","rd":"rd","n":"1","p":"p","dt":"dt","b":"b"}""")));
    }


    private static MessageFieldMap Decode(string json) => AcdcJson.DecodeFieldMap(Encoding.UTF8.GetBytes(json));
}
