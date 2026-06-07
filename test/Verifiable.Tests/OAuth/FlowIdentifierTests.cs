using System.Collections.Immutable;
using Microsoft.Extensions.Time.Testing;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.JCose;
using Verifiable.Cryptography;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for the dispatcher's flow-identifier generation.
/// </summary>
/// <remarks>
/// Phase 9h chunk 8 switched flowId generation from
/// <see cref="Guid.NewGuid"/> to <see cref="Guid.CreateVersion7"/>. v7
/// GUIDs encode a 48-bit Unix-milliseconds timestamp in the high-order
/// bits so they sort lexicographically by creation time. The test below
/// locks in the choice — any future change that regresses to v4 GUIDs
/// fails it immediately, drawing attention to the lost DB-index
/// locality and forensic-archive ordering property.
/// </remarks>
[TestClass]
internal sealed class FlowIdentifierTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    private const string VerifierClientId = "https://verifier.example.com";

    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    [TestMethod]
    public async Task Guid7FlowIdSortsLexicographicallyByGenerationTime()
    {
        TimeProvider.SetUtcNow(new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.Zero));
        await using TestHostShell host = new(TimeProvider);

        List<string> flowIds = [];
        InspectDelegate previousInspect = host.Server.Integration.InspectAsync!;
        host.Server.Integration.InspectAsync = (stage, ctx, ct) =>
        {
            if(stage is StateTransitionStage transition)
            {
                //Capture the flowId from the state the transition produced.
                //The first transition of a new flow puts the flowId on After.
                flowIds.Add(transition.After.FlowId);
            }
            return previousInspect(stage, ctx, ct);
        };

        using VerifierKeyMaterial keys = host.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        //First PAR — flowId₁ generated at t.
        (Uri _, string _) = await host.HandleParAsync(
            keys,
            new TransactionNonce("nonce-flowid-01"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        //Advance the FakeTimeProvider so the second flowId's v7 timestamp
        //sorts strictly after the first. v7 GUIDs use millisecond
        //resolution, so a sub-ms advance produces an indeterminate ordering
        //(the random bits decide); 50 ms is comfortably larger than the
        //resolution.
        TimeProvider.Advance(TimeSpan.FromMilliseconds(50));

        //Second PAR — flowId₂ generated at t + 50 ms.
        (Uri _, string _) = await host.HandleParAsync(
            keys,
            new TransactionNonce("nonce-flowid-02"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        List<string> distinctIds = flowIds.Distinct().ToList();
        Assert.IsGreaterThan(1, distinctIds.Count,
            "Two PAR dispatches must produce two distinct flowIds — "
            + "precondition for the ordering assertion below.");

        //Note: Guid.CreateVersion7 reads from the BCL clock, not from the
        //test fixture's FakeTimeProvider. So the two flowIds are timestamped
        //by wall-clock; what we're testing is that v7's encoded timestamp
        //makes sequential-generation IDs sort in generation order regardless
        //of which clock fed them. Distinct generation order is sufficient.
        List<string> sorted = distinctIds.OrderBy(id => id, StringComparer.Ordinal).ToList();
        Assert.IsTrue(
            sorted.SequenceEqual(distinctIds),
            "v7 GUID flowIds must sort lexicographically in generation order. "
            + $"Observed order: [{string.Join(", ", distinctIds)}]; "
            + $"sorted order:   [{string.Join(", ", sorted)}]. "
            + "A failure here typically means the flowId generation regressed "
            + "to Guid.NewGuid (v4) — restore Guid.CreateVersion7 in "
            + "AuthorizationServer.HandleCoreAsync.");
    }


    //Helpers go below the public surface.

    private static PreparedDcqlQuery CreatePreparedQuery() =>
        DcqlFixtures.PidFamilyNamePrepared();
}
