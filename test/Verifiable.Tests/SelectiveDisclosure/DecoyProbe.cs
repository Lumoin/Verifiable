using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// A decoy decision-engine stand-in used by the end-to-end decoy tests. It is supplied as the
/// per-call <see cref="DecoyDigestOptions.State"/> and reached through <see cref="DecoyDigestContext.State"/>
/// at callback time — never captured by a closure. The decoy-count delegate the tests pass is a
/// <see langword="static"/> lambda, so the compiler guarantees the probe arrives only via the threaded
/// state, mirroring how a real singleton engine would receive per-call data.
/// </summary>
internal sealed class DecoyProbe
{
    /// <summary>How many decoys the engine decides to add at each location.</summary>
    public int DecoysPerLocation { get; init; }

    /// <summary>How many times the policy was invoked (one per <c>_sd</c> location).</summary>
    public int Invocations { get; private set; }

    /// <summary>The real-disclosure counts the engine observed, in invocation order.</summary>
    public List<int> RealCountsSeen { get; } = [];

    /// <summary>Records one policy invocation and returns the decided decoy count.</summary>
    public int Decide(DecoyDigestContext context)
    {
        Invocations++;
        RealCountsSeen.Add(context.RealDisclosureCount);

        return DecoysPerLocation;
    }
}
