using System;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The suite's shared deterministic clock anchor.
/// </summary>
/// <remarks>
/// <see cref="CanonicalEpoch"/> is the one instant the suite validates against unless a fixture
/// needs a specific relationship to a validity window (an expired certificate, a not-yet-valid
/// window, a staleness boundary); fixture families that need such a relationship derive named
/// offsets from it rather than reading the real clock or inventing their own anchor.
/// </remarks>
internal static class TestClock
{
    /// <summary>
    /// The suite's canonical "now" for tests with no specific time relationship to validate.
    /// </summary>
    public static DateTimeOffset CanonicalEpoch { get; } = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
}
