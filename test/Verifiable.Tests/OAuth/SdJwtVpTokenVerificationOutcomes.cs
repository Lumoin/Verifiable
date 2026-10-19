using Verifiable.Core;
using Verifiable.OAuth.Oid4Vp.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The tests' reading of an SD-JWT VP token verification's outcome where a row presents a well-formed presentation: its contents
/// and the facts of its checks, the row failing with the defect named when the verification refused the presentation instead.
/// </summary>
internal static class SdJwtVpTokenVerificationOutcomes
{
    /// <summary>The contents and the facts of the checks of an outcome the row expects read.</summary>
    /// <param name="outcome">The outcome.</param>
    /// <returns>The contents and the facts of the checks.</returns>
    /// <exception cref="AssertFailedException">The verification refused the presentation.</exception>
    public static VpTokenParsed ExpectRead(this Result<VpTokenParsed, SdJwtPresentationDefect> outcome) =>
        outcome.IsSuccess
            ? outcome.Value
            : throw new AssertFailedException($"The presentation was refused as {outcome.Error}, where the row expects it read.");
}
