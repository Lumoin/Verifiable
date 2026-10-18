using Verifiable.OAuth.Oid4Vp.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The tests' reading of an SD-JWT VP token verification's outcome where a row presents a well-formed presentation: its verified
/// contents, the row failing with the refusal named when the verification refused the presentation instead.
/// </summary>
internal static class SdJwtVpTokenVerificationOutcomes
{
    /// <summary>The verified contents of an outcome the row expects verified.</summary>
    /// <param name="outcome">The outcome.</param>
    /// <returns>The verified contents.</returns>
    /// <exception cref="AssertFailedException">The verification refused the presentation.</exception>
    public static VpTokenParsed ExpectVerified(this SdJwtVpTokenVerificationOutcome outcome) => outcome switch
    {
        SdJwtVpTokenVerified { Parsed: var parsed } => parsed,
        SdJwtVpTokenRefused { Defect: var defect } => throw new AssertFailedException($"The presentation was refused as {defect}, where the row expects it verified."),
        _ => throw new AssertFailedException($"The verification answered {outcome}, neither its contents nor its refusal.")
    };
}
