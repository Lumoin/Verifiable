using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The parsed VCALM 1.0 §3.3.1 / §3.3.2 verify-options object. Every member is OPTIONAL per §2.4
/// ("All properties of the options object are OPTIONAL"); an absent member defaults to
/// <see langword="false"/> / <see langword="null"/>. The parser rejects an options object carrying
/// any member the verifier does not understand by surfacing
/// <see cref="VcalmParseFailure.UnknownOption"/> — the §2.4 "Implementations MUST throw an error if
/// an endpoint receives data, options, or option values that it does not understand" MUST mapped to
/// the §3.8 <see cref="VcalmProblemTypes.UnknownOptionProvided"/> problem type.
/// </summary>
[DebuggerDisplay("VcalmVerifyOptions")]
public sealed record VcalmVerifyOptions
{
    /// <summary>
    /// §3.3.1 <c>returnResults</c> — include the verbose per-step <c>results</c> object in the
    /// response. Defaults to <see langword="false"/>.
    /// </summary>
    public bool ReturnResults { get; init; }

    /// <summary>
    /// §3.3.1 <c>returnProblemDetails</c> — include the <c>problemDetails</c> array in the
    /// response. Defaults to <see langword="false"/>.
    /// </summary>
    public bool ReturnProblemDetails { get; init; }

    /// <summary>
    /// §3.3.1 <c>returnCredential</c> — echo the verified credential back in the response "in the
    /// form in which it was verified". Defaults to <see langword="false"/>.
    /// </summary>
    public bool ReturnCredential { get; init; }

    /// <summary>
    /// §3.3.2 <c>returnPresentation</c> — "If true, then the verified presentation MUST be
    /// returned. If false or not provided, then the verified presentation MUST NOT be returned."
    /// Defaults to <see langword="false"/>.
    /// </summary>
    public bool ReturnPresentation { get; init; }

    /// <summary>
    /// §3.3.2 <c>challenge</c> — the challenge the presentation proof MUST carry. <see langword="null"/>
    /// when the caller did not bind a challenge.
    /// </summary>
    public string? Challenge { get; init; }

    /// <summary>
    /// §3.3.2 <c>domain</c> — the intended domain of validity the presentation proof MUST carry.
    /// <see langword="null"/> when the caller did not bind a domain.
    /// </summary>
    public string? Domain { get; init; }
}
