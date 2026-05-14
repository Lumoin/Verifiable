using System.Diagnostics;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The result of validating a presented DPoP nonce.
/// </summary>
[DebuggerDisplay("DpopNonceValidationResult Success={IsSuccess} Reason={FailureReason}")]
public sealed record DpopNonceValidationResult
{
    /// <summary>The decoded payload if validation succeeded.</summary>
    public DpopNoncePayload? Payload { get; init; }

    /// <summary>The failure reason if validation failed.</summary>
    public DpopNonceValidationFailureReason? FailureReason { get; init; }

    /// <summary><see langword="true"/> when the nonce is valid.</summary>
    public bool IsSuccess => FailureReason is null;

    /// <summary>Constructs a successful result wrapping the decoded payload.</summary>
    public static DpopNonceValidationResult Success(DpopNoncePayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return new DpopNonceValidationResult { Payload = payload };
    }

    /// <summary>Constructs a failure result.</summary>
    public static DpopNonceValidationResult Failure(DpopNonceValidationFailureReason reason) =>
        new() { FailureReason = reason };
}
