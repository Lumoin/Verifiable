using System.Diagnostics;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The typed payload of a DPoP nonce, as decoded by the validator. Exposed
/// for applications wanting to inspect what a nonce carries (diagnostics,
/// logging, custom validation composition). Library code never constructs
/// this directly — issuance produces the wire form, validation produces
/// this on a successful decode.
/// </summary>
[DebuggerDisplay("DpopNoncePayload Kid={Kid,nq} IssuedAt={IssuedAt}")]
public sealed record DpopNoncePayload
{
    /// <summary>The kid of the HMAC key that signed this nonce.</summary>
    public required string Kid { get; init; }

    /// <summary>The issuance time recorded in the nonce.</summary>
    public required DateTimeOffset IssuedAt { get; init; }
}
