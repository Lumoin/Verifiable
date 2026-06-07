using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The matching mode a deployment applies to the OAuth <c>state</c> parameter
/// when validating callback responses against persisted flow state.
/// </summary>
/// <remarks>
/// <para>
/// RFC 6749 §10.12 and RFC 9700 §4.7 require <c>state</c> to be unguessable and
/// bound to the user's session. The strict reading is exact-ordinal comparison
/// against the persisted value (<see cref="ExactOrdinal"/>). Some FAPI-aligned
/// deployments use HMAC-bound state where the <c>state</c> value is verified by
/// recomputing an HMAC tag rather than direct equality (<see cref="HmacBound"/>);
/// this future-proofs against state-storage compromise.
/// </para>
/// </remarks>
[DebuggerDisplay("StateMatchingMode={ToString(),nq}")]
public enum StateMatchingMode
{
    /// <summary>Exact ordinal string equality against persisted <c>state</c>.</summary>
    ExactOrdinal,

    /// <summary>HMAC-bound verification — recompute and compare tag.</summary>
    HmacBound
}
