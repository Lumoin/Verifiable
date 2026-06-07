namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// The decoy-digest configuration for one issuance: the count policy and the per-call state that
/// policy may need. Passed explicitly through the issuance API (never captured by a closure) so the
/// decision engine receives its data as documented per-call input.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Count"/> is the decision engine (see <see cref="DecoyDigestPolicy"/>); <see cref="State"/>
/// is whatever per-call data that engine needs and is surfaced unchanged on
/// <see cref="DecoyDigestContext.State"/> at callback time. The library does not interpret
/// <see cref="State"/> — it threads it through and the caller casts it back. This keeps the seam
/// context-neutral (the OAuth or wallet layer can pass its request/tenant/user object as
/// <see cref="State"/> without <c>Verifiable.Core</c> depending on it).
/// </para>
/// <para>
/// This is a value type whose <see cref="None"/> (<see langword="default"/>) value — a null
/// <see cref="Count"/> — means "add no decoys". That makes <see cref="None"/> the natural parameter
/// default throughout the issuance API, so no nullable plumbing is needed to express "no decoys".
/// </para>
/// </remarks>
/// <param name="Count">The per-location decoy-count policy.</param>
/// <param name="State">
/// Optional per-call data the policy needs (e.g. a tenant/request/user object). Surfaced on
/// <see cref="DecoyDigestContext.State"/>; the library passes it through untouched.
/// </param>
public readonly record struct DecoyDigestOptions(DecoyDigestCountDelegate Count, object? State = null)
{
    /// <summary>
    /// The "add no decoys" configuration — the <see langword="default"/> value, with a null
    /// <see cref="Count"/>. The default at every issuance entry point.
    /// </summary>
    public static DecoyDigestOptions None => default;


    /// <summary>
    /// Lets a bare <see cref="DecoyDigestCountDelegate"/> be supplied wherever a
    /// <see cref="DecoyDigestOptions"/> is expected, for the common case of a policy with no per-call state.
    /// </summary>
    public static implicit operator DecoyDigestOptions(DecoyDigestCountDelegate count) => new(count);
}
