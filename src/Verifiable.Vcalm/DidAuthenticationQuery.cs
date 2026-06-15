using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// A §3.4.3 DID Authentication query entry: the verifier requests that the holder demonstrate
/// control of a DID of an accepted method by signing the request's <c>challenge</c> (and binding the
/// <c>domain</c>). The §3.4.3.2 response — a verifiable presentation whose <c>holder</c> is a DID of
/// an accepted method, carrying a proof with the request's <c>domain</c> + <c>challenge</c> — is
/// produced and verified by the holder / verifier flow; this entry models the REQUEST and the
/// <see cref="IsHolderAccepted"/> predicate.
/// </summary>
[DebuggerDisplay("DidAuthentication Methods={AcceptedMethods.Length} Group={Group}")]
public sealed record DidAuthenticationQuery: VcalmPresentationQuery
{
    /// <summary>
    /// The §3.4.3 <c>acceptedMethods</c> — DID-method names the verifier accepts (e.g. <c>key</c>,
    /// <c>web</c>). Empty when the query omits the (optional) array, in which case any method is
    /// acceptable.
    /// </summary>
    public ImmutableArray<string> AcceptedMethods { get; init; } = ImmutableArray<string>.Empty;

    /// <summary>
    /// The §3.4.3 <c>acceptedCryptosuites</c> — the cryptosuites among which the holder MUST choose
    /// when generating the authentication proof. Empty when the query omits the (optional) array.
    /// </summary>
    public ImmutableArray<string> AcceptedCryptosuites { get; init; } = ImmutableArray<string>.Empty;


    /// <summary>
    /// The §3.4.3 holder-side predicate: whether a candidate holder DID is of one of the
    /// <see cref="AcceptedMethods"/>. An empty <see cref="AcceptedMethods"/> accepts any DID (the
    /// §3.4.3 array is optional). Matching is on the <c>did:&lt;method&gt;:</c> prefix.
    /// </summary>
    /// <param name="holderDid">The candidate holder DID (e.g. <c>did:key:z6Mk...</c>).</param>
    /// <returns><see langword="true"/> when the DID's method is accepted; otherwise <see langword="false"/>.</returns>
    public bool IsHolderAccepted(string holderDid)
    {
        ArgumentNullException.ThrowIfNull(holderDid);

        if(AcceptedMethods.IsEmpty)
        {
            return true;
        }

        foreach(string method in AcceptedMethods)
        {
            //§3.4.3 acceptedMethods carry the DID-method NAME; a holder DID is did:<method>:<id>.
            string prefix = string.Concat("did:", method, ":");
            if(holderDid.StartsWith(prefix, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
