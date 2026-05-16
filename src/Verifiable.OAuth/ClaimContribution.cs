using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// Application-contributed claims merged into a token's payload during the
/// token-endpoint pipeline.
/// </summary>
/// <remarks>
/// <para>
/// The contribution is a typed record carrying an ordered list of
/// <see cref="ClaimEntry"/> items rather than a raw dictionary. The record
/// shape makes the merge semantics explicit: claims are applied to the
/// payload in list order, later entries overwrite earlier entries with the
/// same name, and the contribution itself is immutable.
/// </para>
/// <para>
/// Claim values remain typed as <see cref="object"/> on
/// <see cref="ClaimEntry.Value"/> because JWT payloads are genuinely
/// heterogeneous: strings (<c>sub</c>, <c>iss</c>, <c>jti</c>), numbers
/// (<c>iat</c>, <c>nbf</c>, <c>exp</c>), arrays of strings (<c>aud</c>,
/// <c>amr</c>), booleans, and nested objects (e.g.,
/// <c>verified_claims</c>). The narrowing to JSON wire form happens in the
/// JWT payload serializer the application wires through
/// <see cref="AuthorizationServerCodecs.JwtPayloadSerializer"/>; that is
/// the layer that owns the JSON shape decisions. A typed-union for claim
/// values would have to enumerate every JWT claim shape across every
/// extension spec, which is not a closed set.
/// </para>
/// </remarks>
[DebuggerDisplay("ClaimContribution Entries={Entries.Count}")]
public sealed record ClaimContribution(IReadOnlyList<ClaimEntry> Entries)
{
    /// <summary>
    /// An empty contribution. Use this from
    /// <see cref="ClaimContributorBuildDelegate"/> implementations that
    /// have nothing to add for a given producer in a given request.
    /// </summary>
    public static readonly ClaimContribution Empty =
        new(Array.Empty<ClaimEntry>());
}


/// <summary>
/// A single named claim entry contributed by a
/// <see cref="ClaimContributor"/>. The <see cref="Value"/> is typed as
/// <see cref="object"/> to span the heterogeneous JWT claim value shapes;
/// see the remarks on <see cref="ClaimContribution"/> for why this is the
/// correct boundary at this layer.
/// </summary>
/// <param name="Name">
/// The claim name. Use values from
/// <see cref="Verifiable.JCose.WellKnownJwtClaimNames"/> or other well-known
/// claim-name classes rather than raw string literals.
/// </param>
/// <param name="Value">
/// The claim value. Acceptable runtime types are those the JWT payload
/// serializer wired into
/// <see cref="AuthorizationServerCodecs.JwtPayloadSerializer"/> can encode.
/// </param>
[DebuggerDisplay("ClaimEntry {Name,nq}")]
public sealed record ClaimEntry(string Name, object Value);
