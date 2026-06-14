namespace Verifiable.Vcalm;

/// <summary>
/// The neutral base for a single §3.4.1 query entry inside a
/// <see cref="VerifiablePresentationRequest"/>. Every query entry is a map that MUST define a
/// string <c>type</c> (carried in <see cref="Type"/>) and MAY carry a §3.4.5 <see cref="Group"/>
/// label that drives the AND / OR combination semantics.
/// </summary>
/// <remarks>
/// <para>
/// The §3.4.1 <c>query</c> array is the request's extension point: this document defines the
/// <see cref="QueryByExampleQuery"/>, <see cref="DidAuthenticationQuery"/>,
/// <see cref="DigitalCredentialQueryLanguageQuery"/> (the co-equal DCQL type), and the
/// editor-unstable <see cref="AuthorizationCapabilityRequestQuery"/> shapes, plus an
/// <see cref="UnknownQuery"/> fallback for a recognized-but-untyped extension a verifier introduces.
/// </para>
/// <para>
/// The model is a closed discriminated hierarchy: matching on the concrete subtype, not on the
/// <see cref="Type"/> string, is the in-library way to branch — the string is the wire identity the
/// parser maps from and the writer maps to.
/// </para>
/// </remarks>
public abstract record VcalmPresentationQuery
{
    /// <summary>
    /// The §3.4.1 REQUIRED query <c>type</c> string ("each map MUST define a type property with an
    /// associated string value"). The well-known values are in <see cref="VcalmQueryTypes"/>.
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// The §3.4.5 OPTIONAL grouping label. Queries sharing a <see cref="Group"/> value are combined
    /// with "AND"; queries with a different or absent (<see langword="null"/>) value are combined
    /// with "OR".
    /// </summary>
    public string? Group { get; init; }
}
