using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.StatusList;

/// <summary>
/// The <c>status</c> claim of a Referenced Token — the set of status mechanisms the token's issuer
/// named, together with the decoded <c>status_list</c> reference when that mechanism is one of them.
/// </summary>
/// <remarks>
/// <para>
/// One carrier serves both encodings the specification defines. In JOSE it is the <c>status</c>
/// claim object, per
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">
/// Token Status List, Section 6.1</see>: "The status (status) claim MUST specify a JSON Object that
/// contains at least one reference to a status mechanism." Its <c>status_list</c> member is
/// specified by
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">
/// Section 6.2</see>: "status_list: REQUIRED when the status mechanism defined in this
/// specification is used. It MUST specify a JSON Object that contains a reference to a Status List
/// Token." In COSE it is the Status CBOR structure, per
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
/// Section 6.3</see>: "The Status CBOR structure is a Map that MUST include at least one data item
/// that refers to a status mechanism. Each data item in the Status CBOR structure comprises a
/// key-value pair, where the key MUST be a CBOR text string (major type 3) specifying the
/// identifier of the status mechanism and the corresponding value defines its contents."
/// </para>
/// <para>
/// <see cref="Mechanisms"/> is what makes the claim a three-way answer rather than a two-way one:
/// no claim at all (the carrier itself is <see langword="null"/> where it is surfaced), a claim
/// naming only mechanisms this library does not evaluate (<see cref="StatusList"/>
/// <see langword="null"/>, <see cref="Mechanisms"/> non-empty), or a claim carrying the reference a
/// verifier can act on (<see cref="StatusList"/> populated). Reading <see cref="StatusList"/> alone
/// collapses the first two.
/// </para>
/// </remarks>
[DebuggerDisplay("StatusClaim[{HasStatusList ? \"status_list\" : \"unmodelled\"}, Mechanisms={Mechanisms.Count}]")]
public sealed record StatusClaim
{
    /// <summary>
    /// Initializes a status claim from its decoded mechanism entries.
    /// </summary>
    /// <param name="statusList">
    /// The <see cref="StatusMechanismNames.StatusList"/> mechanism's decoded reference, or
    /// <see langword="null"/> when the claim does not carry that mechanism.
    /// </param>
    /// <param name="mechanisms">
    /// The mechanism identifiers present in the wire object or map. Defensively copied into an
    /// immutable ordinal set — the caller's own collection is never aliased, and the comparer is
    /// normalized regardless of what the caller passed, so every producer's instance compares and
    /// hashes alike. The invariants below are evaluated on that copy, so what the instance is
    /// checked for is exactly what it stores: a caller's case-insensitive set holding
    /// <c>STATUS_LIST</c> answers membership of <see cref="StatusMechanismNames.StatusList"/>
    /// differently from the ordinal copy, and the ordinal copy is the state that survives.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="mechanisms"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="mechanisms"/> is empty (Section 6.1's "MUST specify a JSON Object
    /// that contains at least one reference to a status mechanism" and Section 6.3's "MUST include
    /// at least one data item that refers to a status mechanism"), or when its containing
    /// <see cref="StatusMechanismNames.StatusList"/> does not agree with whether
    /// <paramref name="statusList"/> is <see langword="null"/>.
    /// </exception>
    public StatusClaim(StatusListReference? statusList, IReadOnlySet<string> mechanisms)
    {
        ArgumentNullException.ThrowIfNull(mechanisms);

        FrozenSet<string> storedMechanisms = mechanisms.ToFrozenSet(StringComparer.Ordinal);

        if(storedMechanisms.Count == 0)
        {
            throw new ArgumentException(
                "The status claim must include at least one status-mechanism entry per Token Status List Section 6.1/6.3.",
                nameof(mechanisms));
        }

        bool hasStatusListMechanism = storedMechanisms.Contains(StatusMechanismNames.StatusList);
        if(statusList is not null && !hasStatusListMechanism)
        {
            throw new ArgumentException(
                $"Mechanisms must contain '{StatusMechanismNames.StatusList}' when {nameof(statusList)} is supplied.",
                nameof(mechanisms));
        }

        if(statusList is null && hasStatusListMechanism)
        {
            throw new ArgumentException(
                $"{nameof(statusList)} must be supplied when mechanisms contains '{StatusMechanismNames.StatusList}'.",
                nameof(statusList));
        }

        StatusList = statusList;
        Mechanisms = storedMechanisms;
    }


    /// <summary>
    /// The <see cref="StatusMechanismNames.StatusList"/> mechanism's decoded index/URI reference, or
    /// <see langword="null"/> when this claim names no status list mechanism. Null here does not
    /// mean "no status claim": <see cref="Mechanisms"/> still names what the issuer did state, and a
    /// verifier that cannot evaluate any of those mechanisms can make no statement about the token's
    /// status.
    /// </summary>
    public StatusListReference? StatusList { get; }

    /// <summary>
    /// The mechanism identifiers present in the wire object or map — the Section 6.1 member names or
    /// the Section 6.3 text-string keys, <see cref="StatusMechanismNames.StatusList"/> included
    /// exactly when <see cref="StatusList"/> is populated. An immutable, ordinal-compared copy the
    /// constructor takes: mutating the collection the caller originally supplied never changes this
    /// instance.
    /// </summary>
    public IReadOnlySet<string> Mechanisms { get; }

    /// <summary>
    /// Whether this claim carries a <see cref="StatusMechanismNames.StatusList"/> reference a
    /// verifier can resolve and check.
    /// </summary>
    public bool HasStatusList => StatusList is not null;


    /// <summary>
    /// Creates a status claim naming the <see cref="StatusMechanismNames.StatusList"/> mechanism
    /// alone — the shape an issuer states when the Token Status List mechanism is the only one it
    /// publishes for the token.
    /// </summary>
    /// <param name="index">The zero-based index within the Status List.</param>
    /// <param name="uri">The URI of the Status List Token.</param>
    /// <returns>A claim whose <see cref="Mechanisms"/> is exactly <c>{status_list}</c>.</returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "The specification defines this as a string claim value serialized directly in JWT and CWT formats.")]
    public static StatusClaim FromStatusList(int index, string uri)
    {
        return new StatusClaim(
            new StatusListReference(index, uri),
            new HashSet<string>(StringComparer.Ordinal) { StatusMechanismNames.StatusList });
    }


    /// <summary>
    /// Determines value equality: <see cref="StatusList"/> compared structurally and
    /// <see cref="Mechanisms"/> compared as a set — order-independent and content-based — so two
    /// claims decoded from byte-identical wire bytes compare equal regardless of the underlying
    /// set's internal iteration order.
    /// </summary>
    /// <param name="other">The claim to compare against.</param>
    /// <returns><see langword="true"/> when both carry the same <see cref="StatusList"/> and mechanism set.</returns>
    public bool Equals(StatusClaim? other)
    {
        if(other is null)
        {
            return false;
        }

        return ReferenceEquals(this, other)
            || (StatusList == other.StatusList && Mechanisms.SetEquals(other.Mechanisms));
    }


    /// <summary>
    /// Computes a hash consistent with <see cref="Equals(StatusClaim?)"/>: an order-independent
    /// ordinal combination of <see cref="Mechanisms"/>'s contents alongside
    /// <see cref="StatusList"/>.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        int mechanismsHash = 0;
        foreach(string mechanism in Mechanisms)
        {
            mechanismsHash ^= StringComparer.Ordinal.GetHashCode(mechanism);
        }

        return HashCode.Combine(StatusList, mechanismsHash);
    }
}
