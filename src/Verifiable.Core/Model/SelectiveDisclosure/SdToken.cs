using System.Buffers;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// A selective disclosure token containing an issuer-signed payload and disclosures.
/// </summary>
/// <typeparam name="TEnvelope">
/// The envelope type: <see cref="string"/> for SD-JWT, <see cref="ReadOnlyMemory{T}"/>
/// of <see cref="byte"/> for SD-CWT.
/// </typeparam>
/// <remarks>
/// <para>
/// The token owns its <see cref="SdDisclosure"/> instances. Disposing the token
/// disposes every disclosure (and therefore every salt). Selection and key-binding
/// operations produce new tokens that own freshly-allocated copies of the disclosures
/// — the source token remains valid and independently disposable.
/// </para>
/// <para>
/// <strong>Positions.</strong> <see cref="DisclosurePaths"/>, <see cref="IssuerSignedClaims"/> and
/// <see cref="DisclosureInteriorClaims"/> are computed by the format-specific leaf that has the
/// issuer-signed payload in hand — <c>Verifiable.Json.Sd.SdJwtSerializer.ParseToken</c> for SD-JWT,
/// <c>Verifiable.Cbor.SdCwtSerializer.ParseToken</c> for SD-CWT — so a token built through
/// <see cref="CreateParsed"/> carries the real position of every disclosure, the value of every
/// unconditionally disclosed claim, and the value of every node that only a disclosure's release
/// reveals. The plain constructor is for issuance-side callers that have disclosures but no signed
/// payload to walk yet; it defaults all three to empty, which is corrected once the issued token is
/// parsed back.
/// </para>
/// <para>
/// <strong>Wire Format (SD-JWT):</strong>
/// </para>
/// <code>
/// Without key binding: &lt;issuer-jwt&gt;~&lt;disclosure1&gt;~&lt;disclosure2&gt;~...~
/// With key binding:    &lt;issuer-jwt&gt;~&lt;disclosure1&gt;~&lt;disclosure2&gt;~...~&lt;kb-jwt&gt;
/// </code>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public class SdToken<TEnvelope>: IEquatable<SdToken<TEnvelope>>, IDisposable where TEnvelope : notnull
{
    /// <summary>
    /// The shared empty value for <see cref="IssuerSignedClaims"/> and
    /// <see cref="DisclosureInteriorClaims"/> on a token built through the plain constructor.
    /// Frozen, so the read-only interface cannot be cast back to a mutable collection.
    /// </summary>
    private static IReadOnlyDictionary<CredentialPath, object?> EmptyClaims { get; } =
        FrozenDictionary<CredentialPath, object?>.Empty;

    /// <summary>Whether this token's disclosures have already been released.</summary>
    private bool disposed;


    /// <summary>The issuer-signed payload (JWT string or CWT bytes).</summary>
    public TEnvelope IssuerSigned { get; }

    /// <summary>The disclosures included in this token.</summary>
    public IReadOnlyList<SdDisclosure> Disclosures { get; }

    /// <summary>The key binding proof, or <c>null</c> if not present.</summary>
    public TEnvelope? KeyBinding { get; }

    /// <summary>Whether this token has key binding.</summary>
    public bool HasKeyBinding => KeyBinding is not null;

    /// <summary>
    /// The concrete <see cref="CredentialPath"/> each disclosure occupies in the issuer-signed
    /// structure, as resolved by the format-specific parse. <see cref="SdDisclosurePaths.Empty"/>
    /// for a token built through the plain constructor (no payload has been walked).
    /// </summary>
    public SdDisclosurePaths DisclosurePaths { get; }

    /// <summary>
    /// Every node of the issuer-signed payload that is unconditionally disclosed — the
    /// SD-JWT/SD-CWT mechanism keys and markers removed, containers carried as nodes and leaves
    /// as their values — keyed by <see cref="CredentialPath"/>. Empty for a token built through
    /// the plain constructor.
    /// </summary>
    /// <remarks>
    /// The invariant is exact and every format leaf must hold it: a path is here only when the
    /// node it names is readable without releasing any disclosure. A node that exists only inside
    /// a disclosure's own value is NOT here — it is in <see cref="DisclosureInteriorClaims"/> —
    /// because reading it costs that disclosure's release, and a caller that treats it as
    /// unconditionally disclosed would report a claim as delivered while it never reaches the
    /// wire.
    /// </remarks>
    public IReadOnlyDictionary<CredentialPath, object?> IssuerSignedClaims { get; }

    /// <summary>
    /// Every node that exists only inside a disclosure's own value — a member of a recursively
    /// disclosable object, an element of a disclosable array — keyed by <see cref="CredentialPath"/>.
    /// Reading such a node costs the release of the disclosure at its nearest ancestor position in
    /// <see cref="DisclosurePaths"/>, which is what
    /// <see cref="SelectDisclosures(IReadOnlySet{CredentialPath}, BaseMemoryPool)"/> selects when
    /// one of these paths is asked for. Empty for a token built through the plain constructor.
    /// </summary>
    public IReadOnlyDictionary<CredentialPath, object?> DisclosureInteriorClaims { get; }


    /// <summary>
    /// Creates a new selective disclosure token, taking ownership of the supplied disclosures.
    /// <see cref="DisclosurePaths"/> and <see cref="IssuerSignedClaims"/> are empty — this
    /// constructor is for issuance-side callers that have not yet parsed the issued payload
    /// back. Use <see cref="CreateParsed"/> when the positions are known.
    /// </summary>
    /// <param name="issuerSigned">The issuer-signed payload.</param>
    /// <param name="disclosures">
    /// The disclosures. Ownership of each disclosure transfers to the new token —
    /// callers must not dispose them after calling this constructor. Disposing the
    /// token disposes every disclosure.
    /// </param>
    /// <param name="keyBinding">Optional key binding proof.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="issuerSigned"/> or <paramref name="disclosures"/> is null.
    /// In that case any non-null disclosures already in the list are disposed before the
    /// exception propagates.
    /// </exception>
    public SdToken(TEnvelope issuerSigned, IReadOnlyList<SdDisclosure> disclosures, TEnvelope? keyBinding = default)
        : this(issuerSigned, disclosures, SdDisclosurePaths.Empty, EmptyClaims, EmptyClaims, keyBinding)
    {
    }


    /// <summary>
    /// Creates a new selective disclosure token whose disclosure positions and claim maps are
    /// already known, taking ownership of the supplied disclosures. This is the
    /// factory the format-specific parse (<c>SdJwtSerializer.ParseToken</c>,
    /// <c>SdCwtSerializer.ParseToken</c>) uses once it has walked the issuer-signed payload.
    /// </summary>
    /// <param name="issuerSigned">The issuer-signed payload.</param>
    /// <param name="disclosures">
    /// The disclosures. Ownership of each disclosure transfers to the new token —
    /// callers must not dispose them after calling this method.
    /// </param>
    /// <param name="disclosurePaths">Each disclosure's resolved position.</param>
    /// <param name="issuerSignedClaims">Every unconditionally disclosed node, keyed by its path.</param>
    /// <param name="disclosureInteriorClaims">Every node interior to a disclosure, keyed by its path.</param>
    /// <param name="keyBinding">Optional key binding proof.</param>
    /// <returns>The parsed token. Caller owns and disposes it.</returns>
    public static SdToken<TEnvelope> CreateParsed(
        TEnvelope issuerSigned,
        IReadOnlyList<SdDisclosure> disclosures,
        SdDisclosurePaths disclosurePaths,
        IReadOnlyDictionary<CredentialPath, object?> issuerSignedClaims,
        IReadOnlyDictionary<CredentialPath, object?> disclosureInteriorClaims,
        TEnvelope? keyBinding = default)
    {
        ArgumentNullException.ThrowIfNull(disclosurePaths);
        ArgumentNullException.ThrowIfNull(issuerSignedClaims);
        ArgumentNullException.ThrowIfNull(disclosureInteriorClaims);

        return new SdToken<TEnvelope>(issuerSigned, disclosures, disclosurePaths, issuerSignedClaims, disclosureInteriorClaims, keyBinding);
    }


    /// <summary>
    /// Creates a token from an already-resolved set of positions, disposing the supplied
    /// disclosures when the arguments do not admit a token.
    /// </summary>
    /// <param name="issuerSigned">The issuer-signed payload.</param>
    /// <param name="disclosures">The disclosures whose ownership transfers to this token.</param>
    /// <param name="disclosurePaths">Each disclosure's resolved position.</param>
    /// <param name="issuerSignedClaims">Every unconditionally disclosed node, keyed by its path.</param>
    /// <param name="disclosureInteriorClaims">Every node interior to a disclosure, keyed by its path.</param>
    /// <param name="keyBinding">Optional key binding proof.</param>
    private SdToken(
        TEnvelope issuerSigned,
        IReadOnlyList<SdDisclosure> disclosures,
        SdDisclosurePaths disclosurePaths,
        IReadOnlyDictionary<CredentialPath, object?> issuerSignedClaims,
        IReadOnlyDictionary<CredentialPath, object?> disclosureInteriorClaims,
        TEnvelope? keyBinding)
    {
        if(issuerSigned is null || disclosures is null)
        {
            //Dispose any disclosures the caller handed in before throwing — caller
            //has already transferred ownership.
            if(disclosures is not null)
            {
                foreach(SdDisclosure d in disclosures)
                {
                    d?.Dispose();
                }
            }

            ArgumentNullException.ThrowIfNull(issuerSigned);
            ArgumentNullException.ThrowIfNull(disclosures);
        }

        IssuerSigned = issuerSigned;
        Disclosures = disclosures;
        KeyBinding = keyBinding;
        DisclosurePaths = disclosurePaths;
        IssuerSignedClaims = issuerSignedClaims;
        DisclosureInteriorClaims = disclosureInteriorClaims;
    }


    /// <summary>
    /// Creates a new token with a subset of disclosures, copying each selected
    /// disclosure so the new token owns its own independent copies.
    /// </summary>
    /// <remarks>
    /// The predicate decides on the disclosure alone, so this overload does exactly what it is
    /// told and no more: it applies none of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see> §7.2 step 2.b's ancestor
    /// closure, and a predicate written over <see cref="SdDisclosure.ClaimName"/> cannot tell two
    /// §9.3 namesakes apart — the same claim name legitimately recurs at different depths with
    /// independent salts, and the predicate sees both. A caller acting on a DCQL decision, or on
    /// any request expressed as positions, takes
    /// <see cref="SelectDisclosures(IReadOnlySet{CredentialPath}, BaseMemoryPool)"/> instead,
    /// which selects by position and pulls in the ancestors that make the selection readable.
    /// </remarks>
    /// <param name="selector">Function to select which disclosures to include.</param>
    /// <param name="pool">Memory pool to allocate the copies' salt buffers from.</param>
    /// <returns>
    /// A new token whose disclosures are fresh copies, carrying the corresponding subset of
    /// <see cref="DisclosurePaths"/> and this token's <see cref="IssuerSignedClaims"/>. The
    /// source token remains valid. Key binding is not carried over — it would need to be
    /// recomputed for the new disclosure set.
    /// </returns>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when this token has been disposed.
    /// </exception>
    public SdToken<TEnvelope> SelectDisclosures(Func<SdDisclosure, bool> selector, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentNullException.ThrowIfNull(pool);
        ObjectDisposedException.ThrowIf(disposed, this);

        var pairs = new List<(SdDisclosure Original, SdDisclosure Copy)>();

        try
        {
            foreach(SdDisclosure d in Disclosures)
            {
                if(selector(d))
                {
                    pairs.Add((d, d.CopyWithFreshSalt(pool)));
                }
            }

            return DeriveToken(pairs);
        }
        catch
        {
            //Construction or copy failed — dispose any copies already made.
            foreach((_, SdDisclosure copy) in pairs)
            {
                copy.Dispose();
            }
            throw;
        }
    }


    /// <summary>
    /// Creates a new token with the disclosures at the given paths, plus their disclosable
    /// ancestors (RFC 9901 §7.2 step 2, via <see cref="SdDisclosureSelection.CreateLattice"/>'s
    /// mandatory-path closure), each included once.
    /// </summary>
    /// <remarks>
    /// A path that names an unconditionally disclosed claim (present in
    /// <see cref="IssuerSignedClaims"/> but not <see cref="DisclosurePaths"/>) selects nothing
    /// extra — it is already disclosed — and is not reported as unmatched. A path that names a
    /// node interior to a disclosure (<see cref="DisclosureInteriorClaims"/>) selects the
    /// disclosure at its nearest ancestor position, since that release is what puts the node on
    /// the wire; the §7.2 step 2.b closure then pulls in the rest of the chain. A path that merely
    /// sits below a disclosure's position without the credential carrying anything there addresses
    /// nothing, so it releases nothing rather than paying a disclosure for a claim that does not
    /// exist. A path that addresses nothing this token carries at all is reported in
    /// <see cref="SdDisclosureSelectionResult{TEnvelope}.UnmatchedPaths"/>; the selection still
    /// returns with whatever did resolve. This is the documented default path for a DCQL-driven
    /// selection; <see cref="SelectDisclosures(Func{SdDisclosure, bool}, BaseMemoryPool)"/>
    /// remains the escape hatch for a caller that already has the exact disclosure set in hand.
    /// </remarks>
    /// <param name="selectedPaths">The paths to disclose.</param>
    /// <param name="pool">Memory pool to allocate the copies' salt buffers from.</param>
    /// <returns>The selected token together with any paths that matched nothing.</returns>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when this token has been disposed.
    /// </exception>
    [SuppressMessage(
        "Reliability", "CA2000",
        Justification =
            "The constructed SdToken's ownership transfers to the returned " +
            "SdDisclosureSelectionResult.Token; the caller disposes it. The analyzer cannot " +
            "see ownership carried through a record struct return value.")]
    public SdDisclosureSelectionResult<TEnvelope> SelectDisclosures(IReadOnlySet<CredentialPath> selectedPaths, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(selectedPaths);
        ArgumentNullException.ThrowIfNull(pool);
        ObjectDisposedException.ThrowIf(disposed, this);

        var unmatched = new HashSet<CredentialPath>();
        var selectableSeeds = new HashSet<CredentialPath>();

        foreach(CredentialPath path in selectedPaths)
        {
            if(DisclosurePaths.Paths.Contains(path))
            {
                selectableSeeds.Add(path);
            }
            else if(!IssuerSignedClaims.ContainsKey(path))
            {
                if(DisclosureInteriorClaims.ContainsKey(path)
                    && DisclosurePaths.TryFindEnclosingDisclosurePath(path, out CredentialPath owningPath))
                {
                    selectableSeeds.Add(owningPath);
                }
                else
                {
                    unmatched.Add(path);
                }
            }
        }

        SetDisclosureLattice<CredentialPath> lattice = SdDisclosureSelection.CreateLattice(DisclosurePaths);
        IReadOnlySet<CredentialPath> closure = lattice.ComputeClosure(selectableSeeds);

        var pairs = new List<(SdDisclosure Original, SdDisclosure Copy)>();

        try
        {
            foreach(CredentialPath path in closure)
            {
                if(DisclosurePaths.TryGetDisclosure(path, out SdDisclosure? disclosure))
                {
                    pairs.Add((disclosure, disclosure.CopyWithFreshSalt(pool)));
                }
            }

            SdToken<TEnvelope> selected = DeriveToken(pairs);

            return new SdDisclosureSelectionResult<TEnvelope>(selected, unmatched);
        }
        catch
        {
            foreach((_, SdDisclosure copy) in pairs)
            {
                copy.Dispose();
            }
            throw;
        }
    }


    /// <summary>
    /// Creates a new token with the specified disclosures, copying each so the new
    /// token owns its own independent copies. Each supplied disclosure must be
    /// reference-equal to one in this token's <see cref="Disclosures"/> list.
    /// </summary>
    /// <param name="disclosures">The disclosures to include (must be from this token).</param>
    /// <param name="pool">Memory pool to allocate the copies' salt buffers from.</param>
    /// <returns>A new token whose disclosures are fresh copies.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when a supplied disclosure is not present in this token.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when this token has been disposed.
    /// </exception>
    public SdToken<TEnvelope> SelectDisclosures(IEnumerable<SdDisclosure> disclosures, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(disclosures);
        ArgumentNullException.ThrowIfNull(pool);
        ObjectDisposedException.ThrowIf(disposed, this);

        var requested = disclosures.ToList();

        foreach(SdDisclosure d in requested)
        {
            if(!Disclosures.Contains(d))
            {
                throw new ArgumentException(
                    $"Disclosure not present in token: {d}",
                    nameof(disclosures));
            }
        }

        var pairs = new List<(SdDisclosure Original, SdDisclosure Copy)>();

        try
        {
            foreach(SdDisclosure d in requested)
            {
                pairs.Add((d, d.CopyWithFreshSalt(pool)));
            }

            return DeriveToken(pairs);
        }
        catch
        {
            foreach((_, SdDisclosure copy) in pairs)
            {
                copy.Dispose();
            }
            throw;
        }
    }


    /// <summary>
    /// Creates a new token with key binding attached. The new token gets fresh copies
    /// of all disclosures; the source token remains valid.
    /// </summary>
    /// <param name="keyBinding">The key binding proof.</param>
    /// <param name="pool">Memory pool to allocate the copies' salt buffers from.</param>
    /// <returns>A new token with key binding and copied disclosures.</returns>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when this token has been disposed.
    /// </exception>
    public SdToken<TEnvelope> WithKeyBinding(TEnvelope keyBinding, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(keyBinding);
        ArgumentNullException.ThrowIfNull(pool);
        ObjectDisposedException.ThrowIf(disposed, this);

        var pairs = new List<(SdDisclosure Original, SdDisclosure Copy)>();

        try
        {
            foreach(SdDisclosure d in Disclosures)
            {
                pairs.Add((d, d.CopyWithFreshSalt(pool)));
            }

            return DeriveToken(pairs, keyBinding);
        }
        catch
        {
            foreach((_, SdDisclosure copy) in pairs)
            {
                copy.Dispose();
            }
            throw;
        }
    }


    /// <summary>
    /// Creates a new token without key binding. The new token gets fresh copies of
    /// all disclosures; the source token remains valid.
    /// </summary>
    /// <param name="pool">Memory pool to allocate the copies' salt buffers from.</param>
    /// <returns>A new token without key binding and with copied disclosures.</returns>
    public SdToken<TEnvelope> WithoutKeyBinding(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ObjectDisposedException.ThrowIf(disposed, this);

        var pairs = new List<(SdDisclosure Original, SdDisclosure Copy)>();

        try
        {
            foreach(SdDisclosure d in Disclosures)
            {
                pairs.Add((d, d.CopyWithFreshSalt(pool)));
            }

            return DeriveToken(pairs);
        }
        catch
        {
            foreach((_, SdDisclosure copy) in pairs)
            {
                copy.Dispose();
            }
            throw;
        }
    }


    /// <summary>
    /// Extracts the copies out of a list of (original, copy) pairs, in order.
    /// </summary>
    /// <param name="pairs">The original/copy pairs built while copying disclosures.</param>
    /// <returns>The copies, in the same order as <paramref name="pairs"/>.</returns>
    private static List<SdDisclosure> CopiesOf(List<(SdDisclosure Original, SdDisclosure Copy)> pairs)
    {
        var copies = new List<SdDisclosure>(pairs.Count);
        foreach((_, SdDisclosure copy) in pairs)
        {
            copies.Add(copy);
        }

        return copies;
    }


    /// <summary>
    /// Builds the token a copy operation produces: the copies own it, the positions are re-keyed
    /// onto them, the unconditionally disclosed claims carry over unchanged, and only the
    /// interior nodes whose owning disclosure survived the copy come with it.
    /// </summary>
    /// <param name="pairs">The original/copy pairs built while copying disclosures.</param>
    /// <param name="keyBinding">The key binding proof to attach, or the default for none.</param>
    /// <returns>The derived token. The caller owns and disposes it.</returns>
    private SdToken<TEnvelope> DeriveToken(
        List<(SdDisclosure Original, SdDisclosure Copy)> pairs,
        TEnvelope? keyBinding = default)
    {
        SdDisclosurePaths paths = PathsFor(pairs);

        return CreateParsed(IssuerSigned, CopiesOf(pairs), paths, IssuerSignedClaims, InteriorClaimsFor(paths), keyBinding);
    }


    /// <summary>
    /// Rebuilds <see cref="DisclosurePaths"/> for a derived token's own copies, so the derived
    /// token never carries a path keyed by a disclosure it does not own (the source token may be
    /// disposed independently, which would otherwise leave a dangling key).
    /// </summary>
    /// <param name="pairs">The original/copy pairs built while copying disclosures.</param>
    /// <returns>A disclosure/path map keyed by the copies.</returns>
    private SdDisclosurePaths PathsFor(List<(SdDisclosure Original, SdDisclosure Copy)> pairs)
    {
        var map = new Dictionary<SdDisclosure, CredentialPath>(ReferenceEqualityComparer.Instance);
        foreach((SdDisclosure original, SdDisclosure copy) in pairs)
        {
            if(DisclosurePaths.TryGetPath(original, out CredentialPath path))
            {
                map[copy] = path;
            }
        }

        return new SdDisclosurePaths(map);
    }


    /// <summary>
    /// Narrows <see cref="DisclosureInteriorClaims"/> to the nodes a derived token can actually
    /// deliver: an interior node is readable only through the disclosure that carries it, so it
    /// travels only when that disclosure is among <paramref name="survivingPaths"/>.
    /// </summary>
    /// <param name="survivingPaths">The positions the derived token's own disclosures occupy.</param>
    /// <returns>The interior nodes the derived token carries.</returns>
    private IReadOnlyDictionary<CredentialPath, object?> InteriorClaimsFor(SdDisclosurePaths survivingPaths)
    {
        if(DisclosureInteriorClaims.Count == 0)
        {
            return DisclosureInteriorClaims;
        }

        var carried = new Dictionary<CredentialPath, object?>();
        foreach(KeyValuePair<CredentialPath, object?> interior in DisclosureInteriorClaims)
        {
            if(DisclosurePaths.TryFindEnclosingDisclosurePath(interior.Key, out CredentialPath owner) && survivingPaths.Paths.Contains(owner))
            {
                carried[interior.Key] = interior.Value;
            }
        }

        return carried;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }


    /// <summary>
    /// Releases the disclosures owned by this token.
    /// </summary>
    /// <param name="disposing">
    /// <see langword="true"/> when called from <see cref="Dispose()"/>;
    /// <see langword="false"/> when called from a finalizer (no finalizer is declared
    /// on this type, so this path is not taken under normal conditions).
    /// </param>
    protected virtual void Dispose(bool disposing)
    {
        if(disposed)
        {
            return;
        }

        disposed = true;

        if(disposing)
        {
            foreach(SdDisclosure d in Disclosures)
            {
                d.Dispose();
            }
        }
    }


    private string DebuggerDisplay =>
        HasKeyBinding
            ? $"SdToken+KB: {Disclosures.Count} disclosures"
            : $"SdToken: {Disclosures.Count} disclosures";


    /// <summary>
    /// Determines whether this token is equal to <paramref name="other"/> by comparing
    /// <see cref="IssuerSigned"/>, <see cref="KeyBinding"/> and every <see cref="Disclosures"/>
    /// entry in order. Equality is exact-type, not polymorphic over subtypes: a derived type
    /// with the same members is never equal to a base instance.
    /// </summary>
    /// <param name="other">The token to compare against.</param>
    /// <returns><see langword="true"/> if the tokens are equal; otherwise <see langword="false"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(SdToken<TEnvelope>? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(GetType() != other.GetType())
        {
            return false;
        }

        if(!EqualityComparer<TEnvelope>.Default.Equals(IssuerSigned, other.IssuerSigned))
        {
            return false;
        }

        if(!EqualityComparer<TEnvelope?>.Default.Equals(KeyBinding, other.KeyBinding))
        {
            return false;
        }

        if(Disclosures.Count != other.Disclosures.Count)
        {
            return false;
        }

        for(int i = 0; i < Disclosures.Count; i++)
        {
            if(!Disclosures[i].Equals(other.Disclosures[i]))
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) =>
        obj is SdToken<TEnvelope> other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(IssuerSigned);
        hash.Add(KeyBinding);

        foreach(SdDisclosure disclosure in Disclosures)
        {
            hash.Add(disclosure);
        }

        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(SdToken<TEnvelope>? left, SdToken<TEnvelope>? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(SdToken<TEnvelope>? left, SdToken<TEnvelope>? right) => !(left == right);
}
