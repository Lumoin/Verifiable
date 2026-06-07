using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;

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
    /// Creates a new selective disclosure token, taking ownership of the supplied disclosures.
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
    }


    /// <summary>
    /// Creates a new token with a subset of disclosures, copying each selected
    /// disclosure so the new token owns its own independent copies.
    /// </summary>
    /// <param name="selector">Function to select which disclosures to include.</param>
    /// <param name="pool">Memory pool to allocate the copies' salt buffers from.</param>
    /// <returns>
    /// A new token whose disclosures are fresh copies. The source token remains valid.
    /// Key binding is not carried over — it would need to be recomputed for the new
    /// disclosure set.
    /// </returns>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when this token has been disposed.
    /// </exception>
    public SdToken<TEnvelope> SelectDisclosures(Func<SdDisclosure, bool> selector, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentNullException.ThrowIfNull(pool);
        ObjectDisposedException.ThrowIf(disposed, this);

        var copies = new List<SdDisclosure>();

        try
        {
            foreach(SdDisclosure d in Disclosures)
            {
                if(selector(d))
                {
                    copies.Add(d.CopyWithFreshSalt(pool));
                }
            }

            return new SdToken<TEnvelope>(IssuerSigned, copies);
        }
        catch
        {
            //Construction or copy failed — dispose any copies already made.
            foreach(SdDisclosure copy in copies)
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
    public SdToken<TEnvelope> SelectDisclosures(IEnumerable<SdDisclosure> disclosures, MemoryPool<byte> pool)
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

        var copies = new List<SdDisclosure>();

        try
        {
            foreach(SdDisclosure d in requested)
            {
                copies.Add(d.CopyWithFreshSalt(pool));
            }

            return new SdToken<TEnvelope>(IssuerSigned, copies);
        }
        catch
        {
            foreach(SdDisclosure copy in copies)
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
    public SdToken<TEnvelope> WithKeyBinding(TEnvelope keyBinding, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(keyBinding);
        ArgumentNullException.ThrowIfNull(pool);
        ObjectDisposedException.ThrowIf(disposed, this);

        var copies = new List<SdDisclosure>();

        try
        {
            foreach(SdDisclosure d in Disclosures)
            {
                copies.Add(d.CopyWithFreshSalt(pool));
            }

            return new SdToken<TEnvelope>(IssuerSigned, copies, keyBinding);
        }
        catch
        {
            foreach(SdDisclosure copy in copies)
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
    public SdToken<TEnvelope> WithoutKeyBinding(MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ObjectDisposedException.ThrowIf(disposed, this);

        var copies = new List<SdDisclosure>();

        try
        {
            foreach(SdDisclosure d in Disclosures)
            {
                copies.Add(d.CopyWithFreshSalt(pool));
            }

            return new SdToken<TEnvelope>(IssuerSigned, copies);
        }
        catch
        {
            foreach(SdDisclosure copy in copies)
            {
                copy.Dispose();
            }
            throw;
        }
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


    /// <inheritdoc/>
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
    public override bool Equals(object? obj) => obj is SdToken<TEnvelope> other && Equals(other);


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
