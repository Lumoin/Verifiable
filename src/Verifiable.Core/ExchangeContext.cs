using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Verifiable.Core;

namespace Verifiable.Core;

/// <summary>
/// The channel- and protocol-neutral per-operation context bag that flows through a credential
/// exchange (issuance, presentation, verification) and the delegate hooks an application wires
/// into it.
/// </summary>
/// <remarks>
/// <para>
/// This is the wallet/presentation-side counterpart of the Authorization Server's request
/// context, lifted to a neutral home: Verifiable Presentations are not necessarily OAuth, nor
/// even HTTP (wallet&#8596;wallet P2P, BLE, NFC, QR), so the threaded context must carry no
/// transport or protocol coupling. It is a per-operation, <em>mutable</em>, string-keyed bag —
/// handlers accumulate values (tenant identity, resolved policy, intermediate results) as the
/// operation progresses. This is deliberately distinct from <see cref="Cryptography.Tag"/>, the
/// <em>immutable</em>, type-keyed metadata attached to a single value (a key, a signature, a
/// verified credential): the two are complementary, and the exchange context is string-keyed
/// because it holds many same-typed values (tenant id, subject id, flow id are all strings) that
/// a type key cannot disambiguate.
/// </para>
/// <para>
/// Typed access is provided by extension methods so consumers never handle the string keys or
/// cast <see cref="object"/> values; cross-cutting accessors (for example tenant identity) and
/// layer-specific ones (OAuth, a given transport channel) live as extensions in their respective
/// layers, so a non-OAuth channel never drags OAuth or HTTP in. A library user that does not care
/// about tenancy or per-call routing simply passes a fresh empty context and ignores it.
/// </para>
/// <para>
/// Inheriting from <see cref="Dictionary{TKey, TValue}"/> follows the same pattern as
/// <see cref="Verifiable.JCose.JwtHeader"/>: the full dictionary API with a distinct type
/// identity that prevents accidental argument swapping at compile time. The type is left
/// unsealed so a protocol-specific context may specialize it.
/// </para>
/// </remarks>
[DebuggerDisplay("ExchangeContext({Count} entries)")]
public class ExchangeContext: Dictionary<string, object>, IEquatable<ExchangeContext>
{
    /// <summary>
    /// Creates an empty <see cref="ExchangeContext"/>.
    /// </summary>
    public ExchangeContext() : base(StringComparer.Ordinal) { }


    /// <summary>
    /// Creates an <see cref="ExchangeContext"/> with the specified initial capacity.
    /// </summary>
    /// <param name="capacity">The initial number of entries the context can contain.</param>
    public ExchangeContext(int capacity) : base(capacity, StringComparer.Ordinal) { }


    /// <summary>
    /// Creates an <see cref="ExchangeContext"/> populated from any key-value enumerable.
    /// </summary>
    /// <param name="entries">The key-value pairs to copy.</param>
    public ExchangeContext(IEnumerable<KeyValuePair<string, object>> entries)
        : base(entries, StringComparer.Ordinal) { }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(ExchangeContext? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(Count != other.Count)
        {
            return false;
        }

        foreach(KeyValuePair<string, object> kvp in this)
        {
            if(!other.TryGetValue(kvp.Key, out object? value)
                || !Equals(kvp.Value, value))
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is ExchangeContext other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach(KeyValuePair<string, object> kvp in this.OrderBy(
            static x => x.Key, StringComparer.Ordinal))
        {
            hash.Add(kvp.Key, StringComparer.Ordinal);
            hash.Add(kvp.Value);
        }

        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(ExchangeContext? left, ExchangeContext? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(ExchangeContext? left, ExchangeContext? right) =>
        !(left == right);
}
