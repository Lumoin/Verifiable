using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A JSON Web Key per
/// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 §4</see>,
/// represented as a string-keyed dictionary with typed accessors for the parameters
/// defined by RFC 7517 and RFC 7518.
/// </summary>
/// <remarks>
/// <para>
/// This type inherits from <see cref="Dictionary{TKey, TValue}"/> and provides
/// type identity at API boundaries, preventing accidental swapping of arguments
/// where a JWK is expected. Parameter names match the lowercase abbreviations
/// defined in RFC 7517 and RFC 7518 — <c>kty</c>, <c>alg</c>, <c>use</c>, <c>kid</c>,
/// <c>crv</c>, <c>x</c>, <c>y</c>, <c>n</c>, <c>e</c>, <c>pub</c>, and any
/// algorithm-specific or extension parameters — all stored as top-level dictionary
/// entries.
/// </para>
/// <para>
/// The typed properties read and write the underlying dictionary using the
/// constants from <see cref="WellKnownJwkValues"/>. Callers can set parameters
/// through either the property form <c>jwk.Kty = "EC"</c> or the indexer form
/// <c>jwk[WellKnownJwkValues.Kty] = "EC"</c>; both end up as the same dictionary
/// entry. Parameters that do not yet have typed properties — extension parameters,
/// draft-stage additions, application-defined members — live alongside the typed
/// ones as ordinary dictionary entries.
/// </para>
/// <para>
/// Equality is based on dictionary contents: two JWKs are equal if they contain
/// the same key-value pairs.
/// </para>
/// </remarks>
[DebuggerDisplay("JsonWebKey({Count} entries)")]
public class JsonWebKey: Dictionary<string, object>, IEquatable<JsonWebKey>
{
    /// <summary>
    /// Creates an empty JSON Web Key.
    /// </summary>
    public JsonWebKey() : base() { }


    /// <summary>
    /// Creates a JSON Web Key with the specified initial capacity.
    /// </summary>
    /// <param name="capacity">The initial number of entries the key can contain.</param>
    public JsonWebKey(int capacity) : base(capacity) { }


    /// <summary>
    /// Creates a JSON Web Key populated from any key-value enumerable,
    /// including <see cref="Dictionary{TKey,TValue}"/>,
    /// <see cref="IReadOnlyDictionary{TKey,TValue}"/>, and
    /// <see cref="IDictionary{TKey,TValue}"/>.
    /// </summary>
    /// <param name="parameters">The key-value pairs to copy.</param>
    public JsonWebKey(IEnumerable<KeyValuePair<string, object>> parameters) : base(parameters) { }


    /// <summary>The key type (<c>kty</c>) per RFC 7517 §4.1, e.g. <c>EC</c>, <c>RSA</c>, <c>OKP</c>, <c>AKP</c>.</summary>
    public string? Kty
    {
        get => TryGetValue(WellKnownJwkValues.Kty, out object? value) ? value as string : null;
        set => SetOrRemove(WellKnownJwkValues.Kty, value);
    }


    /// <summary>The intended algorithm (<c>alg</c>) per RFC 7517 §4.4. <see langword="null"/> when unrestricted.</summary>
    public string? Alg
    {
        get => TryGetValue(WellKnownJwkValues.Alg, out object? value) ? value as string : null;
        set => SetOrRemove(WellKnownJwkValues.Alg, value);
    }


    /// <summary>The intended use (<c>use</c>) per RFC 7517 §4.2. <c>sig</c> or <c>enc</c>.</summary>
    public string? Use
    {
        get => TryGetValue(WellKnownJwkValues.Use, out object? value) ? value as string : null;
        set => SetOrRemove(WellKnownJwkValues.Use, value);
    }


    /// <summary>The key identifier (<c>kid</c>) per RFC 7517 §4.5.</summary>
    public string? Kid
    {
        get => TryGetValue(WellKnownJwkValues.Kid, out object? value) ? value as string : null;
        set => SetOrRemove(WellKnownJwkValues.Kid, value);
    }


    /// <summary>The elliptic curve (<c>crv</c>) per RFC 7518 §6.2.1.1, e.g. <c>P-256</c>.</summary>
    public string? Crv
    {
        get => TryGetValue(WellKnownJwkValues.Crv, out object? value) ? value as string : null;
        set => SetOrRemove(WellKnownJwkValues.Crv, value);
    }


    /// <summary>The X coordinate of an EC public key (<c>x</c>), Base64url-encoded per RFC 7518 §6.2.1.2.</summary>
    public string? X
    {
        get => TryGetValue(WellKnownJwkValues.X, out object? value) ? value as string : null;
        set => SetOrRemove(WellKnownJwkValues.X, value);
    }


    /// <summary>The Y coordinate of an EC public key (<c>y</c>), Base64url-encoded per RFC 7518 §6.2.1.3.</summary>
    public string? Y
    {
        get => TryGetValue(WellKnownJwkValues.Y, out object? value) ? value as string : null;
        set => SetOrRemove(WellKnownJwkValues.Y, value);
    }


    /// <summary>The RSA modulus (<c>n</c>), Base64url-encoded per RFC 7518 §6.3.1.1.</summary>
    public string? N
    {
        get => TryGetValue(WellKnownJwkValues.N, out object? value) ? value as string : null;
        set => SetOrRemove(WellKnownJwkValues.N, value);
    }


    /// <summary>The RSA public exponent (<c>e</c>), Base64url-encoded per RFC 7518 §6.3.1.2.</summary>
    public string? E
    {
        get => TryGetValue(WellKnownJwkValues.E, out object? value) ? value as string : null;
        set => SetOrRemove(WellKnownJwkValues.E, value);
    }


    /// <summary>
    /// Raw public-key bytes (<c>pub</c>), Base64url-encoded, for post-quantum JWK
    /// representations such as <c>kty=AKP</c> keys (ML-DSA family).
    /// </summary>
    public string? Pub
    {
        get => TryGetValue(WellKnownJwkValues.Pub, out object? value) ? value as string : null;
        set => SetOrRemove(WellKnownJwkValues.Pub, value);
    }


    private void SetOrRemove(string key, string? value)
    {
        if(value is null)
        {
            Remove(key);
            return;
        }

        this[key] = value;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(JsonWebKey? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return DictionaryEquality.DictionariesEqual(this, other);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is JsonWebKey other && Equals(other);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return DictionaryEquality.GetDictionaryHashCode(this);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(JsonWebKey? left, JsonWebKey? right)
    {
        return left is null ? right is null : left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(JsonWebKey? left, JsonWebKey? right)
    {
        return !(left == right);
    }
}
