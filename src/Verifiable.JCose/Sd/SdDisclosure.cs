using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.JCose.Sd;

/// <summary>
/// A selective disclosure element containing salt, optional claim name, and value.
/// </summary>
/// <remarks>
/// <para>
/// This is a format-agnostic representation used by both SD-JWT (JSON-based, RFC 9901)
/// and SD-CWT (CBOR-based). Serialization to wire format is handled by format-specific
/// serializers in Verifiable.Json and Verifiable.Cbor.
/// </para>
/// <para>
/// <strong>Salt Requirements (RFC 9901 Section 4.2.2):</strong>
/// </para>
/// <list type="bullet">
/// <item><description>Minimum 128 bits of cryptographically secure random data.</description></item>
/// <item><description>Unique per disclosure to prevent correlation attacks.</description></item>
/// </list>
/// <para>
/// <strong>Salt ownership.</strong>
/// The disclosure owns its <see cref="Salt"/>. Factory methods take ownership of the
/// supplied <see cref="Salt"/> instance — callers must not dispose the salt after
/// handing it to a factory. Disposing the disclosure (directly, via
/// <see cref="SdToken{TEnvelope}"/> disposal, or via <see langword="using"/>) disposes
/// the held salt, which clears its underlying memory and stops any associated OTel
/// activity.
/// </para>
/// <para>
/// <strong>Equality.</strong> Two disclosures are equal if they have the same salt
/// bytes. The salt serves as the cryptographic identity of the disclosure.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SdDisclosure: IEquatable<SdDisclosure>, IDisposable
{
    private bool disposed;


    /// <summary>
    /// The salt value used to prevent guessing of undisclosed claim values.
    /// </summary>
    /// <remarks>
    /// Per RFC 9901 Section 4.2.2, the salt is at least 128 bits of cryptographically
    /// secure random data. The salt is owned by this disclosure; reading
    /// <see cref="Cryptography.Salt.AsReadOnlySpan"/> on it is safe until disposal.
    /// </remarks>
    public Salt Salt { get; }

    /// <summary>
    /// The claim name for object property disclosures, or <c>null</c> for array element disclosures.
    /// </summary>
    public string? ClaimName { get; }

    /// <summary>The claim value.</summary>
    public object? ClaimValue { get; }

    /// <summary>Whether this disclosure is for an array element (no claim name).</summary>
    public bool IsArrayElement => ClaimName is null;

    /// <summary>Whether this disclosure is for an object property (has claim name).</summary>
    public bool IsObjectProperty => ClaimName is not null;


    /// <summary>
    /// Creates a disclosure for an object property, taking ownership of the supplied salt.
    /// </summary>
    /// <param name="salt">
    /// The cryptographic salt. Ownership transfers to the new disclosure — the caller
    /// must not dispose the salt after calling this method. Disposing the disclosure
    /// disposes the salt.
    /// </param>
    /// <param name="claimName">The claim name.</param>
    /// <param name="claimValue">The claim value.</param>
    /// <returns>A new object property disclosure that owns <paramref name="salt"/>.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="salt"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="claimName"/> is null or empty. The salt is disposed
    /// before the exception propagates.
    /// </exception>
    public static SdDisclosure CreateProperty(Salt salt, string claimName, object? claimValue)
    {
        ArgumentNullException.ThrowIfNull(salt);

        try
        {
            ArgumentException.ThrowIfNullOrEmpty(claimName);
            return new SdDisclosure(salt, claimName, claimValue);
        }
        catch
        {
            //Dispose the salt on construction failure so the caller does not have to
            //track partial ownership.
            salt.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Creates a disclosure for an array element, taking ownership of the supplied salt.
    /// </summary>
    /// <param name="salt">
    /// The cryptographic salt. Ownership transfers to the new disclosure — the caller
    /// must not dispose the salt after calling this method.
    /// </param>
    /// <param name="claimValue">The array element value.</param>
    /// <returns>A new array element disclosure that owns <paramref name="salt"/>.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="salt"/> is <see langword="null"/>.
    /// </exception>
    public static SdDisclosure CreateArrayElement(Salt salt, object? claimValue)
    {
        ArgumentNullException.ThrowIfNull(salt);

        return new SdDisclosure(salt, null, claimValue);
    }


    private SdDisclosure(Salt salt, string? claimName, object? claimValue)
    {
        Salt = salt;
        ClaimName = claimName;
        ClaimValue = claimValue;
    }


    /// <summary>
    /// Creates a copy of this disclosure with a fresh salt instance containing the
    /// same bytes. The source disclosure remains valid and independently disposable.
    /// </summary>
    /// <param name="pool">The memory pool to allocate the copy's salt buffer from.</param>
    /// <returns>A new disclosure owning a freshly-allocated salt.</returns>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when this disclosure has been disposed.
    /// </exception>
    public SdDisclosure CopyWithFreshSalt(MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ObjectDisposedException.ThrowIf(disposed, this);

        ReadOnlySpan<byte> sourceBytes = Salt.AsReadOnlySpan();
        IMemoryOwner<byte> owner = pool.Rent(sourceBytes.Length);

        try
        {
            sourceBytes.CopyTo(owner.Memory.Span[..sourceBytes.Length]);
            //The copy inherits the source's tag. Applications that want derivation
            //provenance on the copy can use the Salt(IMemoryOwner, Tag, Activity?)
            //constructor directly with a derived tag and call CreateProperty/
            //CreateArrayElement themselves.
            Salt copy = new Salt(owner, Salt.Tag, lifetime: null);

            return ClaimName is null
                ? CreateArrayElement(copy, ClaimValue)
                : CreateProperty(copy, ClaimName, ClaimValue);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        Salt.Dispose();
    }


    private string DebuggerDisplay =>
        ClaimName is not null
            ? $"SdDisclosure: {ClaimName} = {ClaimValue}"
            : $"SdDisclosure: [array] = {ClaimValue}";


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(SdDisclosure? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        //Equality based on salt bytes (cryptographic identity).
        return Salt.AsReadOnlySpan().SequenceEqual(other.Salt.AsReadOnlySpan());
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => obj is SdDisclosure other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Salt.AsReadOnlySpan());

        return hash.ToHashCode();
    }


    /// <summary>Returns a debug string representation.</summary>
    public override string ToString() => DebuggerDisplay;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(SdDisclosure? left, SdDisclosure? right) => left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(SdDisclosure? left, SdDisclosure? right) => !(left == right);
}
