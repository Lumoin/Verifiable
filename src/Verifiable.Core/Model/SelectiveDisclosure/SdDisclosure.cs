using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.SelectiveDisclosure;

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
public sealed class SdDisclosure : IEquatable<SdDisclosure>, IDisposable
{
    private bool disposed;


    /// <summary>
    /// The salt value used to prevent guessing of undisclosed claim values.
    /// </summary>
    /// <remarks>
    /// Per RFC 9901 Section 4.2.2, the salt is at least 128 bits of cryptographically
    /// secure random data. The salt is owned by this disclosure; reading
    /// <see cref="Lumoin.Base.SensitiveMemory.AsReadOnlySpan"/> on it is safe until disposal.
    /// </remarks>
    public Salt Salt { get; }

    /// <summary>
    /// The salt as the wire wrote it: the JSON string of an SD-JWT disclosure read from its wire form, which RFC 9901 section
    /// 4.2.1 requires to be a string and nothing more, kept exactly so the disclosure serializes as it was read; or
    /// <see langword="null"/> for a disclosure created from salt bytes, whose serialization encodes them.
    /// </summary>
    public string? EncodedSalt { get; }

    /// <summary>
    /// The claim name for object property disclosures, which may be the empty string (RFC 9901 section 4.2.1 requires a string
    /// and reserves only <c>_sd</c> and <c>...</c>), or <c>null</c> for array element disclosures.
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
    /// <param name="claimName">The claim name, the empty string among the names RFC 9901 section 4.2.1 permits.</param>
    /// <param name="claimValue">The claim value.</param>
    /// <returns>A new object property disclosure that owns <paramref name="salt"/>.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="salt"/> or <paramref name="claimName"/> is <see langword="null"/>; the salt is disposed before
    /// the exception of a null claim name propagates.
    /// </exception>
    public static SdDisclosure CreateProperty(Salt salt, string claimName, object? claimValue)
    {
        ArgumentNullException.ThrowIfNull(salt);

        try
        {
            ArgumentNullException.ThrowIfNull(claimName);

            return new SdDisclosure(salt, null, claimName, claimValue);
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

        return new SdDisclosure(salt, null, null, claimValue);
    }


    /// <summary>
    /// The object property disclosure an SD-JWT disclosure read from its wire form states: its salt's bytes are copied into a
    /// salt rented from <paramref name="pool"/>, which the disclosure owns, and the salt's wire string is kept as
    /// <see cref="EncodedSalt"/>.
    /// </summary>
    /// <param name="saltBytes">The salt's bytes, the identity the disclosure is compared and committed to by.</param>
    /// <param name="encodedSalt">The salt as the wire wrote it.</param>
    /// <param name="saltTag">The tag stamped on the salt, recording that its bytes came from a wire reading.</param>
    /// <param name="pool">The pool the salt is rented from.</param>
    /// <param name="claimName">The claim name, the empty string among the names RFC 9901 section 4.2.1 permits.</param>
    /// <param name="claimValue">The claim value.</param>
    /// <returns>The disclosure, which the caller owns and disposes.</returns>
    public static SdDisclosure ReadProperty(ReadOnlySpan<byte> saltBytes, string encodedSalt, Tag saltTag, BaseMemoryPool pool, string claimName, object? claimValue)
    {
        ArgumentNullException.ThrowIfNull(encodedSalt);
        ArgumentNullException.ThrowIfNull(claimName);

        return new SdDisclosure(ReadSalt(saltBytes, saltTag, pool), encodedSalt, claimName, claimValue);
    }


    /// <summary>
    /// The array element disclosure an SD-JWT disclosure read from its wire form states: its salt's bytes are copied into a
    /// salt rented from <paramref name="pool"/>, which the disclosure owns, and the salt's wire string is kept as
    /// <see cref="EncodedSalt"/>.
    /// </summary>
    /// <param name="saltBytes">The salt's bytes, the identity the disclosure is compared and committed to by.</param>
    /// <param name="encodedSalt">The salt as the wire wrote it.</param>
    /// <param name="saltTag">The tag stamped on the salt, recording that its bytes came from a wire reading.</param>
    /// <param name="pool">The pool the salt is rented from.</param>
    /// <param name="claimValue">The array element value.</param>
    /// <returns>The disclosure, which the caller owns and disposes.</returns>
    public static SdDisclosure ReadArrayElement(ReadOnlySpan<byte> saltBytes, string encodedSalt, Tag saltTag, BaseMemoryPool pool, object? claimValue)
    {
        ArgumentNullException.ThrowIfNull(encodedSalt);

        return new SdDisclosure(ReadSalt(saltBytes, saltTag, pool), encodedSalt, null, claimValue);
    }


    /// <summary>
    /// A salt holding a copy of the bytes given, rented from <paramref name="pool"/>; an empty salt, which a wire string names
    /// when it is empty, holds the shared empty buffer, since the pool rents no buffer of length zero.
    /// </summary>
    /// <param name="saltBytes">The salt's bytes.</param>
    /// <param name="saltTag">The tag stamped on the salt.</param>
    /// <param name="pool">The pool the salt is rented from.</param>
    /// <returns>The salt, which the caller owns.</returns>
    private static Salt ReadSalt(ReadOnlySpan<byte> saltBytes, Tag saltTag, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(saltTag);
        ArgumentNullException.ThrowIfNull(pool);

        if(saltBytes.IsEmpty)
        {
            return new Salt(EmptyMemoryOwner.Instance, saltTag, null);
        }

        var owner = pool.Rent(saltBytes.Length);
        saltBytes.CopyTo(owner.Memory.Span);

        return new Salt(owner, saltTag, null);
    }


    /// <summary>Creates a disclosure owning <paramref name="salt"/>.</summary>
    /// <param name="salt">The salt, owned by the disclosure from here on.</param>
    /// <param name="encodedSalt">The salt as the wire wrote it, or <see langword="null"/> for a disclosure created from salt bytes.</param>
    /// <param name="claimName">The claim name, or <see langword="null"/> for an array element.</param>
    /// <param name="claimValue">The claim value.</param>
    private SdDisclosure(Salt salt, string? encodedSalt, string? claimName, object? claimValue)
    {
        Salt = salt;
        EncodedSalt = encodedSalt;
        ClaimName = claimName;
        ClaimValue = claimValue;
    }


    /// <summary>
    /// Creates a copy of this disclosure with a fresh salt instance containing the
    /// same bytes and the same <see cref="EncodedSalt"/>. The source disclosure remains valid and independently disposable.
    /// </summary>
    /// <param name="pool">The memory pool to allocate the copy's salt buffer from.</param>
    /// <returns>A new disclosure owning a freshly-allocated salt.</returns>
    /// <exception cref="ObjectDisposedException">
    /// Thrown when this disclosure has been disposed.
    /// </exception>
    public SdDisclosure CopyWithFreshSalt(BaseMemoryPool pool)
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
            //The copy keeps the salt's wire string with its bytes, so it serializes as the source does.
            Salt copy = new(owner, Salt.Tag, lifetime: null);

            return new SdDisclosure(copy, EncodedSalt, ClaimName, ClaimValue);
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
