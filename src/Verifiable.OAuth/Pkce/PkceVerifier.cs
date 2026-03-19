using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Pkce;

/// <summary>
/// A PKCE code verifier as defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.1">RFC 7636 §4.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// The verifier is a cryptographically random octet sequence with a minimum length of
/// 43 characters and a maximum length of 128 characters when Base64url-encoded without
/// padding. Only the Base64url-encoded form is ever transmitted; the raw bytes are held
/// only in memory.
/// </para>
/// <para>
/// The verifier must never leave the initiating party. Only the derived
/// <see cref="PkceChallenge"/> is transmitted to the authorization server.
/// Dispose this instance when the flow completes or is abandoned.
/// </para>
/// </remarks>
[DebuggerDisplay("PkceVerifier Length={EncodedLength}")]
public sealed class PkceVerifier: IDisposable, IEquatable<PkceVerifier>
{
    private bool disposed;
    private readonly IMemoryOwner<byte> owner;

    /// <summary>
    /// The raw verifier bytes. Valid only while this instance has not been disposed.
    /// </summary>
    public ReadOnlyMemory<byte> Bytes => owner.Memory;

    /// <summary>
    /// The length of the Base64url-encoded verifier without padding.
    /// Must be between 43 and 128 inclusive per RFC 7636 §4.1.
    /// </summary>
    public int EncodedLength { get; }

    /// <summary>
    /// The Base64url-encoded verifier string without padding, ready for inclusion
    /// in the token endpoint request as <c>code_verifier</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.5">RFC 7636 §4.5</see>.
    /// </summary>
    public string EncodedValue =>
        System.Convert.ToBase64String(Bytes.Span)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');


    /// <summary>
    /// Initializes a <see cref="PkceVerifier"/> from owned memory.
    /// </summary>
    /// <param name="owner">
    /// The memory owner holding the raw verifier bytes. Ownership transfers to this instance.
    /// </param>
    /// <param name="encodedLength">
    /// The length of the Base64url-encoded verifier without padding.
    /// Must be between 43 and 128 inclusive.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="encodedLength"/> is outside the range [43, 128].
    /// </exception>
    public PkceVerifier(IMemoryOwner<byte> owner, int encodedLength)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentOutOfRangeException.ThrowIfLessThan(encodedLength, 43);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(encodedLength, 128);

        this.owner = owner;
        EncodedLength = encodedLength;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            owner.Dispose();
            disposed = true;
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(PkceVerifier? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return EncodedLength == other.EncodedLength
            && Bytes.Span.SequenceEqual(other.Bytes.Span);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is PkceVerifier other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Bytes.Span);
        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(PkceVerifier? left, PkceVerifier? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(PkceVerifier? left, PkceVerifier? right) =>
        !(left == right);
}