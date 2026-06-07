using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Pkce;

/// <summary>
/// A PKCE S256 code challenge as defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.2">RFC 7636 §4.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// The challenge is the SHA-256 hash of the UTF-8 encoded <see cref="PkceVerifier"/>,
/// Base64url-encoded without padding. It is derived from the verifier and is safe
/// to transmit to the authorization server in the authorization request.
/// </para>
/// <para>
/// Only <see cref="PkceMethod.S256"/> is permitted by
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("PkceChallenge Length={EncodedLength}")]
public sealed class PkceChallenge: IDisposable, IEquatable<PkceChallenge>
{
    private bool disposed;
    private readonly IMemoryOwner<byte> owner;

    /// <summary>
    /// The raw SHA-256 hash bytes of the encoded verifier. Valid only while this instance
    /// has not been disposed.
    /// </summary>
    public ReadOnlyMemory<byte> Bytes => owner.Memory;

    /// <summary>
    /// The length of the Base64url-encoded challenge without padding.
    /// Always 43 characters for SHA-256 output.
    /// </summary>
    public int EncodedLength { get; }

    /// <summary>
    /// The Base64url-encoded challenge string without padding, ready for inclusion
    /// in the authorization request as <c>code_challenge</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.2">RFC 7636 §4.2</see>.
    /// </summary>
    public string EncodedValue =>
        System.Convert.ToBase64String(Bytes.Span)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');


    /// <summary>
    /// Initializes a <see cref="PkceChallenge"/> from owned memory.
    /// </summary>
    /// <param name="owner">
    /// The memory owner holding the raw SHA-256 hash bytes. Ownership transfers to this instance.
    /// </param>
    /// <param name="encodedLength">
    /// The length of the Base64url-encoded challenge without padding. Must be 43 for SHA-256.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="encodedLength"/> is not 43.
    /// </exception>
    public PkceChallenge(IMemoryOwner<byte> owner, int encodedLength)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentOutOfRangeException.ThrowIfNotEqual(encodedLength, 43);

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
    public bool Equals(PkceChallenge? other)
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
        obj is PkceChallenge other && Equals(other);


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
    public static bool operator ==(PkceChallenge? left, PkceChallenge? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(PkceChallenge? left, PkceChallenge? right) =>
        !(left == right);
}