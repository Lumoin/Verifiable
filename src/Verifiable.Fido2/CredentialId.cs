using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Fido2;

/// <summary>
/// A WebAuthn credential identifier — the opaque byte string an authenticator mints to identify a
/// public key credential.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#credential-id">W3C Web Authentication Level 3,
/// section 4: Terminology, "Credential ID"</see>: "A probabilistically-unique byte sequence
/// identifying a public key credential source and its authentication assertions." Per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">section 7.1:
/// Registering a New Credential</see>, step 25, a credential ID is at most 1023 bytes.
/// </para>
/// <para>
/// <strong>Handling.</strong> Like <see cref="DigestValue"/> and <see cref="MacValue"/>, this type
/// extends <see cref="SensitiveMemory"/> not because a credential ID is secret — it is sent openly
/// on the wire in every registration and authentication ceremony — but because carrying it as a
/// named type (rather than a naked <see cref="ReadOnlyMemory{T}"/>) prevents it from being confused
/// at a call site with an <c>rpIdHash</c>, a raw signature, or any other opaque byte value the
/// WebAuthn wire format carries. Pooled ownership and deterministic disposal give it the same
/// disciplined-lifetime handling as every other carrier in this codebase.
/// </para>
/// <para>
/// <strong>Equality.</strong> A credential ID is public, so <see cref="Equals(CredentialId?)"/>
/// compares bytes directly with <see cref="ReadOnlySpan{T}.SequenceEqual(ReadOnlySpan{T})"/> rather
/// than the constant-time comparison a secret or a MAC verification would require — there is no
/// timing side channel to protect against when comparing two values neither side keeps secret.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CredentialId: SensitiveMemory, IEquatable<CredentialId>
{
    /// <summary>
    /// The maximum length of a credential identifier in bytes.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
    /// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 25 bounds a
    /// credential ID to at most 1023 bytes.
    /// </remarks>
    public const int MaxLength = 1023;

    /// <summary>
    /// Gets the length of the credential identifier in bytes.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Initializes a new <see cref="CredentialId"/> from owned memory.
    /// </summary>
    /// <param name="sensitiveMemory">The owned memory. Ownership transfers to this instance.</param>
    /// <param name="tag">Metadata including purpose, encoding, and CBOM provenance entries.</param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this value's lifetime. Started by the backend; stopped on
    /// <see cref="SensitiveMemory.Dispose()"/>. Pass <see langword="null"/> when no OTel listener is
    /// active.
    /// </param>
    public CredentialId(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null): base(sensitiveMemory, tag, lifetime)
    {
    }


    /// <summary>
    /// Creates a <see cref="CredentialId"/> by copying <paramref name="value"/> into memory rented
    /// from <paramref name="pool"/>.
    /// </summary>
    /// <param name="value">The credential identifier bytes to copy.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>A new <see cref="CredentialId"/> containing a copy of <paramref name="value"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// A zero-length <paramref name="value"/> is not routed through <paramref name="pool"/>: the
    /// pooled backends this codebase registers reject a zero-byte rent, but
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">section 7.1</see>,
    /// step 25's 1-1023 byte bound is a validation concern for
    /// <see cref="Fido2RegistrationChecks.CheckRegistrationCredentialIdLength"/> to reject, not an
    /// allocator concern — a wire-level empty credential ID must construct so the rule can fail it
    /// closed.
    /// </remarks>
    public static CredentialId Create(ReadOnlySpan<byte> value, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(value.Length == 0)
        {
            return new CredentialId(EmptyMemoryOwner, Fido2Tags.CredentialId);
        }

        IMemoryOwner<byte> owner = pool.Rent(value.Length);
        try
        {
            value.CopyTo(owner.Memory.Span);

            return new CredentialId(owner, Fido2Tags.CredentialId);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// A shared, always-empty memory owner for the zero-length case <see cref="Create"/> special-cases.
    /// Safe to share across every empty <see cref="CredentialId"/>: it holds no rented buffer and its
    /// <see cref="IDisposable.Dispose"/> is a no-op, so repeated disposal across independently
    /// disposed <see cref="CredentialId"/> instances is harmless.
    /// </summary>
    private static IMemoryOwner<byte> EmptyMemoryOwner { get; } = new ZeroLengthMemoryOwner();


    /// <summary>
    /// An <see cref="IMemoryOwner{T}"/> over an always-empty <see cref="Memory{T}"/>, backing
    /// <see cref="CredentialId.EmptyMemoryOwner"/>.
    /// </summary>
    private sealed class ZeroLengthMemoryOwner: IMemoryOwner<byte>
    {
        /// <inheritdoc/>
        public Memory<byte> Memory => Memory<byte>.Empty;


        /// <summary>
        /// No-op: there is no rented buffer to release.
        /// </summary>
        public void Dispose()
        {
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] CredentialId? other)
    {
        return other is not null
            && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj switch
        {
            CredentialId c => Equals(c),
            SensitiveMemory sm => base.Equals(sm),
            _ => false
        };
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();


    /// <summary>
    /// Determines whether two <see cref="CredentialId"/> instances contain identical bytes.
    /// </summary>
    public static bool operator ==(CredentialId? left, CredentialId? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Determines whether two <see cref="CredentialId"/> instances differ.
    /// </summary>
    public static bool operator !=(CredentialId? left, CredentialId? right) => !(left == right);


    /// <inheritdoc/>
    public override string ToString() => DebuggerDisplay;


    private string DebuggerDisplay
    {
        get
        {
            ReadOnlySpan<byte> span = MemoryOwner.Memory.Span;
            int previewLength = Math.Min(span.Length, 8);
            string hexPreview = Convert.ToHexStringLower(span[..previewLength]);
            string ellipsis = span.Length > 8 ? "..." : string.Empty;

            return $"CredentialId({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}
