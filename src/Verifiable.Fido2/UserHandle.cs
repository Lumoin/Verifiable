using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Fido2;

/// <summary>
/// A WebAuthn user handle — the opaque byte string a relying party assigns to a user account and
/// an authenticator may return on an assertion to identify the account the credential belongs to.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params">W3C Web
/// Authentication Level 3, section 5.4.3: User Account Parameters for Credential Generation
/// (dictionary <c>PublicKeyCredentialUserEntity</c>)</see>, member <c>id</c>: "a user handle is an
/// opaque byte sequence with a maximum size of 64 bytes, and is not meant to be displayed to the
/// user. ... The user handle MUST NOT be empty" — together bounding a user handle to 1-64 bytes.
/// </para>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">section 7.2: Verifying an
/// Authentication Assertion</see>, step 6, uses a returned <c>response.userHandle</c> to identify
/// the credential's owning user account: when the relying party had already identified the user
/// before the ceremony (e.g. via a username), a present <c>userHandle</c> must equal that user
/// account's handle; when the relying party had not identified the user beforehand — the
/// discoverable-credential path — <c>userHandle</c> is REQUIRED and is itself used to look the
/// account up.
/// </para>
/// <para>
/// <strong>Handling.</strong> Like <see cref="CredentialId"/>, this type extends
/// <see cref="SensitiveMemory"/> not because a user handle is secret — a relying party may return
/// it to the client on every assertion, and WebAuthn L3 explicitly forbids embedding personally
/// identifying information in it (<see href="https://www.w3.org/TR/webauthn-3/#sctn-user-handle-privacy">
/// section 14.6.1: User Handle Contents</see>) — but because carrying it as a named type prevents it
/// from being confused at a call site with a <see cref="CredentialId"/>, an <c>rpIdHash</c>, or any
/// other opaque WebAuthn byte value. Pooled ownership and deterministic disposal give it the same
/// disciplined-lifetime handling as every other carrier in this codebase.
/// </para>
/// <para>
/// <strong>Equality.</strong> A user handle is not itself a secret, so
/// <see cref="Equals(UserHandle?)"/> compares bytes directly with
/// <see cref="ReadOnlySpan{T}.SequenceEqual(ReadOnlySpan{T})"/> rather than the constant-time
/// comparison a secret or a MAC verification would require — there is no timing side channel to
/// protect against when comparing two values neither side keeps secret.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class UserHandle: SensitiveMemory, IEquatable<UserHandle>
{
    /// <summary>
    /// The maximum length of a user handle in bytes.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params">W3C Web
    /// Authentication Level 3, section 5.4.3: User Account Parameters for Credential Generation
    /// (dictionary <c>PublicKeyCredentialUserEntity</c>)</see>, member <c>id</c>: "a user handle is
    /// an opaque byte sequence with a maximum size of 64 bytes ... The user handle MUST NOT be
    /// empty" — together with that MUST NOT, this bounds a user handle to 1-64 bytes.
    /// </remarks>
    public const int MaxLength = 64;

    /// <summary>
    /// Gets the length of the user handle in bytes.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Initializes a new <see cref="UserHandle"/> from owned memory.
    /// </summary>
    /// <param name="sensitiveMemory">The owned memory. Ownership transfers to this instance.</param>
    /// <param name="tag">Metadata including purpose, encoding, and CBOM provenance entries.</param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this value's lifetime. Started by the backend; stopped on
    /// <see cref="SensitiveMemory.Dispose()"/>. Pass <see langword="null"/> when no OTel listener is
    /// active.
    /// </param>
    public UserHandle(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null): base(sensitiveMemory, tag, lifetime)
    {
    }


    /// <summary>
    /// Creates a <see cref="UserHandle"/> by copying <paramref name="value"/> into memory rented
    /// from <paramref name="pool"/>.
    /// </summary>
    /// <param name="value">The user handle bytes to copy.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>A new <see cref="UserHandle"/> containing a copy of <paramref name="value"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// A zero-length <paramref name="value"/> is not routed through <paramref name="pool"/>: the
    /// pooled backends this codebase registers reject a zero-byte rent, but
    /// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params">section
    /// 5.4.3</see>'s "MUST NOT be empty" bound is a validation concern for
    /// <see cref="Fido2AssertionChecks.CheckAssertionUserHandle"/> to reject, not an allocator
    /// concern — a wire-level empty user handle must construct so the rule can fail it closed.
    /// </remarks>
    public static UserHandle Create(ReadOnlySpan<byte> value, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(value.Length == 0)
        {
            return new UserHandle(EmptyMemoryOwner, Fido2Tags.UserHandle);
        }

        IMemoryOwner<byte> owner = pool.Rent(value.Length);
        try
        {
            value.CopyTo(owner.Memory.Span);

            return new UserHandle(owner, Fido2Tags.UserHandle);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// A shared, always-empty memory owner for the zero-length case <see cref="Create"/> special-cases.
    /// Safe to share across every empty <see cref="UserHandle"/>: it holds no rented buffer and its
    /// <see cref="IDisposable.Dispose"/> is a no-op, so repeated disposal across independently
    /// disposed <see cref="UserHandle"/> instances is harmless.
    /// </summary>
    private static IMemoryOwner<byte> EmptyMemoryOwner { get; } = new ZeroLengthMemoryOwner();


    /// <summary>
    /// An <see cref="IMemoryOwner{T}"/> over an always-empty <see cref="Memory{T}"/>, backing
    /// <see cref="UserHandle.EmptyMemoryOwner"/>.
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
    public bool Equals([NotNullWhen(true)] UserHandle? other)
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
            UserHandle u => Equals(u),
            SensitiveMemory sm => base.Equals(sm),
            _ => false
        };
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();


    /// <summary>
    /// Determines whether two <see cref="UserHandle"/> instances contain identical bytes.
    /// </summary>
    public static bool operator ==(UserHandle? left, UserHandle? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Determines whether two <see cref="UserHandle"/> instances differ.
    /// </summary>
    public static bool operator !=(UserHandle? left, UserHandle? right) => !(left == right);


    /// <inheritdoc/>
    public override string ToString() => DebuggerDisplay;


    /// <summary>
    /// A debugger-friendly preview of the handle's length and leading bytes.
    /// </summary>
    private string DebuggerDisplay
    {
        get
        {
            ReadOnlySpan<byte> span = MemoryOwner.Memory.Span;
            int previewLength = Math.Min(span.Length, 8);
            string hexPreview = Convert.ToHexStringLower(span[..previewLength]);
            string ellipsis = span.Length > 8 ? "..." : string.Empty;

            return $"UserHandle({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}
