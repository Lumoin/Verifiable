using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Fido2;

/// <summary>
/// A CTAP2 <c>authenticatorBioEnrollment</c> fingerprint template identifier — the opaque byte string an
/// authenticator mints to identify one enrolled fingerprint template.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, <c>templateId</c> (subCommandParams
/// member <c>0x01</c>, response member <c>0x04</c>): "Template Identifier." Minted by <c>enrollBegin</c>
/// (§6.7.4 step 8, "The authenticator generates templateId for new enrollment") and addressed by every
/// later gated subcommand (<c>enrollCaptureNextSample</c>/<c>setFriendlyName</c>/<c>removeEnrollment</c>)
/// via that same value.
/// </para>
/// <para>
/// <strong>Handling.</strong> Like <see cref="CredentialId"/>, this type extends <see cref="SensitiveMemory"/>
/// not because a template identifier is secret — it travels openly on the wire in every enrollment
/// response — but because carrying it as a named type prevents it from being confused at a call site with
/// a <see cref="CredentialId"/> or any other opaque byte value, and gives it the same disciplined pooled
/// ownership and deterministic disposal every other carrier in this codebase has, satisfying the
/// no-naked-bytes convention <see cref="Ctap.Authenticator.Automata.CtapBioEnrollmentTemplateRecord"/>'s
/// own disposal joins.
/// </para>
/// <para>
/// <strong>Equality.</strong> A template identifier is public, so <see cref="Equals(BioEnrollmentTemplateId?)"/>
/// compares bytes directly with <see cref="ReadOnlySpan{T}.SequenceEqual(ReadOnlySpan{T})"/> rather than
/// the constant-time comparison a secret would require — there is no timing side channel to protect
/// against when comparing two values neither side keeps secret.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class BioEnrollmentTemplateId: SensitiveMemory, IEquatable<BioEnrollmentTemplateId>
{
    /// <summary>
    /// Gets the length of the template identifier in bytes.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Initializes a new <see cref="BioEnrollmentTemplateId"/> from owned memory.
    /// </summary>
    /// <param name="sensitiveMemory">The owned memory. Ownership transfers to this instance.</param>
    /// <param name="tag">Metadata including purpose, encoding, and CBOM provenance entries.</param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this value's lifetime. Started by the backend; stopped on
    /// <see cref="SensitiveMemory.Dispose()"/>. Pass <see langword="null"/> when no OTel listener is
    /// active.
    /// </param>
    public BioEnrollmentTemplateId(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null): base(sensitiveMemory, tag, lifetime)
    {
    }


    /// <summary>
    /// Creates a <see cref="BioEnrollmentTemplateId"/> by copying <paramref name="value"/> into memory
    /// rented from <paramref name="pool"/>.
    /// </summary>
    /// <param name="value">The template identifier bytes to copy.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>A new <see cref="BioEnrollmentTemplateId"/> containing a copy of <paramref name="value"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static BioEnrollmentTemplateId Create(ReadOnlySpan<byte> value, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(value.Length);
        try
        {
            value.CopyTo(owner.Memory.Span);

            return new BioEnrollmentTemplateId(owner, Fido2Tags.BioEnrollmentTemplateId);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] BioEnrollmentTemplateId? other)
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
            BioEnrollmentTemplateId t => Equals(t),
            SensitiveMemory sm => base.Equals(sm),
            _ => false
        };
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();


    /// <summary>
    /// Determines whether two <see cref="BioEnrollmentTemplateId"/> instances contain identical bytes.
    /// </summary>
    public static bool operator ==(BioEnrollmentTemplateId? left, BioEnrollmentTemplateId? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Determines whether two <see cref="BioEnrollmentTemplateId"/> instances differ.
    /// </summary>
    public static bool operator !=(BioEnrollmentTemplateId? left, BioEnrollmentTemplateId? right) => !(left == right);


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

            return $"BioEnrollmentTemplateId({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}
