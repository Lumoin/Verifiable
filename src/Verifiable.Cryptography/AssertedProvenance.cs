using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

/// <summary>
/// A verification provenance that names an identity without any check tying that identity to the verified
/// value — the honest shape for a genuine bring-your-own-key path, where nothing in scope resolves the
/// claimed identity against anything else.
/// </summary>
/// <remarks>
/// <para>
/// An asserted identity is a label, not a proof of principal: <see cref="Verified{T}.IsIdentityBound"/> is
/// <see langword="false"/> for every instance minted with an <see cref="AssertedProvenance"/>, and a compile-time
/// authorization seam that requires <see cref="BoundProvenance"/> refuses one outright. Freely constructible —
/// asserting a label requires no check — unlike <see cref="BoundProvenance"/>, whose constructor no type outside
/// this one can reach.
/// </para>
/// <para>
/// <strong>Value equality over <see cref="VerificationProvenance.Identity"/>.</strong> A label IS its
/// value, so two <see cref="AssertedProvenance"/> instances naming the same identity (or both naming none) are
/// equal regardless of which mint produced them — restoring the equality <see cref="Verified{T}"/> held before
/// it grew a <see cref="Verified{T}.Provenance"/> property: two <see cref="Verified{T}"/> over the same value
/// and label compare equal again. Contrast <see cref="BoundProvenance"/>, which keeps reference identity — a
/// bound provenance is a capability token tied to the one instance a typed gate actually witnessed, not a label,
/// so two independently-established bindings for the same identity are correctly NOT equal.
/// </para>
/// </remarks>
public sealed class AssertedProvenance: VerificationProvenance, IEquatable<AssertedProvenance>
{
    private AssertedProvenance(KeyId? identity): base(identity)
    {
    }


    /// <summary>Creates an asserted provenance naming <paramref name="identity"/>, or naming none.</summary>
    /// <param name="identity">The identity to record, or <see langword="null"/> when none is known.</param>
    public static AssertedProvenance Of(KeyId? identity)
    {
        return new AssertedProvenance(identity);
    }

    /// <summary>
    /// Creates an asserted provenance from a raw label, recording it as a <see cref="KeyId"/> iff it is
    /// non-<see langword="null"/> and non-whitespace.
    /// </summary>
    /// <param name="verificationMethod">The verification method / key id label, or <see langword="null"/>.</param>
    public static AssertedProvenance OfLabel(string? verificationMethod)
    {
        if(string.IsNullOrWhiteSpace(verificationMethod))
        {
            return new AssertedProvenance(null);
        }

        return new AssertedProvenance(new KeyId(verificationMethod));
    }


    /// <inheritdoc/>
    public bool Equals(AssertedProvenance? other)
    {
        if(other is null)
        {
            return false;
        }

        return Nullable.Equals(Identity, other.Identity);
    }

    /// <inheritdoc/>
    public override bool Equals([NotNullWhen(true)] object? obj) => Equals(obj as AssertedProvenance);

    /// <inheritdoc/>
    public override int GetHashCode() => Identity?.GetHashCode() ?? 0;

    /// <inheritdoc/>
    public static bool operator ==(AssertedProvenance? left, AssertedProvenance? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <inheritdoc/>
    public static bool operator !=(AssertedProvenance? left, AssertedProvenance? right) => !(left == right);
}
