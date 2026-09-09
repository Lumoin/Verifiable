using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

/// <summary>
/// The relationship a bound verification method was resolved under — the DID document verification
/// relationship (<c>authentication</c>, <c>assertionMethod</c>) a <see cref="BoundProvenance"/> was scoped
/// to, or the AdES signing-certificate role for a certificate-digest binding.
/// </summary>
/// <remarks>
/// Unlike the "dynamic enum" pattern used elsewhere in the cryptography layer (see
/// <see cref="Context.Purpose"/>), which is extensible at application startup because the extensibility is
/// reachable through a real production path, this is a CLOSED value set: a custom code could never reach
/// a <see cref="BoundProvenance"/> — the constructor is private and every producer hardcodes its own
/// relationship (or <see langword="null"/>).
/// </remarks>
[DebuggerDisplay("{VerificationRelationshipNames.GetName(this),nq}")]
public readonly struct VerificationRelationship: IEquatable<VerificationRelationship>
{
    /// <summary>Gets the numeric code for this verification relationship.</summary>
    public int Code { get; }

    private VerificationRelationship(int code)
    {
        Code = code;
    }


    /// <summary>The <c>authentication</c> verification relationship of the DID Core data model.</summary>
    public static VerificationRelationship Authentication { get; } = new(0);

    /// <summary>The <c>assertionMethod</c> verification relationship of the DID Core data model.</summary>
    public static VerificationRelationship AssertionMethod { get; } = new(1);

    /// <summary>The signing-certificate role of an AdES signature's identified signer certificate.</summary>
    public static VerificationRelationship SignerCertificate { get; } = new(2);


    private static IReadOnlyList<VerificationRelationship> RegisteredRelationships { get; } = [Authentication, AssertionMethod, SignerCertificate];

    /// <summary>Gets all verification relationship values — a closed set; see the type remarks.</summary>
    public static IReadOnlyList<VerificationRelationship> Relationships => RegisteredRelationships;


    /// <inheritdoc/>
    public override string ToString() => VerificationRelationshipNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(VerificationRelationship other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is VerificationRelationship other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(VerificationRelationship left, VerificationRelationship right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(VerificationRelationship left, VerificationRelationship right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="VerificationRelationship"/> values.</summary>
public static class VerificationRelationshipNames
{
    /// <summary>Gets the name for the specified verification relationship.</summary>
    public static string GetName(VerificationRelationship relationship) => GetName(relationship.Code);

    /// <summary>Gets the name for the specified verification relationship code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == VerificationRelationship.Authentication.Code => nameof(VerificationRelationship.Authentication),
        var c when c == VerificationRelationship.AssertionMethod.Code => nameof(VerificationRelationship.AssertionMethod),
        var c when c == VerificationRelationship.SignerCertificate.Code => nameof(VerificationRelationship.SignerCertificate),
        _ => $"Custom ({code})"
    };
}
