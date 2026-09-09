using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

/// <summary>
/// Identifies which typed gate produced a <see cref="BoundProvenance"/>.
/// </summary>
/// <remarks>
/// Unlike the "dynamic enum" pattern used elsewhere in the cryptography layer (see
/// <see cref="Context.Purpose"/>), which is extensible at application startup because the extensibility is
/// reachable through a real production path, this is a CLOSED value set: every value names exactly one
/// <see cref="BoundProvenance"/> producer declared on that sealed type, and a custom code could never reach a
/// <see cref="BoundProvenance"/> — the constructor is private and every producer hardcodes its own source. The
/// source a caller reads back states which residual trust bar that binding rests on —
/// <see cref="CertificateDigest"/>'s in-body recompute-and-compare, <see cref="MethodResolved"/>'s and
/// <see cref="CallerControllerArtifact"/>'s trust in the caller's own prior resolution, or
/// <see cref="KeyAgreement"/>'s trust in a decryption that already failed for a wrong sender identity.
/// </remarks>
[DebuggerDisplay("{ResolutionSourceNames.GetName(this),nq}")]
public readonly struct ResolutionSource: IEquatable<ResolutionSource>
{
    /// <summary>Gets the numeric code for this resolution source.</summary>
    public int Code { get; }

    private ResolutionSource(int code)
    {
        Code = code;
    }


    /// <summary>
    /// Bound by <see cref="BoundProvenance.TryBindByCertificateDigestAsync"/>: the identified signing
    /// certificate's own digest, recomputed and compared against the signature's signed reference.
    /// </summary>
    public static ResolutionSource CertificateDigest { get; } = new(0);

    /// <summary>
    /// Bound by <see cref="BoundProvenance.TryBindByResolvedMethod"/>: the caller's own already-resolved
    /// and already-authorized verification method, witnessed for consistency against the claimed identity.
    /// </summary>
    public static ResolutionSource MethodResolved { get; } = new(1);

    /// <summary>
    /// Bound by <see cref="BoundProvenance.TryBindByControllerArtifact"/>: a resolved verification method
    /// whose controller and relationship the caller checked against a claimed controller artifact.
    /// </summary>
    public static ResolutionSource CallerControllerArtifact { get; } = new(2);

    /// <summary>
    /// Bound by <see cref="BoundProvenance.TryBindByKeyAgreement"/>: an authenticated-encryption sender
    /// identity whose correctness a successful key-agreement decryption already established.
    /// </summary>
    public static ResolutionSource KeyAgreement { get; } = new(3);

    /// <summary>
    /// Bound by <see cref="BoundProvenance.TryBindByKeriAnchor"/>: a KERI issuer AID a key event log replay
    /// independently established for the verified event that anchored the value under verification.
    /// </summary>
    public static ResolutionSource KeriAnchor { get; } = new(4);


    private static IReadOnlyList<ResolutionSource> RegisteredSources { get; } = [CertificateDigest, MethodResolved, CallerControllerArtifact, KeyAgreement, KeriAnchor];

    /// <summary>Gets all resolution source values — a closed set; see the type remarks.</summary>
    public static IReadOnlyList<ResolutionSource> Sources => RegisteredSources;


    /// <inheritdoc/>
    public override string ToString() => ResolutionSourceNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(ResolutionSource other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is ResolutionSource other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(ResolutionSource left, ResolutionSource right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(ResolutionSource left, ResolutionSource right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="ResolutionSource"/> values.</summary>
public static class ResolutionSourceNames
{
    /// <summary>Gets the name for the specified resolution source.</summary>
    public static string GetName(ResolutionSource source) => GetName(source.Code);

    /// <summary>Gets the name for the specified resolution source code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == ResolutionSource.CertificateDigest.Code => nameof(ResolutionSource.CertificateDigest),
        var c when c == ResolutionSource.MethodResolved.Code => nameof(ResolutionSource.MethodResolved),
        var c when c == ResolutionSource.CallerControllerArtifact.Code => nameof(ResolutionSource.CallerControllerArtifact),
        var c when c == ResolutionSource.KeyAgreement.Code => nameof(ResolutionSource.KeyAgreement),
        var c when c == ResolutionSource.KeriAnchor.Code => nameof(ResolutionSource.KeriAnchor),
        _ => $"Custom ({code})"
    };
}
