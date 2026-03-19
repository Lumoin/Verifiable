using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Context;

/// <summary>
/// Identifies the source of cryptographically random bytes.
/// </summary>
/// <remarks>
/// <para>
/// Different entropy sources have different security properties, hardware
/// backing, and attestation capabilities. Knowing the source is essential
/// for regulated environments where entropy provenance must be auditable.
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <see cref="Csprng"/> — OS-provided cryptographically strong
///       pseudo-random number generator. Software-based. Always available.
///       Quality depends on OS and platform seeding.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="Tpm"/> — TPM 2.0 <c>TPM2_GetRandom</c> command.
///       Hardware-backed. Subject to TPM health and availability.
///       Provides the strongest attestation guarantees.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="Hsm"/> — Hardware Security Module. Hardware-backed.
///       Availability and attestation depend on the HSM vendor and configuration.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="Deterministic"/> — Fixed test vectors. Must never be
///       used in production. Produces predictable output for test reproducibility.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="Unknown"/> — The entropy source is not known or was not
///       captured. Indicates that provenance cannot be verified for this value.
///       Forensically significant — an auditor seeing this should investigate.
///     </description>
///   </item>
/// </list>
/// </remarks>
[DebuggerDisplay("{EntropySourceNames.GetName(this),nq}")]
public readonly struct EntropySource: IEquatable<EntropySource>
{
    /// <summary>Gets the numeric code for this entropy source.</summary>
    public int Code { get; }

    private EntropySource(int code) { Code = code; }


    /// <summary>OS-provided cryptographically strong pseudo-random number generator.</summary>
    public static EntropySource Csprng { get; } = new(0);

    /// <summary>TPM 2.0 hardware random number generator via <c>TPM2_GetRandom</c>.</summary>
    public static EntropySource Tpm { get; } = new(1);

    /// <summary>Hardware Security Module random number generator.</summary>
    public static EntropySource Hsm { get; } = new(2);

    /// <summary>
    /// Fixed deterministic test vectors. Must never be used outside of tests.
    /// </summary>
    public static EntropySource Deterministic { get; } = new(3);

    /// <summary>
    /// Source not known or not captured. Entropy provenance cannot be verified.
    /// </summary>
    public static EntropySource Unknown { get; } = new(4);


    private static readonly List<EntropySource> sources = [Csprng, Tpm, Hsm, Deterministic, Unknown];

    /// <summary>Gets all registered entropy source values.</summary>
    public static IReadOnlyList<EntropySource> Sources => sources.AsReadOnly();


    /// <summary>
    /// Creates a new entropy source value for custom sources.
    /// Use codes above 1000 to avoid collisions with future library additions.
    /// </summary>
    public static EntropySource Create(int code)
    {
        for(int i = 0; i < sources.Count; ++i)
        {
            if(sources[i].Code == code)
            {
                throw new ArgumentException("Code already exists.");
            }
        }

        var newSource = new EntropySource(code);
        sources.Add(newSource);
        return newSource;
    }


    /// <inheritdoc/>
    public override string ToString() => EntropySourceNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(EntropySource other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is EntropySource other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(EntropySource left, EntropySource right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(EntropySource left, EntropySource right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="EntropySource"/> values.</summary>
public static class EntropySourceNames
{
    /// <summary>Gets the name for the specified entropy source.</summary>
    public static string GetName(EntropySource source) => GetName(source.Code);

    /// <summary>Gets the name for the specified entropy source code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == EntropySource.Csprng.Code => nameof(EntropySource.Csprng),
        var c when c == EntropySource.Tpm.Code => nameof(EntropySource.Tpm),
        var c when c == EntropySource.Hsm.Code => nameof(EntropySource.Hsm),
        var c when c == EntropySource.Deterministic.Code => nameof(EntropySource.Deterministic),
        var c when c == EntropySource.Unknown.Code => nameof(EntropySource.Unknown),
        _ => $"Custom ({code})"
    };
}