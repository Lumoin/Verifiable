using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// A JWS signature parsed from untrusted input. Contains raw signature bytes
/// and header claims that must be validated before use.
/// </summary>
/// <remarks>
/// <para>
/// This type represents data parsed from an untrusted source (network, file, etc.).
/// The header claims (including <c>alg</c>) are attacker-controlled until verified.
/// </para>
/// <para>
/// The verifier should:
/// </para>
/// <list type="number">
/// <item><description>Resolve the verification key using application-specific logic
/// (e.g., <c>kid</c>, <c>jku</c>, <c>x5c</c>, issuer discovery, etc.).</description></item>
/// <item><description>Validate that the claimed <c>alg</c> matches the key's expected algorithm.</description></item>
/// <item><description>Verify the signature using the key's algorithm, not the claimed algorithm.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class UnverifiedJwsSignature : IDisposable, IEquatable<UnverifiedJwsSignature>
{
    private bool disposed;

    /// <summary>
    /// The Base64Url-encoded protected header.
    /// </summary>
    public string Protected { get; }

    /// <summary>
    /// The decoded protected header parameters. UNTRUSTED - claims must be validated.
    /// </summary>
    public IReadOnlyDictionary<string, object> ProtectedHeader { get; }

    /// <summary>
    /// The unprotected header parameters. UNTRUSTED.
    /// </summary>
    public IReadOnlyDictionary<string, object>? UnprotectedHeader { get; }

    /// <summary>
    /// Raw signature bytes from untrusted input. Owned by this instance.
    /// </summary>
    public IMemoryOwner<byte> SignatureBytes { get; }

    /// <summary>
    /// The claimed algorithm from the <c>alg</c> header. UNTRUSTED - must be validated
    /// against the expected algorithm from the verification key.
    /// </summary>
    public string? ClaimedAlgorithm => ProtectedHeader.TryGetValue("alg", out var alg) ? alg as string : null;


    public UnverifiedJwsSignature(
        string protectedEncoded,
        IReadOnlyDictionary<string, object> protectedHeader,
        IMemoryOwner<byte> signatureBytes,
        IReadOnlyDictionary<string, object>? unprotectedHeader = null)
    {
        ArgumentNullException.ThrowIfNull(protectedEncoded);
        ArgumentNullException.ThrowIfNull(protectedHeader);
        ArgumentNullException.ThrowIfNull(signatureBytes);

        Protected = protectedEncoded;
        ProtectedHeader = protectedHeader;
        SignatureBytes = signatureBytes;
        UnprotectedHeader = unprotectedHeader;
    }


    public void Dispose()
    {
        if(!disposed)
        {
            SignatureBytes.Dispose();
            disposed = true;
        }
    }


    private string DebuggerDisplay
    {
        get
        {
            string alg = ClaimedAlgorithm ?? "?";
            return $"UnverifiedJwsSignature[alg={alg} (claimed), {SignatureBytes.Memory.Length} bytes]";
        }
    }


    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(UnverifiedJwsSignature? other)
    {
        if(other is null) return false;
        if(ReferenceEquals(this, other)) return true;

        return Protected == other.Protected
            && SignatureBytes.Memory.Span.SequenceEqual(other.SignatureBytes.Memory.Span);
    }


    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is UnverifiedJwsSignature other && Equals(other);


    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Protected);
        hash.AddBytes(SignatureBytes.Memory.Span);
        return hash.ToHashCode();
    }
}