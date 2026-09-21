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
public sealed class UnverifiedJwsSignature: IDisposable, IEquatable<UnverifiedJwsSignature>
{
    private bool disposed;

    /// <summary>
    /// The Base64Url-encoded protected header.
    /// </summary>
    public string Protected { get; }

    /// <summary>
    /// The decoded protected header parameters. Attacker-controlled until the
    /// signature has been verified — use <see cref="JwtChecks"/> extension
    /// methods on this value before verification.
    /// </summary>
    public UnverifiedJwtHeader ProtectedHeader { get; }

    /// <summary>
    /// The unprotected header parameters. Attacker-controlled and not
    /// integrity-protected by the JWS signature.
    /// </summary>
    public UnverifiedJwtHeader? UnprotectedHeader { get; }

    /// <summary>
    /// Raw signature bytes from untrusted input. Owned by this instance.
    /// </summary>
    public IMemoryOwner<byte> SignatureBytes { get; }

    /// <summary>
    /// The claimed algorithm from the <c>alg</c> header. Attacker-controlled until
    /// verified — never use this value to select a verification algorithm. Always
    /// resolve the algorithm from the verification key instead.
    /// </summary>
    public string? ClaimedAlgorithm =>
        ProtectedHeader.TryGetValue(WellKnownJwkMemberNames.Alg, out object? alg) ? alg as string : null;


    /// <summary>
    /// Creates a new unverified JWS signature component.
    /// </summary>
    /// <param name="protectedEncoded">The Base64Url-encoded protected header string.</param>
    /// <param name="protectedHeader">
    /// The decoded protected header. Ownership is shared — this instance does not
    /// dispose the header.
    /// </param>
    /// <param name="signatureBytes">The raw signature bytes. Ownership is transferred.</param>
    /// <param name="unprotectedHeader">Optional unprotected header parameters.</param>
    public UnverifiedJwsSignature(
        string protectedEncoded,
        UnverifiedJwtHeader protectedHeader,
        IMemoryOwner<byte> signatureBytes,
        UnverifiedJwtHeader? unprotectedHeader = null)
    {
        ArgumentNullException.ThrowIfNull(protectedEncoded);
        ArgumentNullException.ThrowIfNull(protectedHeader);
        ArgumentNullException.ThrowIfNull(signatureBytes);

        Protected = protectedEncoded;
        ProtectedHeader = protectedHeader;
        SignatureBytes = signatureBytes;
        UnprotectedHeader = unprotectedHeader;
    }


    /// <summary>Disposes the owned <see cref="SignatureBytes"/>.</summary>
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


    /// <summary>Compares by <see cref="Protected"/> and <see cref="SignatureBytes"/> content, not by reference.</summary>
    /// <param name="other">The instance to compare against.</param>
    /// <returns><see langword="true"/> when the protected header string and signature bytes are equal.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(UnverifiedJwsSignature? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Protected == other.Protected
            && SignatureBytes.Memory.Span.SequenceEqual(other.SignatureBytes.Memory.Span);
    }


    /// <summary>Compares by <see cref="Protected"/> and <see cref="SignatureBytes"/> content when <paramref name="obj"/> is an <see cref="UnverifiedJwsSignature"/>.</summary>
    /// <param name="obj">The instance to compare against.</param>
    /// <returns><see langword="true"/> when <paramref name="obj"/> is an equal <see cref="UnverifiedJwsSignature"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is UnverifiedJwsSignature other && Equals(other);


    /// <summary>Computes a hash code from <see cref="Protected"/> and the <see cref="SignatureBytes"/> content.</summary>
    /// <returns>The hash code.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Protected);
        hash.AddBytes(SignatureBytes.Memory.Span);
        return hash.ToHashCode();
    }
}
