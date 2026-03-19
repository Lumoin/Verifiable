using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Verifier (client) metadata as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-11">OID4VP 1.0 §11</see>.
/// </summary>
/// <remarks>
/// <para>
/// Passed inline in the JAR via the <c>client_metadata</c> parameter, or retrieved
/// by reference via <c>client_metadata_uri</c>. Authoritative data obtained through
/// other mechanisms — such as an OpenID Federation Entity Statement — takes precedence
/// over values in this object per OID4VP 1.0 §5.1.
/// </para>
/// <para>
/// The <see cref="Jwks"/> property carries the Verifier's public keys for response
/// encryption per OID4VP 1.0 §8.3. These MUST NOT be used to verify the signature
/// of signed Authorization Requests. Each key MUST have a <c>kid</c> that uniquely
/// identifies it within the context of the request.
/// </para>
/// <para>
/// Key material is represented as a raw JSON string so that the application can
/// resolve it using whatever JWKS library it chooses — consistent with the delegate
/// and pluggable pattern throughout this library.
/// </para>
/// </remarks>
[DebuggerDisplay("VerifierClientMetadata ClientId={ClientId}")]
public sealed class VerifierClientMetadata: IEquatable<VerifierClientMetadata>
{
    /// <summary>
    /// The verifier's client identifier. Matches the <c>client_id</c> in the
    /// Authorization Request.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// The JSON Web Key Set carrying the Verifier's public keys for response
    /// encryption, as defined in OID4VP 1.0 §5.1 and §8.3. OPTIONAL.
    /// Represented as a raw JSON string — parsing is the caller's responsibility.
    /// Keys included here MUST NOT be used to verify JAR signatures.
    /// </summary>
    public string? Jwks { get; init; }

    /// <summary>
    /// The credential formats and algorithms supported by the Verifier, as defined
    /// in OID4VP 1.0 §11.1. REQUIRED when not available to the Wallet via another
    /// mechanism.
    /// </summary>
    public VpFormatsSupported? VpFormatsSupported { get; init; }

    /// <summary>
    /// Content encryption algorithms supported for encrypted Authorization Responses,
    /// corresponding to the JWE <c>enc</c> parameter. OPTIONAL.
    /// Values are JWA identifiers per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518">RFC 7518</see>.
    /// When a response mode requiring encryption is specified, this MUST be present
    /// for any value other than the default <c>A128GCM</c> per OID4VP 1.0 §5.1.
    /// </summary>
    public IReadOnlyList<string>? EncryptedResponseEncValuesSupported { get; init; }

    /// <summary>
    /// Key management algorithms supported for encrypted Authorization Responses,
    /// corresponding to the JWE <c>alg</c> parameter. OPTIONAL.
    /// Values are JWA identifiers per RFC 7518.
    /// </summary>
    public IReadOnlyList<string>? EncryptedResponseAlgValuesSupported { get; init; }

    /// <summary>
    /// Additional metadata parameters not covered by the typed properties.
    /// Profiles of OID4VP 1.0 §11 may define further parameters usable here.
    /// </summary>
    public IReadOnlyDictionary<string, object>? AdditionalParameters { get; init; }


    /// <inheritdoc/>
    public bool Equals(VerifierClientMetadata? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(ClientId, other.ClientId, StringComparison.Ordinal)
            && string.Equals(Jwks, other.Jwks, StringComparison.Ordinal)
            && SequenceEqualOrBothNull(
                EncryptedResponseAlgValuesSupported,
                other.EncryptedResponseAlgValuesSupported)
            && SequenceEqualOrBothNull(
                EncryptedResponseEncValuesSupported,
                other.EncryptedResponseEncValuesSupported);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is VerifierClientMetadata other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(ClientId, Jwks);

    /// <summary>Determines whether two instances are equal.</summary>
    public static bool operator ==(VerifierClientMetadata? left, VerifierClientMetadata? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two instances differ.</summary>
    public static bool operator !=(VerifierClientMetadata? left, VerifierClientMetadata? right) =>
        !(left == right);


    private static bool SequenceEqualOrBothNull(
        IReadOnlyList<string>? a,
        IReadOnlyList<string>? b)
    {
        if(a is null && b is null)
        {
            return true;
        }

        if(a is null || b is null)
        {
            return false;
        }

        return a.SequenceEqual(b, StringComparer.Ordinal);
    }
}
