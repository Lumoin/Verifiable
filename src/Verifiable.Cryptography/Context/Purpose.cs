using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Context;

/// <summary>
/// Defines the intended use of cryptographic material.
/// </summary>
/// <remarks>
/// <para>
/// This type follows a "dynamic enum" pattern used throughout the Context namespace.
/// Regular C# enums cannot be extended by library users without forking. This pattern
/// provides type safety while allowing runtime extension:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Type safety</strong> — Stronger than raw <see langword="int"/> or
/// <see langword="string"/> identifiers.
/// </description></item>
/// <item><description>
/// <strong>Fast routing</strong> — Integer comparison for registry lookups, no string parsing.
/// </description></item>
/// <item><description>
/// <strong>Extensibility</strong> — Library users call <see cref="Create"/> to add custom values
/// at application startup for organization-specific purposes.
/// </description></item>
/// </list>
/// <para>
/// Use code values above 1000 to avoid collisions with future library additions:
/// </para>
/// <code>
/// public static class CustomPurposes
/// {
///     public static Purpose Attestation { get; } = Purpose.Create(1001);
///     public static Purpose Recovery { get; } = Purpose.Create(1002);
/// }
/// </code>
/// <para>
/// The <see cref="Create"/> method modifies shared static state. Call it only during
/// application startup before concurrent access begins.
/// </para>
/// </remarks>
[DebuggerDisplay("{PurposeNames.GetName(this),nq}")]
public readonly struct Purpose: IEquatable<Purpose>
{
    /// <summary>Gets the numeric code for this purpose.</summary>
    public int Code { get; }


    private Purpose(int code)
    {
        Code = code;
    }


    /// <summary>No specific purpose defined.</summary>
    public static Purpose None { get; } = new Purpose(0);

    /// <summary>Public key for signature verification.</summary>
    public static Purpose Verification { get; } = new Purpose(1);

    /// <summary>Private key for creating asymmetric signatures.</summary>
    public static Purpose Signing { get; } = new Purpose(2);

    /// <summary>Key for key exchange operations such as ECDH.</summary>
    public static Purpose Exchange { get; } = new Purpose(3);

    /// <summary>Key is wrapped (encrypted under another key).</summary>
    public static Purpose Wrapped { get; } = new Purpose(4);

    /// <summary>An asymmetric signature value (not a key).</summary>
    public static Purpose Signature { get; } = new Purpose(5);

    /// <summary>Key or material used for symmetric encryption.</summary>
    public static Purpose Encryption { get; } = new Purpose(6);

    /// <summary>
    /// Nonce value for session freshness and replay protection.
    /// </summary>
    /// <remarks>
    /// Used in session protocols where a random value provides freshness guarantees.
    /// In TPM contexts, used for nonceCaller and nonceTPM in authorization sessions.
    /// Initialization vectors for AEAD ciphers are nonces in this sense.
    /// </remarks>
    public static Purpose Nonce { get; } = new Purpose(7);

    /// <summary>
    /// HMAC key or HMAC output value.
    /// </summary>
    /// <remarks>
    /// Specifically for HMAC constructions (RFC 2104) — keyed hash-based MACs.
    /// Used for HMAC keys and output values in session-based protocols, including
    /// TPM authorization session HMACs and HKDF-derived keys. Distinct from
    /// <see cref="Mac"/>, which covers non-HMAC MAC constructions such as GHASH
    /// and Poly1305.
    /// </remarks>
    public static Purpose Hmac { get; } = new Purpose(8);

    /// <summary>
    /// Digest or hash value.
    /// </summary>
    /// <remarks>
    /// Used for hash results, integrity values, and derived data. In TPM contexts,
    /// used for PCR values, cpHash, rpHash, and general digests.
    /// </remarks>
    public static Purpose Digest { get; } = new Purpose(9);

    /// <summary>TPM transport input or output.</summary>
    public static Purpose Transport { get; } = new Purpose(10);

    /// <summary>Opaque data value without a more specific cryptographic purpose.</summary>
    public static Purpose Data { get; } = new Purpose(11);

    /// <summary>
    /// Message Authentication Code (MAC) output from a symmetric algorithm that is
    /// not HMAC, such as GHASH (AES-GCM) or Poly1305 (ChaCha20-Poly1305).
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="Hmac"/>, which specifically identifies HMAC-based
    /// authentication codes. Use <see cref="Mac"/> for authentication tags produced
    /// by AEAD ciphers such as the GCM authentication tag in a JWE token.
    /// </remarks>
    public static Purpose Mac { get; } = new Purpose(12);

    /// <summary>
    /// Plaintext bytes produced by a decryption operation.
    /// </summary>
    /// <remarks>
    /// Tags memory that holds the result of decrypting ciphertext. The content is
    /// sensitive and must be cleared on disposal. Typical consumers read it once and
    /// immediately parse or forward the bytes.
    /// </remarks>
    public static Purpose Decrypted { get; } = new Purpose(13);


    private static readonly List<Purpose> purposes = new([
        None, Verification, Signing, Exchange, Wrapped, Signature,
        Encryption, Nonce, Hmac, Digest, Transport, Data, Mac, Decrypted
    ]);

    /// <summary>Gets all registered purpose values.</summary>
    public static IReadOnlyList<Purpose> Purposes => purposes.AsReadOnly();


    /// <summary>
    /// Creates a new purpose value for custom use cases.
    /// </summary>
    /// <param name="code">The unique numeric code for this purpose.</param>
    /// <returns>The newly created purpose.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    public static Purpose Create(int code)
    {
        for(int i = 0; i < purposes.Count; ++i)
        {
            if(purposes[i].Code == code)
            {
                throw new ArgumentException($"Purpose code {code} already exists.");
            }
        }

        var newPurpose = new Purpose(code);
        purposes.Add(newPurpose);
        return newPurpose;
    }


    /// <inheritdoc/>
    public override string ToString() => PurposeNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(Purpose other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is Purpose other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in Purpose left, in Purpose right) => left.Equals(right);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in Purpose left, in Purpose right) => !left.Equals(right);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in object left, in Purpose right) => Equals(left, right);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in Purpose left, in object right) => Equals(left, right);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in object left, in Purpose right) => !Equals(left, right);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in Purpose left, in object right) => !Equals(left, right);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;
}


/// <summary>
/// Provides human-readable names for <see cref="Purpose"/> values.
/// </summary>
public static class PurposeNames
{
    /// <summary>Gets the name for the specified purpose.</summary>
    public static string GetName(Purpose purpose) => GetName(purpose.Code);

    /// <summary>Gets the name for the specified purpose code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == Purpose.None.Code => nameof(Purpose.None),
        var c when c == Purpose.Verification.Code => nameof(Purpose.Verification),
        var c when c == Purpose.Signing.Code => nameof(Purpose.Signing),
        var c when c == Purpose.Exchange.Code => nameof(Purpose.Exchange),
        var c when c == Purpose.Wrapped.Code => nameof(Purpose.Wrapped),
        var c when c == Purpose.Signature.Code => nameof(Purpose.Signature),
        var c when c == Purpose.Encryption.Code => nameof(Purpose.Encryption),
        var c when c == Purpose.Nonce.Code => nameof(Purpose.Nonce),
        var c when c == Purpose.Hmac.Code => nameof(Purpose.Hmac),
        var c when c == Purpose.Digest.Code => nameof(Purpose.Digest),
        var c when c == Purpose.Transport.Code => nameof(Purpose.Transport),
        var c when c == Purpose.Data.Code => nameof(Purpose.Data),
        var c when c == Purpose.Mac.Code => nameof(Purpose.Mac),
        var c when c == Purpose.Decrypted.Code => nameof(Purpose.Decrypted),
        _ => $"Custom ({code})"
    };
}
