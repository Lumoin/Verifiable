using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Context;

/// <summary>
/// Defines the intended use of cryptographic materials.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Design Rationale: Extensible Type-Safe Identifiers</strong>
/// </para>
/// <para>
/// This type follows a "dynamic enum" pattern used throughout the Context namespace.
/// Regular C# enums cannot be extended by library users without forking. This pattern
/// provides type safety while allowing runtime extension:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Type safety</strong> - Stronger than raw int or string identifiers.
/// </description></item>
/// <item><description>
/// <strong>Fast routing</strong> - Integer comparison for registry lookups, no string parsing.
/// </description></item>
/// <item><description>
/// <strong>Extensibility</strong> - Library users call <see cref="Create"/> to add custom values
/// at application startup for organization-specific purposes.
/// </description></item>
/// </list>
/// <para>
/// <strong>Extending with Custom Values</strong>
/// </para>
/// <para>
/// To add custom values, call <see cref="Create"/> during application initialization.
/// Use code values above 1000 to avoid collisions with future library additions:
/// </para>
/// <code>
/// // Application startup
/// public static class CustomPurposes
/// {
///     public static Purpose Attestation { get; } = Purpose.Create(1001);
///     public static Purpose Recovery { get; } = Purpose.Create(1002);
/// }
/// </code>
/// <para>
/// <strong>Thread Safety</strong>
/// </para>
/// <para>
/// The <see cref="Create"/> method modifies shared static state. Call it only during
/// application startup before concurrent access begins. Predefined values are safe
/// for concurrent read access.
/// </para>
/// 
/// <para>
/// <strong>Purpose in the Tagging System</strong>
/// </para>
/// <para>
/// This struct specifies the role of cryptographic material within operations,
/// such as signing, verification, encryption, or key exchange. It is part of a
/// structured tagging mechanism designed to clearly define cryptographic contexts
/// without relying on OIDs, JWT values, or other identifiers that could be
/// ambiguous over time or require extensive parsing.
/// </para>
/// 
/// <para>
/// <strong>Related Components</strong>
/// </para>
/// <para>
/// Works in conjunction with other context types to fully describe cryptographic material:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="CryptoAlgorithm"/> - which algorithm (P-256, Ed25519, RSA-2048, etc.).
/// </description></item>
/// <item><description>
/// <see cref="Purpose"/> - intended use (signing, verification, key exchange).
/// </description></item>
/// <item><description>
/// <see cref="EncodingScheme"/> - how bytes are encoded (DER, PEM, raw, compressed).
/// </description></item>
/// <item><description>
/// <see cref="MaterialSemantics"/> - what the bytes represent (direct material or handle).
/// </description></item>
/// </list>
/// 
/// <para>
/// <strong>Usage in Tag</strong>
/// </para>
/// <para>
/// These values are stored in <see cref="Tag"/> to describe key material:
/// </para>
/// <code>
/// var tag = new Tag(new Dictionary&lt;Type, object&gt;
/// {
///     [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Ed25519,
///     [typeof(Purpose)] = Purpose.Signing,
///     [typeof(EncodingScheme)] = EncodingScheme.Raw,
///     [typeof(MaterialSemantics)] = MaterialSemantics.Direct
/// });
/// </code>
/// 
/// <para>
/// <strong>Registry Routing</strong>
/// </para>
/// <para>
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> uses
/// <see cref="Purpose"/> as a discriminator to route operations to the appropriate
/// cryptographic implementation (e.g., signing vs verification functions).
/// </para>
/// </remarks>
/// <seealso cref="CryptoAlgorithm"/>
/// <seealso cref="EncodingScheme"/>
/// <seealso cref="MaterialSemantics"/>
/// <seealso cref="Tag"/>
[DebuggerDisplay("{PurposeNames.GetName(this),nq}")]
public readonly struct Purpose: IEquatable<Purpose>
{
    /// <summary>
    /// Gets the numeric code for this purpose.
    /// </summary>
    public int Code { get; }


    private Purpose(int code)
    {
        Code = code;
    }


    /// <summary>
    /// No specific purpose defined.
    /// </summary>
    public static Purpose None { get; } = new Purpose(0);


    /// <summary>
    /// Public key for signature verification.
    /// </summary>
    public static Purpose Verification { get; } = new Purpose(1);


    /// <summary>
    /// Private key for creating signatures.
    /// </summary>
    public static Purpose Signing { get; } = new Purpose(2);


    /// <summary>
    /// Key for key exchange operations (e.g., ECDH).
    /// </summary>
    public static Purpose Exchange { get; } = new Purpose(3);


    /// <summary>
    /// Key is wrapped (encrypted).
    /// </summary>
    public static Purpose Wrapped { get; } = new Purpose(4);


    /// <summary>
    /// Represents a signature value (not a key).
    /// </summary>
    public static Purpose Signature { get; } = new Purpose(5);


    /// <summary>
    /// Key for encryption operations.
    /// </summary>
    public static Purpose Encryption { get; } = new Purpose(6);


    /// <summary>
    /// Nonce value for session freshness and replay protection.
    /// </summary>
    /// <remarks>
    /// Used in session protocols where a random value provides freshness guarantees.
    /// In TPM, used for nonceCaller and nonceTPM in authorization sessions.
    /// </remarks>
    public static Purpose Nonce { get; } = new Purpose(7);


    /// <summary>
    /// Authorization value for access control.
    /// </summary>
    /// <remarks>
    /// Used for passwords, PINs, or derived values that authorize operations.
    /// In TPM, used for authValue and session HMACs.
    /// </remarks>
    public static Purpose Auth { get; } = new Purpose(8);


    /// <summary>
    /// Digest or hash value.
    /// </summary>
    /// <remarks>
    /// Used for hash results, integrity values, and derived data.
    /// In TPM, used for PCR values, cpHash, rpHash, and general digests.
    /// </remarks>
    public static Purpose Digest { get; } = new Purpose(9);

    /// <summary>
    /// TPM transport (in our out).
    /// </summary>
    public static Purpose Transport { get; } = new Purpose(10);

    /// <summary>
    /// Some data (e.g. in TPM opereations).
    /// </summary>
    public static Purpose Data { get; } = new Purpose(11);


    private static readonly List<Purpose> purposes = new([None, Verification, Signing, Exchange, Wrapped, Signature, Encryption, Nonce, Auth, Digest, Transport, Data]);

    /// <summary>
    /// Gets all registered purpose values.
    /// </summary>
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
                throw new ArgumentException("Code already exists.");
            }
        }

        var newPurpose = new Purpose(code);
        purposes.Add(newPurpose);

        return newPurpose;
    }


    /// <inheritdoc />
    public override string ToString() => PurposeNames.GetName(this);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(Purpose other)
    {
        return Code == other.Code;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is Purpose other && Equals(other);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in Purpose left, in Purpose right)
    {
        return left.Equals(right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in Purpose left, in Purpose right)
    {
        return !left.Equals(right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in object left, in Purpose right)
    {
        return Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in Purpose left, in object right)
    {
        return Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in object left, in Purpose right)
    {
        return !Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in Purpose left, in object right)
    {
        return !Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return Code;
    }
}


/// <summary>
/// Provides human-readable names for <see cref="Purpose"/> values.
/// </summary>
public static class PurposeNames
{
    /// <summary>
    /// Gets the name for the specified purpose.
    /// </summary>
    /// <param name="purpose">The purpose.</param>
    /// <returns>The human-readable name.</returns>
    public static string GetName(Purpose purpose) => GetName(purpose.Code);


    /// <summary>
    /// Gets the name for the specified purpose code.
    /// </summary>
    /// <param name="code">The numeric code.</param>
    /// <returns>The human-readable name.</returns>
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
        var c when c == Purpose.Auth.Code => nameof(Purpose.Auth),
        var c when c == Purpose.Digest.Code => nameof(Purpose.Digest),
        var c when c == Purpose.Transport.Code => nameof(Purpose.Transport),
        var c when c == Purpose.Data.Code => nameof(Purpose.Data),
        _ => $"Custom ({code})"
    };
}