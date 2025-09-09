using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// Represents a verification method in a DID document. Verification methods are used to verify
    /// digital signatures and other cryptographic material. Each method specifies a cryptographic key
    /// or other process to perform the verification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Verification methods are the foundational building blocks for cryptographic operations in DID documents.
    /// They contain the actual key material and metadata needed to perform verification operations.
    /// Verification methods can be referenced by verification relationships such as <see cref="AuthenticationMethod"/>,
    /// <see cref="AssertionMethod"/>, <see cref="KeyAgreementMethod"/>, <see cref="CapabilityInvocationMethod"/>,
    /// and <see cref="CapabilityDelegationMethod"/>.
    /// </para>
    /// <para>
    /// A verification method can be used in two ways within a DID document:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <strong>Direct inclusion:</strong> Listed in the document's <c>verificationMethod</c> array and referenced
    /// by ID from verification relationships (e.g., "#key-1").
    /// </description></item>
    /// <item><description>
    /// <strong>Embedded inclusion:</strong> Directly embedded within a verification relationship without being
    /// listed in the main <c>verificationMethod</c> array.
    /// </description></item>
    /// </list>
    /// <para>
    /// The key material is stored in the <see cref="KeyFormat"/> property, which can be one of several
    /// standard formats such as <see cref="PublicKeyJwk"/> (JSON Web Key) or <see cref="PublicKeyMultibase"/>
    /// (Multibase-encoded key). The specific format is determined by the <see cref="Type"/> property,
    /// which indicates the cryptographic suite being used.
    /// </para>
    /// <para>
    /// See more at <see href="https://www.w3.org/TR/did-core/#verification-methods">
    /// DID Core specification: Verification methods</see>.
    /// </para>
    /// </remarks>
    [DebuggerDisplay("VerificationMethod(Id = {Id}, Type = {Type}, Controller = {Controller})")]
    public class VerificationMethod: IEquatable<VerificationMethod>
    {
        /// <summary>
        /// A unique identifier for the verification method that conforms to the rules in Section 3.2 DID URL Syntax of the DID specification.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The ID serves as a unique reference within the DID document and can take several forms:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// <strong>Fragment identifier:</strong> A local reference like "#key-1" that points to this method
        /// within the same DID document.
        /// </description></item>
        /// <item><description>
        /// <strong>Absolute DID URL:</strong> A fully qualified reference like "did:example:123#key-1"
        /// that can be resolved across different DID documents.
        /// </description></item>
        /// </list>
        /// <para>
        /// When used in verification relationships, this ID is used to establish the connection between
        /// the relationship and the verification method, enabling the resolution of cryptographic material
        /// for verification operations.
        /// </para>
        /// </remarks>
        public string? Id { get; set; }


        /// <summary>
        /// The <c>DID</c> of the entity that controls the verification method.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The controller is the entity that has the authority to update, rotate, or revoke this verification method.
        /// In most cases, the controller is the same as the DID subject (the entity the DID document describes),
        /// but it can be different in scenarios involving:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// <strong>Delegation:</strong> Where one entity delegates cryptographic authority to another.
        /// </description></item>
        /// <item><description>
        /// <strong>Multi-party control:</strong> Where multiple entities share control over verification methods.
        /// </description></item>
        /// <item><description>
        /// <strong>Guardian scenarios:</strong> Where a guardian entity controls methods on behalf of another.
        /// </description></item>
        /// </list>
        /// <para>
        /// The controller value must be a valid DID that can be resolved to determine the controlling entity's
        /// capabilities and verification methods.
        /// </para>
        /// </remarks>
        public string? Controller { get; set; }


        /// <summary>
        /// A string that indicates the cryptographic algorithm and key type for the verification method.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The type property specifies which cryptographic suite is being used and determines:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// <strong>Expected key format:</strong> Whether the <see cref="KeyFormat"/> should be a
        /// <see cref="PublicKeyJwk"/>, <see cref="PublicKeyMultibase"/>, or other format.
        /// </description></item>
        /// <item><description>
        /// <strong>Cryptographic operations:</strong> Which algorithms can be used for signing, verification,
        /// key agreement, or other operations.
        /// </description></item>
        /// <item><description>
        /// <strong>Validation rules:</strong> How the key material should be validated and what constraints apply.
        /// </description></item>
        /// </list>
        /// <para>
        /// Common values include:
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>JsonWebKey2020</c> - For JWK-based key material</description></item>
        /// <item><description><c>Multikey</c> - For multibase-encoded key material</description></item>
        /// <item><description><c>Ed25519VerificationKey2020</c> - For Ed25519 signature keys</description></item>
        /// <item><description><c>EcdsaSecp256k1VerificationKey2019</c> - For secp256k1 signature keys</description></item>
        /// </list>
        /// <para>
        /// This value defines the expected properties and behavior of the verification method as specified
        /// in the DID specification registries and cryptographic suite specifications.
        /// </para>
        /// </remarks>
        public string? Type { get; set; }


        /// <summary>
        /// A key format object representing the public key material used for verification.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The key format contains the actual cryptographic material needed to perform verification operations.
        /// The specific type of this property depends on the <see cref="Type"/> property:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// <strong><see cref="PublicKeyJwk"/>:</strong> Used with types like "JsonWebKey2020" and contains
        /// key material in JSON Web Key format according to RFC 7517.
        /// </description></item>
        /// <item><description>
        /// <strong><see cref="PublicKeyMultibase"/>:</strong> Used with types like "Multikey" and contains
        /// key material encoded using the multibase specification.
        /// </description></item>
        /// </list>
        /// <para>
        /// The key format object provides the bridge between the high-level verification method abstraction
        /// and the low-level cryptographic operations. It can be converted to raw key material using
        /// methods like <see cref="VerificationMethodResolutionExtensions.ExtractKeyMaterial"/> for use
        /// with cryptographic libraries and signing/verification operations.
        /// </para>
        /// <para>
        /// Note that for DID specifications, private key information must never be present in verification methods.
        /// Only public key material should be included, as DID documents are typically public and may be
        /// widely distributed.
        /// </para>
        /// </remarks>
        public KeyFormat? KeyFormat { get; set; }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals(VerificationMethod? other)
        {
            if(other is null)
            {
                return false;
            }

            if(ReferenceEquals(this, other))
            {
                return true;
            }

            return string.Equals(Id, other.Id, StringComparison.Ordinal)
                && string.Equals(Controller, other.Controller, StringComparison.Ordinal)
                && string.Equals(Type, other.Type, StringComparison.Ordinal)
                && Equals(KeyFormat, other.KeyFormat);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? obj) => obj is VerificationMethod method && Equals(method);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(VerificationMethod? method1, VerificationMethod? method2)
        {
            if(method1 is null)
            {
                return method2 is null;
            }

            return method1.Equals(method2);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(VerificationMethod? method1, VerificationMethod? method2) => !(method1 == method2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(object? method1, VerificationMethod? method2) => method1 is VerificationMethod m && m == method2;


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(VerificationMethod? method1, object? method2) => method2 is VerificationMethod m && method1 == m;


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(object? method1, VerificationMethod? method2) => !(method1 == method2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(VerificationMethod? method1, object? method2) => !(method1 == method2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(Id);
            hash.Add(Controller);
            hash.Add(Type);
            hash.Add(KeyFormat);
            return hash.ToHashCode();
        }
    }
}