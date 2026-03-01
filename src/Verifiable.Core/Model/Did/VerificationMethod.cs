using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Represents a verification method as defined in the W3C Controlled Identifiers v1.0 specification.
    /// Verification methods contain the cryptographic material needed to verify proofs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A verification method specifies a cryptographic key or other mechanism used to verify digital
    /// signatures, authenticate entities, or perform key agreement. Each method contains:
    /// </para>
    /// <list type="bullet">
    /// <item><description><see cref="Id"/>: A unique identifier conforming to URL syntax.</description></item>
    /// <item><description><see cref="Type"/>: The cryptographic suite type (e.g., <c>Multikey</c>, <c>JsonWebKey</c>).</description></item>
    /// <item><description><see cref="Controller"/>: The entity authorized to use this method.</description></item>
    /// <item><description><see cref="KeyFormat"/>: The actual cryptographic key material.</description></item>
    /// </list>
    /// <para>
    /// Verification methods can be used in two ways within a controlled identifier document:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <strong>Direct inclusion:</strong> Listed in the document's <c>verificationMethod</c> array
    /// and referenced by ID from verification relationships.
    /// </description></item>
    /// <item><description>
    /// <strong>Embedded inclusion:</strong> Directly embedded within a verification relationship
    /// without being listed in the main <c>verificationMethod</c> array.
    /// </description></item>
    /// </list>
    /// <para>
    /// See <see href="https://www.w3.org/TR/cid-1.0/#verification-methods">CID 1.0 2.2 Verification Methods</see>.
    /// </para>
    /// </remarks>
    [DebuggerDisplay("VerificationMethod(Id = {Id}, Type = {Type}, Controller = {Controller})")]
    public class VerificationMethod: IEquatable<VerificationMethod>
    {
        /// <summary>
        /// A unique identifier for the verification method that conforms to URL syntax.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The ID serves as a unique reference and can take several forms:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// <strong>Fragment identifier:</strong> A local reference like <c>#key-1</c> that points
        /// to this method within the same document.
        /// </description></item>
        /// <item><description>
        /// <strong>Absolute URL:</strong> A fully qualified reference like
        /// <c>https://controller.example#key-1</c> that can be resolved across documents.
        /// </description></item>
        /// </list>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#verification-methods">CID 1.0 �2.2 Verification Methods</see>.
        /// </para>
        /// </remarks>
        public string? Id { get; set; }

        /// <summary>
        /// The URL identifying the entity that controls this verification method.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The controller is the entity authorized to use the associated cryptographic material
        /// to generate proofs. This is typically the same as the document subject but can differ
        /// in delegation scenarios.
        /// </para>
        /// <para>
        /// Note that the <c>controller</c> property on a verification method is an assertion made
        /// by the document controller. To verify this binding, one must retrieve the controller's
        /// own controlled identifier document and confirm it references this verification method.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#verification-methods">CID 1.0 �2.2 Verification Methods</see>.
        /// </para>
        /// </remarks>
        public string? Controller { get; set; }

        /// <summary>
        /// The type of verification method, determining the expected key format and cryptographic operations.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This specification defines two standard types:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// <c>Multikey</c>: Uses <c>publicKeyMultibase</c> for key material encoding.
        /// See <see href="https://www.w3.org/TR/cid-1.0/#Multikey">CID 1.0 �2.2.2 Multikey</see>.
        /// </description></item>
        /// <item><description>
        /// <c>JsonWebKey</c>: Uses <c>publicKeyJwk</c> for key material in JWK format.
        /// See <see href="https://www.w3.org/TR/cid-1.0/#JsonWebKey">CID 1.0 �2.2.3 JsonWebKey</see>.
        /// </description></item>
        /// </list>
        /// <para>
        /// Other types may be registered in the Verifiable Credential Extensions registry.
        /// </para>
        /// </remarks>
        public string? Type { get; set; }

        /// <summary>
        /// The date and time when this verification method expires.
        /// </summary>
        /// <remarks>
        /// <para>
        /// If provided, systems should not verify any proofs associated with this verification
        /// method at or after the expiration time. Once set, this value is not expected to be updated.
        /// </para>
        /// <para>
        /// The value must be an <see href="https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp">XML Schema 1.1 dateTimeStamp</see>
        /// string in UTC (with Z suffix) or with an explicit time zone offset. For example:
        /// <c>2024-12-31T23:59:59Z</c> or <c>2024-12-31T23:59:59+01:00</c>.
        /// </para>
        /// <para>
        /// Use <see cref="Verifiable.Core.Model.Common.DateTimeStampFormat"/> for parsing and formatting.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#verification-methods">CID 1.0 �2.2 Verification Methods</see>.
        /// </para>
        /// </remarks>
        public string? Expires { get; set; }

        /// <summary>
        /// The date and time when this verification method was revoked.
        /// </summary>
        /// <remarks>
        /// <para>
        /// If present, systems must not verify any proofs associated with this verification
        /// method at or after the revocation time. Once set, this value is not expected to be updated.
        /// </para>
        /// <para>
        /// The value must be an <see href="https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp">XML Schema 1.1 dateTimeStamp</see>
        /// string in UTC (with Z suffix) or with an explicit time zone offset. For example:
        /// <c>2024-12-31T23:59:59Z</c> or <c>2024-12-31T23:59:59+01:00</c>.
        /// </para>
        /// <para>
        /// Use <see cref="Verifiable.Core.Model.Common.DateTimeStampFormat"/> for parsing and formatting.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#verification-methods">CID 1.0 �2.2 Verification Methods</see>.
        /// </para>
        /// </remarks>
        public string? Revoked { get; set; }

        /// <summary>
        /// The cryptographic key material in a format determined by <see cref="Type"/>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The specific key format type depends on the <see cref="Type"/> property:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// <see cref="PublicKeyJwk"/>: Used with type <c>JsonWebKey</c>, contains key material
        /// in JSON Web Key format per RFC 7517.
        /// </description></item>
        /// <item><description>
        /// <see cref="PublicKeyMultibase"/>: Used with type <c>Multikey</c>, contains key material
        /// encoded using the multibase specification.
        /// </description></item>
        /// </list>
        /// <para>
        /// A verification method must not contain multiple verification material properties for
        /// the same material. For example, expressing key material using both <c>publicKeyJwk</c>
        /// and <c>publicKeyMultibase</c> simultaneously is prohibited.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#verification-material">CID 1.0 �2.2.1 Verification Material</see>.
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
                && string.Equals(Expires, other.Expires, StringComparison.Ordinal)
                && string.Equals(Revoked, other.Revoked, StringComparison.Ordinal)
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
            hash.Add(Id, StringComparer.Ordinal);
            hash.Add(Controller, StringComparer.Ordinal);
            hash.Add(Type, StringComparer.Ordinal);
            hash.Add(Expires, StringComparer.Ordinal);
            hash.Add(Revoked, StringComparer.Ordinal);
            hash.Add(KeyFormat);

            return hash.ToHashCode();
        }
    }
}