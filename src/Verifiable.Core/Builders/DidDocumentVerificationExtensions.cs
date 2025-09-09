using System;
using Verifiable.Core.Did;

namespace Verifiable.Core.Builders
{
    /// <summary>
    /// Provides extension methods for adding verification relationships to <see cref="DidDocument"/> instances.
    /// These extensions enable fluent configuration of verification methods and their associated relationships
    /// in a DID document during the building process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Verification relationships define how verification methods can be used within a DID document.
    /// Each relationship type serves a specific purpose as defined by the DID Core specification:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Authentication - Proving control of the DID.</description></item>
    /// <item><description>Assertion Method - Making claims or assertions.</description></item>
    /// <item><description>Key Agreement - Establishing cryptographic keys for secure communication.</description></item>
    /// <item><description>Capability Invocation - Invoking cryptographic capabilities.</description></item>
    /// <item><description>Capability Delegation - Delegating cryptographic capabilities to other entities.</description></item>
    /// </list>
    /// <para>
    /// These extension methods provide a consistent API for configuring verification relationships
    /// across different DID method implementations while maintaining type safety and builder pattern compatibility.
    /// </para>
    /// </remarks>
    public static class DidDocumentVerificationExtensions
    {
        extension(DidDocument document)
        {
            /// <summary>
            /// Adds an authentication verification relationship to the DID document.
            /// Authentication verification methods are used to prove control of the DID.
            /// </summary>
            /// <param name="document">The DID document to modify.</param>
            /// <param name="verificationMethodId">The identifier of the verification method to use for authentication.</param>
            /// <returns>The same DID document instance with the authentication relationship added.</returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="document"/> is null.
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="verificationMethodId"/> is null or whitespace.
            /// </exception>
            /// <remarks>
            /// This method appends to any existing authentication relationships. The verification method
            /// referenced by <paramref name="verificationMethodId"/> should exist in the document's
            /// verification method array.
            /// </remarks>
            /// <example>
            /// <code>
            /// var document = new DidDocument();
            /// document.WithAuthentication("did:example:123#key-1");
            /// </code>
            /// </example>
            public DidDocument WithAuthentication(string verificationMethodId)
            {
                return document.AddRelationship(
                    verificationMethodId,
                    doc => doc.Authentication,
                    (doc, items) => doc.Authentication = items,
                    id => new AuthenticationMethod(id));
            }


            /// <summary>
            /// Adds an assertion method verification relationship to the DID document.
            /// Assertion methods are used for making claims, assertions, or signing verifiable credentials.
            /// </summary>
            /// <param name="document">The DID document to modify.</param>
            /// <param name="verificationMethodId">The identifier of the verification method to use for assertions.</param>
            /// <returns>The same DID document instance with the assertion method relationship added.</returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="document"/> is null.
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="verificationMethodId"/> is null or whitespace.
            /// </exception>
            /// <remarks>
            /// Assertion methods are commonly used when the DID subject needs to make verifiable claims
            /// or sign documents that others will verify. This is distinct from authentication, which
            /// proves control of the DID itself.
            /// </remarks>
            /// <example>
            /// <code>
            /// var document = new DidDocument();
            /// document.WithAssertionMethod("did:example:123#key-1");
            /// </code>
            /// </example>
            public DidDocument WithAssertionMethod(string verificationMethodId)
            {
                return document.AddRelationship(
                    verificationMethodId,
                    doc => doc.AssertionMethod,
                    (doc, items) => doc.AssertionMethod = items,
                    id => new AssertionMethod(id));
            }


            /// <summary>
            /// Adds a key agreement verification relationship to the DID document.
            /// Key agreement methods are used for establishing cryptographic keys for secure communication.
            /// </summary>
            /// <param name="document">The DID document to modify.</param>
            /// <param name="verificationMethodId">The identifier of the verification method to use for key agreement.</param>
            /// <returns>The same DID document instance with the key agreement relationship added.</returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="document"/> is null.
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="verificationMethodId"/> is null or whitespace.
            /// </exception>
            /// <remarks>
            /// <para>
            /// Key agreement methods are used for protocols like Elliptic Curve Diffie-Hellman (ECDH)
            /// to establish shared secrets for encryption. Not all cryptographic algorithms support
            /// key agreement operations.
            /// </para>
            /// <para>
            /// For <c>did:key</c> documents, key agreement is typically supported for:
            /// </para>
            /// <list type="bullet">
            /// <item><description>Ed25519 keys (derived to X25519 for ECDH)</description></item>
            /// <item><description>NIST P-curve keys (P-256, P-384, P-521)</description></item>
            /// <item><description>secp256k1 keys</description></item>
            /// </list>
            /// <para>
            /// RSA keys typically do not support ECDH key agreement and should not use this relationship.
            /// </para>
            /// </remarks>
            /// <example>
            /// <code>
            /// var document = new DidDocument();
            /// document.WithKeyAgreement("did:example:123#key-agreement-1");
            /// </code>
            /// </example>
            public DidDocument WithKeyAgreement(string verificationMethodId)
            {
                return document.AddRelationship(
                    verificationMethodId,
                    doc => doc.KeyAgreement,
                    (doc, items) => doc.KeyAgreement = items,
                    id => new KeyAgreementMethod(id));
            }


            /// <summary>
            /// Adds a capability invocation verification relationship to the DID document.
            /// Capability invocation methods are used for invoking cryptographic capabilities or operations.
            /// </summary>
            /// <param name="document">The DID document to modify.</param>
            /// <param name="verificationMethodId">The identifier of the verification method to use for capability invocation.</param>
            /// <returns>The same DID document instance with the capability invocation relationship added.</returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="document"/> is null.
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="verificationMethodId"/> is null or whitespace.
            /// </exception>
            /// <remarks>
            /// Capability invocation is used when the DID subject needs to invoke or execute
            /// capabilities, often in the context of authorization systems or smart contracts.
            /// This relationship indicates that the verification method can be used to prove
            /// authorization to perform specific operations.
            /// </remarks>
            /// <example>
            /// <code>
            /// var document = new DidDocument();
            /// document.WithCapabilityInvocation("did:example:123#key-1");
            /// </code>
            /// </example>
            public DidDocument WithCapabilityInvocation(string verificationMethodId)
            {
                return document.AddRelationship(
                    verificationMethodId,
                    doc => doc.CapabilityInvocation,
                    (doc, items) => doc.CapabilityInvocation = items,
                    id => new CapabilityInvocationMethod(id));
            }


            /// <summary>
            /// Adds a capability delegation verification relationship to the DID document.
            /// Capability delegation methods are used for delegating cryptographic capabilities to other entities.
            /// </summary>
            /// <param name="document">The DID document to modify.</param>
            /// <param name="verificationMethodId">The identifier of the verification method to use for capability delegation.</param>
            /// <returns>The same DID document instance with the capability delegation relationship added.</returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="document"/> is null.
            /// </exception>
            /// <exception cref="ArgumentException">
            /// Thrown when <paramref name="verificationMethodId"/> is null or whitespace.
            /// </exception>
            /// <remarks>
            /// Capability delegation is used when the DID subject needs to delegate specific
            /// capabilities or permissions to other entities. This relationship indicates that
            /// the verification method can be used to authorize delegation of capabilities,
            /// often in hierarchical authorization systems.
            /// </remarks>
            /// <example>
            /// <code>
            /// var document = new DidDocument();
            /// document.WithCapabilityDelegation("did:example:123#key-1");
            /// </code>
            /// </example>
            public DidDocument WithCapabilityDelegation(string verificationMethodId)
            {
                return document.AddRelationship(
                    verificationMethodId,
                    doc => doc.CapabilityDelegation,
                    (doc, items) => doc.CapabilityDelegation = items,
                    id => new CapabilityDelegationMethod(id));
            }
        }


        /// <summary>
        /// Generic helper for adding verification relationships with compile-time type safety and efficiency.
        /// This method provides the common array manipulation pattern used across all verification relationship types.
        /// </summary>
        /// <typeparam name="T">The specific verification relationship type.</typeparam>
        /// <param name="document">The DID document to modify.</param>
        /// <param name="verificationMethodId">The verification method identifier to add.</param>
        /// <param name="getter">Function to get the current array from the document.</param>
        /// <param name="setter">Function to set the updated array on the document.</param>
        /// <param name="factory">Function to create a new verification relationship instance.</param>
        /// <returns>The same DID document instance with the relationship added.</returns>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="verificationMethodId"/> is null or whitespace.</exception>
        /// <remarks>
        /// This method eliminates repetitive array manipulation code while maintaining zero-cost abstractions
        /// and optimal JIT compilation efficiency through compile-time generics.
        /// </remarks>
        private static DidDocument AddRelationship<T>(
            this DidDocument document,
            string verificationMethodId,
            Func<DidDocument, T[]?> getter,
            Action<DidDocument, T[]> setter,
            Func<string, T> factory) where T: VerificationRelationship
        {
            ArgumentNullException.ThrowIfNull(document, nameof(document));
            ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId, nameof(verificationMethodId));

            var existing = getter(document);
            var newItem = factory(verificationMethodId);
            T[] updated = existing == null ? [newItem] : [.. existing, newItem];
            setter(document, updated);

            return document;
        }
    }
}