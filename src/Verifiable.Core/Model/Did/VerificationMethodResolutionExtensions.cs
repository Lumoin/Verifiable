using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Extension methods for resolving verification methods from DID document verification relationships.
    /// These methods handle both local resolution (within the same document) and external resolution
    /// (requiring retrieval of other DID documents) in a unified interface.
    /// </summary>
    public static class VerificationMethodResolutionExtensions
    {
        /// <summary>
        /// Resolves all verification methods from the Authentication relationship in a DID document.
        /// This method attempts local resolution first, then external resolution if a resolver is provided.
        /// </summary>
        /// <param name="document">The DID document containing the Authentication relationship.</param>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results indicating which methods were resolved and which failed.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="document"/> is null.</exception>
        /// <remarks>
        /// This method processes each authentication method in the document, handling both embedded verification methods
        /// and references to methods in the document's VerificationMethod array or external DID documents.
        /// Results include both successful and failed resolutions to provide complete transparency.
        /// </remarks>
        /// <example>
        /// <code>
        /// var results = await document.SelectFromAuthenticationAsync(myExternalResolver);
        /// var resolvedMethods = results.Where(r => r.IsResolved).Select(r => r.Method);
        /// var unresolvedRefs = results.Where(r => !r.IsResolved).Select(r => r.Reference);
        /// </code>
        /// </example>
        public static ValueTask<IEnumerable<VerificationMethodResolutionResult>> SelectFromAuthenticationAsync(
            this DidDocument document,
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            ArgumentNullException.ThrowIfNull(document, nameof(document));

            return ResolveVerificationMethodReferences(document.Authentication, document, externalResolver);
        }


        /// <summary>
        /// Resolves all verification methods from the AssertionMethod relationship in a DID document.
        /// This method attempts local resolution first, then external resolution if a resolver is provided.
        /// </summary>
        /// <param name="document">The DID document containing the AssertionMethod relationship.</param>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results indicating which methods were resolved and which failed.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="document"/> is null.</exception>
        /// <remarks>
        /// This method processes each assertion method in the document, handling both embedded verification methods
        /// and references to methods in the document's VerificationMethod array or external DID documents.
        /// Results include both successful and failed resolutions to provide complete transparency.
        /// </remarks>
        /// <example>
        /// <code>
        /// var results = await document.SelectFromAssertionMethodAsync();
        /// var localMethods = results.Where(r => r.IsResolved && r.IsLocal).Select(r => r.Method);
        /// </code>
        /// </example>
        public static ValueTask<IEnumerable<VerificationMethodResolutionResult>> SelectFromAssertionMethodAsync(
            this DidDocument document,
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            ArgumentNullException.ThrowIfNull(document, nameof(document));

            return ResolveVerificationMethodReferences(document.AssertionMethod, document, externalResolver);
        }


        /// <summary>
        /// Resolves all verification methods from the KeyAgreement relationship in a DID document.
        /// This method attempts local resolution first, then external resolution if a resolver is provided.
        /// </summary>
        /// <param name="document">The DID document containing the KeyAgreement relationship.</param>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results indicating which methods were resolved and which failed.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="document"/> is null.</exception>
        /// <remarks>
        /// This method processes each key agreement method in the document, handling both embedded verification methods
        /// and references to methods in the document's VerificationMethod array or external DID documents.
        /// Results include both successful and failed resolutions to provide complete transparency.
        /// </remarks>
        /// <example>
        /// <code>
        /// var results = await document.SelectFromKeyAgreementAsync(myExternalResolver);
        /// var externalMethods = results.Where(r => r.IsResolved && !r.IsLocal).Select(r => r.Method);
        /// </code>
        /// </example>
        public static ValueTask<IEnumerable<VerificationMethodResolutionResult>> SelectFromKeyAgreementAsync(
            this DidDocument document,
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            ArgumentNullException.ThrowIfNull(document, nameof(document));

            return ResolveVerificationMethodReferences(document.KeyAgreement, document, externalResolver);
        }


        /// <summary>
        /// Resolves all verification methods from the CapabilityInvocation relationship in a DID document.
        /// This method attempts local resolution first, then external resolution if a resolver is provided.
        /// </summary>
        /// <param name="document">The DID document containing the CapabilityInvocation relationship.</param>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results indicating which methods were resolved and which failed.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="document"/> is null.</exception>
        /// <remarks>
        /// This method processes each capability invocation method in the document, handling both embedded verification methods
        /// and references to methods in the document's VerificationMethod array or external DID documents.
        /// Results include both successful and failed resolutions to provide complete transparency.
        /// </remarks>
        /// <example>
        /// <code>
        /// var results = await document.SelectFromCapabilityInvocationAsync();
        /// foreach(var result in results)
        /// {
        ///     if(result.IsResolved)
        ///     {
        ///         //Use result.Method for capability invocation operations.
        ///     }
        ///     else
        ///     {
        ///         //Log or handle unresolved reference: result.Reference.
        ///     }
        /// }
        /// </code>
        /// </example>
        public static ValueTask<IEnumerable<VerificationMethodResolutionResult>> SelectFromCapabilityInvocationAsync(
            this DidDocument document,
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            ArgumentNullException.ThrowIfNull(document, nameof(document));

            return ResolveVerificationMethodReferences(document.CapabilityInvocation, document, externalResolver);
        }


        /// <summary>
        /// Resolves all verification methods from the CapabilityDelegation relationship in a DID document.
        /// This method attempts local resolution first, then external resolution if a resolver is provided.
        /// </summary>
        /// <param name="document">The DID document containing the CapabilityDelegation relationship.</param>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results indicating which methods were resolved and which failed.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="document"/> is null.</exception>
        /// <remarks>
        /// This method processes each capability delegation method in the document, handling both embedded verification methods
        /// and references to methods in the document's VerificationMethod array or external DID documents.
        /// Results include both successful and failed resolutions to provide complete transparency.
        /// </remarks>
        /// <example>
        /// <code>
        /// var results = await document.SelectFromCapabilityDelegationAsync(myExternalResolver);
        /// var resolvedMethods = results.Where(r => r.IsResolved).Select(r => r.Method);
        /// </code>
        /// </example>
        public static ValueTask<IEnumerable<VerificationMethodResolutionResult>> SelectFromCapabilityDelegationAsync(
            this DidDocument document,
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            ArgumentNullException.ThrowIfNull(document, nameof(document));

            return ResolveVerificationMethodReferences(document.CapabilityDelegation, document, externalResolver);
        }


        /// <summary>
        /// Resolves a verification method reference within a DID document by matching against
        /// the document's verification method array.
        /// </summary>
        /// <param name="document">The DID document containing verification methods.</param>
        /// <param name="reference">The verification method reference to resolve (fragment or absolute DID URL).</param>
        /// <returns>The resolved verification method, or null if not found.</returns>
        /// <remarks>
        /// <para>
        /// This method handles both fragment references (e.g., <c>#key-1</c>) and absolute
        /// DID URLs (e.g., <c>did:example:123#key-1</c>). For fragment references, the
        /// document's base DID is prepended before matching.
        /// </para>
        /// <para>
        /// The method performs case-sensitive matching against the Id property of each
        /// verification method in the document.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// var method = document.ResolveVerificationMethodReference("#key-1");
        /// if(method != null)
        /// {
        ///     //Use the resolved verification method.
        /// }
        /// </code>
        /// </example>
        public static VerificationMethod? ResolveVerificationMethodReference(
            this DidDocument document,
            string reference)
        {
            if(document.VerificationMethod is null || document.VerificationMethod.Length == 0)
            {
                return null;
            }

            string resolvedReference = reference;
            if(reference.StartsWith('#') && document.Id is not null)
            {
                resolvedReference = document.Id.ToString() + reference;
            }

            for(int i = 0; i < document.VerificationMethod.Length; ++i)
            {
                var method = document.VerificationMethod[i];
                if(string.Equals(method.Id, resolvedReference, StringComparison.Ordinal)
                    || string.Equals(method.Id, reference, StringComparison.Ordinal))
                {
                    return method;
                }
            }

            return null;
        }


        /// <summary>
        /// Extracts raw key material from a verification method using the default conversion infrastructure.
        /// This method provides direct access to the underlying cryptographic key bytes and metadata.
        /// </summary>
        /// <param name="verificationMethod">The verification method containing the key format.</param>
        /// <param name="memoryPool">Memory pool for key material allocation.</param>
        /// <returns>A tuple containing the key material, algorithm, purpose, and encoding scheme.</returns>
        /// <exception cref="ArgumentNullException">Thrown when parameters are null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when key material cannot be extracted.</exception>
        /// <remarks>
        /// This method delegates to the existing VerifiableCryptoFormatConversions infrastructure
        /// to handle the conversion from key formats (JWK, Multibase, etc.) to raw key material.
        /// The returned memory should be disposed after use.
        /// </remarks>
        /// <example>
        /// <code>
        /// var verificationMethod = results.Where(r => r.IsResolved).Select(r => r.Method).FirstOrDefault();
        /// if(verificationMethod != null)
        /// {
        ///     var keyMaterial = verificationMethod.ExtractKeyMaterial(ExactSizeMemoryPool&lt;byte&gt;.Shared);
        ///     using(keyMaterial.keyMaterial)
        ///     {
        ///         //Work with raw key bytes: keyMaterial.keyMaterial.Memory.Span.
        ///     }
        /// }
        /// </code>
        /// </example>
        public static (IMemoryOwner<byte> keyMaterial, CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme)
            ExtractKeyMaterial(this VerificationMethod verificationMethod, MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(verificationMethod, nameof(verificationMethod));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            var rawKeyMaterial = VerificationMethodCryptoConversions.DefaultConverter(
                verificationMethod, memoryPool);

            if(rawKeyMaterial.keyMaterial is null)
            {
                throw new InvalidOperationException($"Unable to extract key material from verification method '{verificationMethod.Id}'.");
            }

            return (rawKeyMaterial.keyMaterial, rawKeyMaterial.Algorithm, rawKeyMaterial.Purpose, rawKeyMaterial.Scheme);
        }


        /// <summary>
        /// Creates a PublicKeyMemory instance from a verification method.
        /// This is a convenience method that combines key material extraction with tag creation.
        /// </summary>
        /// <param name="verificationMethod">The verification method to convert.</param>
        /// <param name="memoryPool">Memory pool for key material allocation.</param>
        /// <returns>A PublicKeyMemory instance containing the key material and associated metadata.</returns>
        /// <exception cref="ArgumentNullException">Thrown when parameters are null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when key material cannot be extracted from the verification method.</exception>
        /// <remarks>
        /// The returned PublicKeyMemory should be disposed after use to return memory to the pool.
        /// The Tag property of the returned instance contains algorithm, purpose, and encoding scheme information.
        /// </remarks>
        public static PublicKeyMemory ToPublicKeyMemory(this VerificationMethod verificationMethod, MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(verificationMethod, nameof(verificationMethod));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            var rawKeyMaterial = verificationMethod.ExtractKeyMaterial(memoryPool);
            var tag = new Tag(new Dictionary<Type, object>
            {
                [typeof(CryptoAlgorithm)] = rawKeyMaterial.Algorithm,
                [typeof(Purpose)] = rawKeyMaterial.Purpose,
                [typeof(EncodingScheme)] = rawKeyMaterial.Scheme
            });

            return new PublicKeyMemory(rawKeyMaterial.keyMaterial, tag);
        }


        /// <summary>
        /// Creates a PublicKey instance directly from a verification method.
        /// This is a convenience method that combines key material extraction, PublicKeyMemory creation,
        /// and PublicKey factory creation in a single call.
        /// </summary>
        /// <param name="verificationMethod">The verification method to convert.</param>
        /// <param name="memoryPool">Memory pool for key material allocation.</param>
        /// <returns>A ready-to-use PublicKey instance.</returns>
        /// <exception cref="ArgumentNullException">Thrown when parameters are null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when key material cannot be extracted or the verification method lacks an ID.</exception>
        /// <remarks>
        /// This method provides the highest level of convenience for converting a verification method
        /// to a usable PublicKey. It handles all the necessary conversions and factory calls internally.
        /// The returned PublicKey should be disposed after use.
        /// </remarks>
        /// <example>
        /// <code>
        /// var resolvedMethod = results.Where(r => r.IsResolved).Select(r => r.Method).FirstOrDefault();
        /// if(resolvedMethod != null)
        /// {
        ///     using var publicKey = resolvedMethod.ToPublicKey(ExactSizeMemoryPool&lt;byte&gt;.Shared);
        ///
        ///     var content = Encoding.UTF8.GetBytes("Hello DID");
        ///     bool isValid = await publicKey.VerifyAsync(content, signature);
        /// }
        /// </code>
        /// </example>
        public static PublicKey ToPublicKey(this VerificationMethod verificationMethod, MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(verificationMethod, nameof(verificationMethod));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            if(string.IsNullOrWhiteSpace(verificationMethod.Id))
            {
                throw new InvalidOperationException("Verification method must have an ID to create a PublicKey.");
            }

            using var publicKeyMemory = verificationMethod.ToPublicKeyMemory(memoryPool);

            return CryptographicKeyFactory.CreatePublicKey(publicKeyMemory, verificationMethod.Id, publicKeyMemory.Tag);
        }


        /// <summary>
        /// Resolves all verification methods from all verification relationships in a DID document.
        /// This method aggregates results from all relationship types: Authentication, AssertionMethod,
        /// KeyAgreement, CapabilityInvocation, and CapabilityDelegation.
        /// </summary>
        /// <param name="document">The DID document containing the verification relationships.</param>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results from all verification relationships.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="document"/> is null.</exception>
        /// <remarks>
        /// This method is useful when you need to process all verification methods regardless of their
        /// relationship type. Results are returned in order: Authentication, AssertionMethod, KeyAgreement,
        /// CapabilityInvocation, CapabilityDelegation.
        /// </remarks>
        /// <example>
        /// <code>
        /// var allResults = await document.SelectFromAllVerificationRelationshipsAsync();
        /// var allResolvedMethods = allResults.Where(r => r.IsResolved).Select(r => r.Method);
        /// </code>
        /// </example>
        public static async ValueTask<IEnumerable<VerificationMethodResolutionResult>> SelectFromAllVerificationRelationshipsAsync(
            this DidDocument document,
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            ArgumentNullException.ThrowIfNull(document, nameof(document));

            var results = new List<VerificationMethodResolutionResult>();

            results.AddRange(await ResolveVerificationMethodReferences(document.Authentication, document, externalResolver));
            results.AddRange(await ResolveVerificationMethodReferences(document.AssertionMethod, document, externalResolver));
            results.AddRange(await ResolveVerificationMethodReferences(document.KeyAgreement, document, externalResolver));
            results.AddRange(await ResolveVerificationMethodReferences(document.CapabilityInvocation, document, externalResolver));
            results.AddRange(await ResolveVerificationMethodReferences(document.CapabilityDelegation, document, externalResolver));

            return results;
        }


        /// <summary>
        /// Core resolution logic that handles verification method reference arrays.
        /// This method implements the unified resolution strategy: local resolution first,
        /// then external resolution if a resolver is provided.
        /// </summary>
        /// <param name="references">The array of verification method references to resolve.</param>
        /// <param name="document">The DID document context for local resolution.</param>
        /// <param name="externalResolver">Optional resolver for external DID references.</param>
        /// <returns>An enumerable of resolution results for all references in the array.</returns>
        /// <remarks>
        /// This method uses pattern matching to handle embedded verification methods and references efficiently.
        /// Local resolution is always attempted first for performance and reliability.
        /// External resolution is only attempted when local resolution fails and an external resolver is provided.
        /// </remarks>
        private static async ValueTask<IEnumerable<VerificationMethodResolutionResult>> ResolveVerificationMethodReferences(
            VerificationMethodReference[]? references,
            DidDocument document,
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            if(references is null || references.Length == 0)
            {
                return Enumerable.Empty<VerificationMethodResolutionResult>();
            }

            var results = new List<VerificationMethodResolutionResult>(references.Length);
            for(int i = 0; i < references.Length; ++i)
            {
                var reference = references[i];
                var result = reference switch
                {
                    //Embedded verification method resolves directly.
                    { IsEmbeddedVerification: true, EmbeddedVerification: not null } =>
                        VerificationMethodResolutionResult.Resolved(reference.EmbeddedVerification, isLocal: true),

                    //Reference to verification method requires resolution.
                    { VerificationReferenceId: not null } =>
                        await ResolveReference(reference.VerificationReferenceId, document, externalResolver),

                    //Neither embedded nor reference indicates a malformed document.
                    _ => VerificationMethodResolutionResult.Unresolved("malformed-verification-method-reference")
                };

                results.Add(result);
            }

            return results;
        }


        /// <summary>
        /// Resolves a verification method reference by attempting local resolution first,
        /// then external resolution if local resolution fails and an external resolver is available.
        /// </summary>
        /// <param name="reference">The verification method reference to resolve (e.g., "#key-1" or "did:example:123#key-1").</param>
        /// <param name="document">The DID document context for local resolution.</param>
        /// <param name="externalResolver">Optional resolver for external DID references.</param>
        /// <returns>A resolution result indicating success or failure and the resolution method used.</returns>
        /// <remarks>
        /// Local resolution is attempted first using the ResolveVerificationMethodReference method.
        /// If local resolution fails and an external resolver is provided, external resolution is attempted.
        /// If no external resolver is provided or external resolution fails, an unresolved result is returned.
        /// </remarks>
        private static async ValueTask<VerificationMethodResolutionResult> ResolveReference(
            string reference,
            DidDocument document,
            ExternalVerificationMethodResolver? externalResolver)
        {
            //First attempt local resolution.
            var localMethod = document.ResolveVerificationMethodReference(reference);
            if(localMethod is not null)
            {
                return VerificationMethodResolutionResult.Resolved(localMethod, isLocal: true);
            }

            //If local resolution failed and external resolver is available, try external resolution.
            if(externalResolver is not null)
            {
                var externalMethod = await externalResolver(reference);
                if(externalMethod is not null)
                {
                    return VerificationMethodResolutionResult.Resolved(externalMethod, isLocal: false);
                }
            }

            //Both local and external resolution failed.
            return VerificationMethodResolutionResult.Unresolved(reference);
        }
    }
}