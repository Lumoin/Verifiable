using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;


namespace Verifiable.Core.Did
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

            return ResolveVerificationRelationships(document.Authentication, document, externalResolver);
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

            return ResolveVerificationRelationships(document.AssertionMethod, document, externalResolver);
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

            return ResolveVerificationRelationships(document.KeyAgreement, document, externalResolver);
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

            return ResolveVerificationRelationships(document.CapabilityInvocation, document, externalResolver);
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
        /// var results = await document.SelectFromCapabilityDelegationAsync(customResolver);
        /// var successfulResolutions = results.Where(r => r.IsResolved).ToList();
        /// Console.WriteLine($"Successfully resolved {successfulResolutions.Count} capability delegation methods");
        /// </code>
        /// </example>
        public static ValueTask<IEnumerable<VerificationMethodResolutionResult>> SelectFromCapabilityDelegationAsync(
            this DidDocument document,
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            ArgumentNullException.ThrowIfNull(document, nameof(document));

            return ResolveVerificationRelationships(document.CapabilityDelegation, document, externalResolver);
        }


        /// <summary>
        /// Resolves all verification methods from all verification relationships in a DID document.
        /// This method aggregates results from Authentication, AssertionMethod, KeyAgreement,
        /// CapabilityInvocation, and CapabilityDelegation relationships.
        /// </summary>
        /// <param name="document">The DID document to search across all verification relationships.</param>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results from all verification relationships.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="document"/> is null.</exception>
        /// <remarks>
        /// This method may return duplicate verification methods if the same method is referenced
        /// from multiple relationships. Use Distinct() on the resolved methods if unique methods are required.
        /// All resolution attempts are included in the results for complete transparency.
        /// </remarks>
        /// <example>
        /// <code>
        /// var allResults = await document.SelectFromAllVerificationRelationshipsAsync(resolver);
        /// var uniqueResolvedMethods = allResults
        ///     .Where(r => r.IsResolved)
        ///     .Select(r => r.Method)
        ///     .Distinct()
        ///     .ToList();
        /// </code>
        /// </example>
        public static async ValueTask<IEnumerable<VerificationMethodResolutionResult>> SelectFromAllVerificationRelationshipsAsync(
            this DidDocument document,
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            ArgumentNullException.ThrowIfNull(document, nameof(document));

            var authResults = await document.SelectFromAuthenticationAsync(externalResolver);
            var assertionResults = await document.SelectFromAssertionMethodAsync(externalResolver);
            var keyAgreementResults = await document.SelectFromKeyAgreementAsync(externalResolver);
            var capabilityInvocationResults = await document.SelectFromCapabilityInvocationAsync(externalResolver);
            var capabilityDelegationResults = await document.SelectFromCapabilityDelegationAsync(externalResolver);

            return authResults
                .Concat(assertionResults)
                .Concat(keyAgreementResults)
                .Concat(capabilityInvocationResults)
                .Concat(capabilityDelegationResults);
        }


        /// <summary>
        /// Resolves a verification method reference (like "#key-1") to the actual verification method
        /// in the document's VerificationMethod array. This method only handles local resolution.
        /// </summary>
        /// <param name="document">The DID document containing the verification methods.</param>
        /// <param name="reference">The reference to resolve (e.g., "#key-1").</param>
        /// <returns>The verification method with the matching ID, or null if not found.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="document"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="reference"/> is null or whitespace.</exception>
        /// <remarks>
        /// This method performs exact string matching on the verification method IDs.
        /// It only searches within the provided document's VerificationMethod array.
        /// For external references, use the SelectFrom*Async methods with an external resolver.
        /// </remarks>
        /// <example>
        /// <code>
        /// var verificationMethod = document.ResolveVerificationMethodReference("#key-1");
        /// if(verificationMethod != null)
        /// {
        ///     //Work with the resolved verification method.
        /// }
        /// </code>
        /// </example>
        public static VerificationMethod? ResolveVerificationMethodReference(this DidDocument document, string reference)
        {
            ArgumentNullException.ThrowIfNull(document, nameof(document));
            ArgumentException.ThrowIfNullOrWhiteSpace(reference, nameof(reference));

            if(document.VerificationMethod == null)
            {
                return null;
            }

            foreach(var vm in document.VerificationMethod)
            {
                if(string.Equals(vm.Id, reference, StringComparison.Ordinal))
                {
                    return vm;
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
        public static (IMemoryOwner<byte> keyMaterial, CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme) ExtractKeyMaterial(
            this VerificationMethod verificationMethod,
            MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(verificationMethod, nameof(verificationMethod));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            var rawKeyMaterial = VerifiableCryptoFormatConversions.DefaultVerificationMethodToAlgorithmConverter(
                verificationMethod, memoryPool);

            if(rawKeyMaterial.keyMaterial == null)
            {
                throw new InvalidOperationException($"Unable to extract key material from verification method '{verificationMethod.Id}'.");
            }

            return (rawKeyMaterial.keyMaterial, rawKeyMaterial.Algorithm, rawKeyMaterial.Purpose, rawKeyMaterial.Scheme);
        }


        /// <summary>
        /// Creates a PublicKeyMemory instance from a verification method.
        /// This provides a convenient way to get a properly tagged PublicKeyMemory for use with
        /// the cryptographic infrastructure.
        /// </summary>
        /// <param name="verificationMethod">The verification method to convert.</param>
        /// <param name="memoryPool">Memory pool for key material allocation.</param>
        /// <returns>A PublicKeyMemory instance with proper algorithm, purpose, and encoding tags.</returns>
        /// <exception cref="ArgumentNullException">Thrown when parameters are null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when key material cannot be extracted.</exception>
        /// <remarks>
        /// This method combines key material extraction with proper tagging to create a PublicKeyMemory
        /// that can be used with the CryptographicKeyFactory or other parts of the crypto infrastructure.
        /// The returned PublicKeyMemory should be disposed after use.
        /// </remarks>
        /// <example>
        /// <code>
        /// var resolvedMethod = results.Where(r => r.IsResolved).Select(r => r.Method).FirstOrDefault();
        /// if(resolvedMethod != null)
        /// {
        ///     using var publicKeyMemory = resolvedMethod.ToPublicKeyMemory(ExactSizeMemoryPool&lt;byte&gt;.Shared);
        ///     var publicKey = CryptographicKeyFactory.CreatePublicKey(
        ///         publicKeyMemory,
        ///         resolvedMethod.Id!,
        ///         publicKeyMemory.Tag);
        /// }
        /// </code>
        /// </example>
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
        /// Core resolution logic that handles verification relationship arrays of any type.
        /// This method implements the unified resolution strategy: local resolution first,
        /// then external resolution if a resolver is provided.
        /// </summary>
        /// <typeparam name="T">The type of verification relationship (must inherit from VerificationRelationship).</typeparam>
        /// <param name="relationships">The array of verification relationships to resolve.</param>
        /// <param name="document">The DID document context for local resolution.</param>
        /// <param name="externalResolver">Optional resolver for external DID references.</param>
        /// <returns>An enumerable of resolution results for all relationships in the array.</returns>
        /// <remarks>
        /// This method uses pattern matching to handle embedded verification methods and references efficiently.
        /// Local resolution is always attempted first for performance and reliability.
        /// External resolution is only attempted when local resolution fails and an external resolver is provided.
        /// </remarks>
        private static async ValueTask<IEnumerable<VerificationMethodResolutionResult>> ResolveVerificationRelationships<T>(
            T[]? relationships,
            DidDocument document,
            ExternalVerificationMethodResolver? externalResolver = null) where T: VerificationRelationship
        {
            if(relationships == null)
            {
                return Enumerable.Empty<VerificationMethodResolutionResult>();
            }

            var results = new List<VerificationMethodResolutionResult>();
            foreach(var relationship in relationships)
            {
                var result = relationship switch
                {
                    //Embedded verification method - always resolves locally.
                    { EmbeddedVerification: not null } =>
                        VerificationMethodResolutionResult.Resolved(relationship.EmbeddedVerification, isLocal: true),

                    //Reference to verification method - attempt local then external resolution.
                    { VerificationReferenceId: not null } =>
                        await ResolveReference(relationship.VerificationReferenceId, document, externalResolver),

                    //Neither embedded nor reference - this should not happen in well-formed documents.
                    _ => VerificationMethodResolutionResult.Unresolved("malformed-verification-relationship")
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
            if(localMethod != null)
            {
                return VerificationMethodResolutionResult.Resolved(localMethod, isLocal: true);
            }

            //If local resolution failed and external resolver is available, try external resolution.
            if(externalResolver != null)
            {
                var externalMethod = await externalResolver(reference);
                if(externalMethod != null)
                {
                    return VerificationMethodResolutionResult.Resolved(externalMethod, isLocal: false);
                }
            }

            //Both local and external resolution failed.
            return VerificationMethodResolutionResult.Unresolved(reference);
        }
    }
}