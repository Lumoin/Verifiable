using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.Did;

/// <summary>
/// Extension methods for resolving verification methods from DID document verification relationships.
/// </summary>
/// <remarks>
/// <para>
/// These methods handle both local resolution (within the same document) and external resolution
/// (requiring retrieval of other DID documents) in a unified interface.
/// </para>
/// <para>
/// <strong>Local vs External Resolution:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Local resolution</strong> - Resolves references within the same DID document.
/// Uses the <c>GetLocal*</c> methods which are synchronous and require no delegate.
/// </description></item>
/// <item><description>
/// <strong>External resolution</strong> - Resolves references that point to other DID documents.
/// Uses the <c>Select*Async</c> methods which require an <see cref="ExternalVerificationMethodResolver"/> delegate.
/// </description></item>
/// </list>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with the latest syntax.")]
public static class VerificationMethodResolutionExtensions
{
    extension(DidDocument document)
    {
        /// <summary>
        /// Gets all locally-resolvable assertion method verification methods.
        /// </summary>
        /// <returns>
        /// An array of resolved <see cref="VerificationMethod"/> objects. Methods that cannot
        /// be resolved locally (e.g., external references) are excluded from the result.
        /// </returns>
        /// <remarks>
        /// <para>
        /// Assertion methods are used for making claims and signing verifiable credentials.
        /// This method resolves only local references within this DID document.
        /// </para>
        /// <para>
        /// For external resolution, use <see cref="SelectFromAssertionMethodAsync"/>.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// var assertionMethods = issuerDidDocument.GetLocalAssertionMethods();
        /// var firstMethod = assertionMethods.FirstOrDefault();
        /// var ed25519Method = assertionMethods.FirstOrDefault(vm => vm.Type == "Ed25519VerificationKey2020");
        /// </code>
        /// </example>
        public VerificationMethod[] GetLocalAssertionMethods()
        {
            return ResolveLocalVerificationMethods(document.AssertionMethod, document);
        }


        /// <summary>
        /// Gets a locally-resolvable assertion method verification method by its ID.
        /// </summary>
        /// <param name="id">
        /// The verification method ID to find. Can be a fragment (e.g., <c>"#key-1"</c>) which
        /// is resolved relative to the document's DID, or a full DID URL
        /// (e.g., <c>"did:web:example.com#key-1"</c>).
        /// </param>
        /// <returns>
        /// The resolved <see cref="VerificationMethod"/>, or <c>null</c> if not found locally.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="id"/> is null or whitespace.
        /// </exception>
        /// <remarks>
        /// <para>
        /// This method first checks if any assertion method reference matches the given ID,
        /// then resolves it to the full verification method from the document's
        /// <see cref="DidDocument.VerificationMethod"/> array.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// var method = issuerDidDocument.GetLocalAssertionMethodById("#signing-key");
        /// // Or with full DID URL:
        /// var method = issuerDidDocument.GetLocalAssertionMethodById("did:web:example.com#signing-key");
        /// </code>
        /// </example>
        public VerificationMethod? GetLocalAssertionMethodById(string id)
        {
            return ResolveLocalVerificationMethodById(document.AssertionMethod, document, id);
        }


        /// <summary>
        /// Gets all locally-resolvable authentication verification methods.
        /// </summary>
        /// <returns>
        /// An array of resolved <see cref="VerificationMethod"/> objects.
        /// </returns>
        /// <remarks>
        /// Authentication methods are used to prove control of the DID.
        /// </remarks>
        public VerificationMethod[] GetLocalAuthenticationMethods()
        {
            return ResolveLocalVerificationMethods(document.Authentication, document);
        }


        /// <summary>
        /// Gets a locally-resolvable authentication verification method by its ID.
        /// </summary>
        /// <param name="id">The verification method ID or fragment to find.</param>
        /// <returns>
        /// The resolved <see cref="VerificationMethod"/>, or <c>null</c> if not found locally.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="id"/> is null or whitespace.
        /// </exception>
        public VerificationMethod? GetLocalAuthenticationMethodById(string id)
        {
            return ResolveLocalVerificationMethodById(document.Authentication, document, id);
        }


        /// <summary>
        /// Gets all locally-resolvable key agreement verification methods.
        /// </summary>
        /// <returns>
        /// An array of resolved <see cref="VerificationMethod"/> objects.
        /// </returns>
        /// <remarks>
        /// Key agreement methods are used for establishing shared secrets via protocols like ECDH.
        /// </remarks>
        public VerificationMethod[] GetLocalKeyAgreementMethods()
        {
            return ResolveLocalVerificationMethods(document.KeyAgreement, document);
        }


        /// <summary>
        /// Gets a locally-resolvable key agreement verification method by its ID.
        /// </summary>
        /// <param name="id">The verification method ID or fragment to find.</param>
        /// <returns>
        /// The resolved <see cref="VerificationMethod"/>, or <c>null</c> if not found locally.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="id"/> is null or whitespace.
        /// </exception>
        public VerificationMethod? GetLocalKeyAgreementMethodById(string id)
        {
            return ResolveLocalVerificationMethodById(document.KeyAgreement, document, id);
        }


        /// <summary>
        /// Gets all locally-resolvable capability invocation verification methods.
        /// </summary>
        /// <returns>
        /// An array of resolved <see cref="VerificationMethod"/> objects.
        /// </returns>
        /// <remarks>
        /// Capability invocation methods are used for invoking cryptographic capabilities.
        /// </remarks>
        public VerificationMethod[] GetLocalCapabilityInvocationMethods()
        {
            return ResolveLocalVerificationMethods(document.CapabilityInvocation, document);
        }


        /// <summary>
        /// Gets a locally-resolvable capability invocation verification method by its ID.
        /// </summary>
        /// <param name="id">The verification method ID or fragment to find.</param>
        /// <returns>
        /// The resolved <see cref="VerificationMethod"/>, or <c>null</c> if not found locally.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="id"/> is null or whitespace.
        /// </exception>
        public VerificationMethod? GetLocalCapabilityInvocationMethodById(string id)
        {
            return ResolveLocalVerificationMethodById(document.CapabilityInvocation, document, id);
        }


        /// <summary>
        /// Gets all locally-resolvable capability delegation verification methods.
        /// </summary>
        /// <returns>
        /// An array of resolved <see cref="VerificationMethod"/> objects.
        /// </returns>
        /// <remarks>
        /// Capability delegation methods are used for delegating cryptographic capabilities to other entities.
        /// </remarks>
        public VerificationMethod[] GetLocalCapabilityDelegationMethods()
        {
            return ResolveLocalVerificationMethods(document.CapabilityDelegation, document);
        }


        /// <summary>
        /// Gets a locally-resolvable capability delegation verification method by its ID.
        /// </summary>
        /// <param name="id">The verification method ID or fragment to find.</param>
        /// <returns>
        /// The resolved <see cref="VerificationMethod"/>, or <c>null</c> if not found locally.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="id"/> is null or whitespace.
        /// </exception>
        public VerificationMethod? GetLocalCapabilityDelegationMethodById(string id)
        {
            return ResolveLocalVerificationMethodById(document.CapabilityDelegation, document, id);
        }


        /// <summary>
        /// Resolves all verification methods from the Authentication relationship in a DID document.
        /// This method attempts local resolution first, then external resolution if a resolver is provided.
        /// </summary>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results indicating which methods were resolved and which failed.</returns>
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
        public ValueTask<VerificationMethodResolutionResult[]> SelectFromAuthenticationAsync(
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            return ResolveVerificationMethodReferencesAsync(document.Authentication, document, externalResolver);
        }


        /// <summary>
        /// Resolves all verification methods from the AssertionMethod relationship in a DID document.
        /// This method attempts local resolution first, then external resolution if a resolver is provided.
        /// </summary>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results indicating which methods were resolved and which failed.</returns>
        /// <remarks>
        /// This method processes each assertion method in the document, handling both embedded verification methods
        /// and references to methods in the document's VerificationMethod array or external DID documents.
        /// Results include both successful and failed resolutions to provide complete transparency.
        /// </remarks>
        /// <example>
        /// <code>
        /// var results = await document.SelectFromAssertionMethodAsync();
        /// var localMethods = results.Where(r => r.IsResolved &amp;&amp; r.IsLocal).Select(r => r.Method);
        /// </code>
        /// </example>
        public ValueTask<VerificationMethodResolutionResult[]> SelectFromAssertionMethodAsync(
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            return ResolveVerificationMethodReferencesAsync(document.AssertionMethod, document, externalResolver);
        }


        /// <summary>
        /// Resolves all verification methods from the KeyAgreement relationship in a DID document.
        /// This method attempts local resolution first, then external resolution if a resolver is provided.
        /// </summary>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results indicating which methods were resolved and which failed.</returns>
        /// <remarks>
        /// This method processes each key agreement method in the document, handling both embedded verification methods
        /// and references to methods in the document's VerificationMethod array or external DID documents.
        /// Results include both successful and failed resolutions to provide complete transparency.
        /// </remarks>
        /// <example>
        /// <code>
        /// var results = await document.SelectFromKeyAgreementAsync(myExternalResolver);
        /// var externalMethods = results.Where(r => r.IsResolved &amp;&amp; !r.IsLocal).Select(r => r.Method);
        /// </code>
        /// </example>
        public ValueTask<VerificationMethodResolutionResult[]> SelectFromKeyAgreementAsync(
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            return ResolveVerificationMethodReferencesAsync(document.KeyAgreement, document, externalResolver);
        }


        /// <summary>
        /// Resolves all verification methods from the CapabilityInvocation relationship in a DID document.
        /// This method attempts local resolution first, then external resolution if a resolver is provided.
        /// </summary>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results indicating which methods were resolved and which failed.</returns>
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
        ///         // Use result.Method for capability invocation operations.
        ///     }
        ///     else
        ///     {
        ///         // Log or handle unresolved reference: result.Reference.
        ///     }
        /// }
        /// </code>
        /// </example>
        public ValueTask<VerificationMethodResolutionResult[]> SelectFromCapabilityInvocationAsync(
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            return ResolveVerificationMethodReferencesAsync(document.CapabilityInvocation, document, externalResolver);
        }


        /// <summary>
        /// Resolves all verification methods from the CapabilityDelegation relationship in a DID document.
        /// This method attempts local resolution first, then external resolution if a resolver is provided.
        /// </summary>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results indicating which methods were resolved and which failed.</returns>
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
        public ValueTask<VerificationMethodResolutionResult[]> SelectFromCapabilityDelegationAsync(
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            return ResolveVerificationMethodReferencesAsync(document.CapabilityDelegation, document, externalResolver);
        }


        /// <summary>
        /// Resolves all verification methods from all verification relationships in a DID document.
        /// This method aggregates results from all relationship types: Authentication, AssertionMethod,
        /// KeyAgreement, CapabilityInvocation, and CapabilityDelegation.
        /// </summary>
        /// <param name="externalResolver">Optional resolver for external DID references. If null, only local resolution is attempted.</param>
        /// <returns>An enumerable of resolution results from all verification relationships.</returns>
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
        public async ValueTask<VerificationMethodResolutionResult[]> SelectFromAllVerificationRelationshipsAsync(
            ExternalVerificationMethodResolver? externalResolver = null)
        {
            var results = new List<VerificationMethodResolutionResult>();

            results.AddRange(await ResolveVerificationMethodReferencesAsync(document.Authentication, document, externalResolver)
                .ConfigureAwait(false));
            results.AddRange(await ResolveVerificationMethodReferencesAsync(document.AssertionMethod, document, externalResolver)
                .ConfigureAwait(false));
            results.AddRange(await ResolveVerificationMethodReferencesAsync(document.KeyAgreement, document, externalResolver)
                .ConfigureAwait(false));
            results.AddRange(await ResolveVerificationMethodReferencesAsync(document.CapabilityInvocation, document, externalResolver)
                .ConfigureAwait(false));
            results.AddRange(await ResolveVerificationMethodReferencesAsync(document.CapabilityDelegation, document, externalResolver)
                .ConfigureAwait(false));

            return [.. results];
        }


        /// <summary>
        /// Resolves a verification method reference within a DID document by matching against
        /// the document's verification method array.
        /// </summary>
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
        ///     // Use the resolved verification method.
        /// }
        /// </code>
        /// </example>
        public VerificationMethod? ResolveVerificationMethodReference(string reference)
        {
            ArgumentNullException.ThrowIfNull(reference);
            if(document.VerificationMethod is null || document.VerificationMethod.Length == 0)
            {
                return null;
            }

            string resolvedReference = reference;
            if(reference.StartsWith('#') && document.Id is not null)
            {
                resolvedReference = document.Id.ToString() + reference;
            }

            for(int i = 0; i < document.VerificationMethod.Length; i++)
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
    /// This method delegates to the existing VerificationMethodCryptoConversions infrastructure
    /// to handle the conversion from key formats (JWK, Multibase, etc.) to raw key material.
    /// The returned memory should be disposed after use.
    /// </remarks>
    public static (IMemoryOwner<byte> keyMaterial, CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme)
        ExtractKeyMaterial(this VerificationMethod verificationMethod, MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(verificationMethod);
        ArgumentNullException.ThrowIfNull(memoryPool);

        var rawKeyMaterial = VerificationMethodCryptoConversions.DefaultConverter(verificationMethod, memoryPool);

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
        ArgumentNullException.ThrowIfNull(verificationMethod);
        ArgumentNullException.ThrowIfNull(memoryPool);

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
    public static PublicKey ToPublicKey(this VerificationMethod verificationMethod, MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(verificationMethod);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(string.IsNullOrWhiteSpace(verificationMethod.Id))
        {
            throw new InvalidOperationException("Verification method must have an ID to create a PublicKey.");
        }

        using var publicKeyMemory = verificationMethod.ToPublicKeyMemory(memoryPool);

        return CryptographicKeyFactory.CreatePublicKey(publicKeyMemory, verificationMethod.Id, publicKeyMemory.Tag);
    }


    /// <summary>
    /// Resolves all verification methods from a relationship array using local resolution only.
    /// </summary>
    /// <typeparam name="T">The verification method reference type.</typeparam>
    /// <param name="references">The relationship array containing verification method references.</param>
    /// <param name="document">The DID document for local resolution.</param>
    /// <returns>
    /// An array of resolved verification methods. References that cannot be resolved locally are excluded.
    /// </returns>
    /// <remarks>
    /// <para>
    /// Per DID Core specification section 5.3.1, verification relationships can contain either
    /// embedded verification methods or references (DID URLs) to verification methods in the
    /// document's <c>verificationMethod</c> array.
    /// </para>
    /// <para>
    /// See: <see href="https://www.w3.org/TR/did-core/#verification-relationships"/>.
    /// </para>
    /// </remarks>
    private static VerificationMethod[] ResolveLocalVerificationMethods<T>(
        T[]? references,
        DidDocument document) where T : VerificationMethodReference
    {
        if(references is null || references.Length == 0)
        {
            return [];
        }

        var results = new List<VerificationMethod>(references.Length);

        for(int i = 0; i < references.Length; i++)
        {
            var resolved = ResolveLocalReference(references[i], document);
            if(resolved is not null)
            {
                results.Add(resolved);
            }
        }

        return [.. results];
    }


    /// <summary>
    /// Resolves a verification method by ID from a relationship array using local resolution only.
    /// </summary>
    /// <typeparam name="T">The verification method reference type.</typeparam>
    /// <param name="references">The relationship array to search.</param>
    /// <param name="document">The DID document for local resolution.</param>
    /// <param name="id">The verification method ID or fragment to find.</param>
    /// <returns>The resolved verification method, or null if not found locally.</returns>
    /// <remarks>
    /// <para>
    /// Per DID Core specification section 3.2, a DID URL can use a fragment to reference a specific
    /// verification method within a DID document. The fragment is appended to the DID with a <c>#</c>
    /// separator (e.g., <c>did:example:123#key-1</c>).
    /// </para>
    /// <para>
    /// See: <see href="https://www.w3.org/TR/did-core/#did-url-syntax"/>.
    /// </para>
    /// </remarks>
    private static VerificationMethod? ResolveLocalVerificationMethodById<T>(
        T[]? references,
        DidDocument document,
        string id) where T : VerificationMethodReference
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        if(references is null || references.Length == 0)
        {
            return null;
        }

        var normalizedId = id.StartsWith('#') && document.Id is not null
            ? document.Id.ToString() + id
            : id;

        for(int i = 0; i < references.Length; i++)
        {
            var reference = references[i];

            if(reference.IsEmbeddedVerification && reference.EmbeddedVerification is not null)
            {
                if(string.Equals(reference.EmbeddedVerification.Id, normalizedId, StringComparison.Ordinal) ||
                   string.Equals(reference.EmbeddedVerification.Id, id, StringComparison.Ordinal))
                {
                    return reference.EmbeddedVerification;
                }
            }
            else if(reference.VerificationReferenceId is not null)
            {
                if(string.Equals(reference.VerificationReferenceId, normalizedId, StringComparison.Ordinal) ||
                   string.Equals(reference.VerificationReferenceId, id, StringComparison.Ordinal))
                {
                    return document.ResolveVerificationMethodReference(reference.VerificationReferenceId);
                }
            }
        }

        return null;
    }


    /// <summary>
    /// Resolves a single verification method reference using local resolution only.
    /// </summary>
    /// <param name="reference">The verification method reference to resolve.</param>
    /// <param name="document">The DID document for local resolution.</param>
    /// <returns>The resolved verification method, or null if not resolvable locally.</returns>
    /// <remarks>
    /// <para>
    /// Per DID Core specification section 5.3.1, a verification relationship entry can be either:
    /// </para>
    /// <list type="bullet">
    /// <item><description>An embedded verification method (the full object).</description></item>
    /// <item><description>A reference (DID URL string) to a verification method.</description></item>
    /// </list>
    /// <para>
    /// See: <see href="https://www.w3.org/TR/did-core/#verification-methods"/>.
    /// </para>
    /// </remarks>
    private static VerificationMethod? ResolveLocalReference(VerificationMethodReference reference, DidDocument document)
    {
        if(reference.IsEmbeddedVerification && reference.EmbeddedVerification is not null)
        {
            return reference.EmbeddedVerification;
        }

        if(reference.VerificationReferenceId is not null)
        {
            return document.ResolveVerificationMethodReference(reference.VerificationReferenceId);
        }

        return null;
    }


    /// <summary>
    /// Resolves all verification method references in a relationship array, attempting local resolution
    /// first and falling back to external resolution when available.
    /// </summary>
    /// <param name="references">The array of verification method references to resolve.</param>
    /// <param name="document">The DID document context for local resolution.</param>
    /// <param name="externalResolver">Optional delegate for resolving external DID references.</param>
    /// <returns>An array of resolution results for all references.</returns>
    /// <remarks>
    /// <para>
    /// This method implements the DID URL dereferencing algorithm as specified in DID Resolution.
    /// Local resolution is always attempted first for performance and reliability. External resolution
    /// is only attempted when local resolution fails and an external resolver is provided.
    /// </para>
    /// <para>
    /// Per DID Core specification section 5.3.1, verification relationships may reference verification
    /// methods in external DID documents. Such references require DID resolution to retrieve the
    /// external document before the verification method can be extracted.
    /// </para>
    /// <para>
    /// See: <see href="https://www.w3.org/TR/did-core/#verification-relationships"/> and
    /// <see href="https://w3c-ccg.github.io/did-resolution/#dereferencing"/>.
    /// </para>
    /// </remarks>
    private static async ValueTask<VerificationMethodResolutionResult[]> ResolveVerificationMethodReferencesAsync(
        VerificationMethodReference[]? references,
        DidDocument document,
        ExternalVerificationMethodResolver? externalResolver)
    {
        if(references is null || references.Length == 0)
        {
            return [];
        }

        var results = new VerificationMethodResolutionResult[references.Length];

        for(int i = 0; i < references.Length; i++)
        {
            var reference = references[i];
            results[i] = reference switch
            {
                { IsEmbeddedVerification: true, EmbeddedVerification: not null } =>
                    VerificationMethodResolutionResult.Resolved(reference.EmbeddedVerification, isLocal: true),

                { VerificationReferenceId: not null } =>
                    await ResolveReferenceAsync(reference.VerificationReferenceId, document, externalResolver)
                        .ConfigureAwait(false),

                _ => VerificationMethodResolutionResult.Unresolved("malformed-verification-method-reference")
            };
        }

        return results;
    }


    /// <summary>
    /// Resolves a verification method reference by attempting local resolution first,
    /// then external resolution if local resolution fails and an external resolver is available.
    /// </summary>
    /// <param name="reference">The verification method reference (DID URL) to resolve.</param>
    /// <param name="document">The DID document context for local resolution.</param>
    /// <param name="externalResolver">Optional delegate for resolving external DID references.</param>
    /// <returns>A resolution result indicating success or failure.</returns>
    /// <remarks>
    /// <para>
    /// This implements the resolution strategy defined in DID Resolution specification:
    /// </para>
    /// <list type="number">
    /// <item><description>Attempt to resolve the reference within the current document.</description></item>
    /// <item><description>If local resolution fails and the reference points to an external DID, use the external resolver.</description></item>
    /// <item><description>Return an unresolved result if both strategies fail.</description></item>
    /// </list>
    /// <para>
    /// See: <see href="https://w3c-ccg.github.io/did-resolution/#dereferencing"/>.
    /// </para>
    /// </remarks>
    private static async ValueTask<VerificationMethodResolutionResult> ResolveReferenceAsync(
        string reference,
        DidDocument document,
        ExternalVerificationMethodResolver? externalResolver)
    {
        var localMethod = document.ResolveVerificationMethodReference(reference);
        if(localMethod is not null)
        {
            return VerificationMethodResolutionResult.Resolved(localMethod, isLocal: true);
        }

        if(externalResolver is not null)
        {
            var externalMethod = await externalResolver(reference).ConfigureAwait(false);
            if(externalMethod is not null)
            {
                return VerificationMethodResolutionResult.Resolved(externalMethod, isLocal: false);
            }
        }

        return VerificationMethodResolutionResult.Unresolved(reference);
    }
}