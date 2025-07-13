using System;
using System.Collections.Generic;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Core.Did.CryptographicSuites;

namespace Verifiable.Core.Builders
{
    /// <summary>
    /// Provides extension methods for DID document builders and general builder operations.
    /// These extensions support common patterns in DID document construction and provide
    /// reusable transformation functions.
    /// </summary>
    public static class DidBuilderExtensions
    {
        /// <summary>
        /// Gets the default JSON-LD context for DID documents as specified by the DID Core specification.
        /// This context is used across different DID methods that require JSON-LD processing.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The default context includes:
        /// </para>
        /// <list type="bullet">
        /// <item><description>The DID Core v1 context (https://www.w3.org/ns/did/v1) - required as first entry</description></item>
        /// <item><description>The JWS 2020 security suite context for cryptographic operations</description></item>
        /// </list>
        /// <para>
        /// This follows the context creation algorithms specified in various DID method specifications,
        /// such as <c>did:key</c> (https://w3c-ccg.github.io/did-method-key/#context-creation-algorithm).
        /// </para>
        /// </remarks>
        private static Context DefaultContext { get; } = new Context
        {
            Contexes = [.. new[]
            {
                //This should be the first entry in the array, see https://w3c-ccg.github.io/did-method-key/#document-creation-algorithm.
                "https://www.w3.org/ns/did/v1",
                //These come from the cryptographic suite/context. See previous
                //and https://w3c-ccg.github.io/did-method-key/#context-creation-algorithm.
                "https://w3id.org/security/suites/jws-2020/v1"
            }]
        };


        /// <summary>
        /// Adds the default JSON-LD context to a DID document.
        /// This is a convenience method for directly modifying existing DID document instances.
        /// </summary>
        /// <param name="document">The DID document to modify. Cannot be null.</param>
        /// <returns>The same DID document instance with the default context applied.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="document"/> is null.</exception>
        /// <remarks>
        /// This method modifies the provided document in-place and returns it for method chaining.
        /// The default context includes the DID Core v1 context and common cryptographic suite contexts.
        /// </remarks>
        /// <example>
        /// <code>
        /// var document = new DidDocument();
        /// document.AddDefaultContext();
        /// // Document now has the default JSON-LD context
        /// </code>
        /// </example>
        public static DidDocument AddDefaultContext(this DidDocument document)
        {
            ArgumentNullException.ThrowIfNull(document, nameof(document));

            document.Context = DefaultContext;
            return document;
        }


        /// <summary>
        /// Creates a transformation function that adds the default JSON-LD context to DID documents
        /// during the builder fold/aggregate process.
        /// </summary>
        /// <typeparam name="TBuilder">The type of the builder implementing <see cref="IBuilder"/>.</typeparam>
        /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
        /// <returns>
        /// A transformation function that can be used with the <see cref="Builder{TResult, TState, TBuilder}.With"/> method
        /// to add default context during document construction.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method provides a reusable transformation function that can be composed with other
        /// builder operations. It's particularly useful when you want to conditionally add context
        /// or when building complex transformation pipelines.
        /// </para>
        /// <para>
        /// The returned function ignores the builder and state parameters, focusing solely on
        /// adding the context to the document. This makes it a pure transformation that doesn't
        /// depend on external state.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// var builder = new KeyDidBuilder()
        ///     .With(DidBuilderExtensions.AddDefaultContext&lt;KeyDidBuilder, KeyDidBuildState&gt;())
        ///     .With((doc, builder, state) => {
        ///         // Additional transformations
        ///         return doc;
        ///     });
        /// </code>
        /// </example>
        public static Func<DidDocument, TBuilder, TState?, DidDocument> AddDefaultContext<TBuilder, TState>()
            where TBuilder : IBuilder
        {
            return (document, builder, state) =>
            {
                ArgumentNullException.ThrowIfNull(document, nameof(document));

                document.Context = DefaultContext;
                return document;
            };
        }


        /// <summary>
        /// Creates a transformation function that adds a custom JSON-LD context to DID documents
        /// during the builder fold/aggregate process.
        /// </summary>
        /// <typeparam name="TBuilder">The type of the builder implementing <see cref="IBuilder"/>.</typeparam>
        /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
        /// <param name="context">The custom context to apply to DID documents.</param>
        /// <returns>
        /// A transformation function that can be used with the <see cref="Builder{TResult, TState, TBuilder}.With"/> method
        /// to add the specified context during document construction.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is null.</exception>
        /// <remarks>
        /// This method allows for custom context configurations beyond the default context.
        /// It's useful when working with specialized cryptographic suites or when additional
        /// JSON-LD contexts are required for specific use cases.
        /// </remarks>
        /// <example>
        /// <code>
        /// var customContext = new Context {
        ///     Contexes = ["https://www.w3.org/ns/did/v1", "https://example.com/custom/v1"]
        /// };
        ///
        /// var builder = new KeyDidBuilder()
        ///     .With(DidBuilderExtensions.AddCustomContext&lt;KeyDidBuilder, KeyDidBuildState&gt;(customContext));
        /// </code>
        /// </example>
        public static Func<DidDocument, TBuilder, TState?, DidDocument> AddCustomContext<TBuilder, TState>(Context context)
            where TBuilder : IBuilder
        {
            ArgumentNullException.ThrowIfNull(context, nameof(context));

            return (document, builder, state) =>
            {
                ArgumentNullException.ThrowIfNull(document, nameof(document));

                document.Context = context;

                return document;
            };
        }


        /// <summary>
        /// Adds multiple service endpoints to the DID document using a factory function that can access the build state.
        /// </summary>
        /// <typeparam name="TBuilder">The type of the builder implementing the builder pattern.</typeparam>
        /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
        /// <param name="builder">The builder instance to extend.</param>
        /// <param name="servicesFactory">A factory function that creates service endpoints based on the current build state.</param>
        /// <returns>The builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> or <paramref name="servicesFactory"/> is null.</exception>
        /// <remarks>
        /// <para>
        /// This extension method provides a fluent interface for adding multiple service endpoints to DID documents
        /// during the builder process. Service endpoints enable DID documents to reference external services
        /// or protocols associated with the DID subject.
        /// </para>
        /// <para>
        /// The factory function receives the build state, allowing for context-sensitive service endpoint
        /// configuration based on information like web domains, encoded keys, or cryptographic suites.
        /// </para>
        /// <para>
        /// If the factory function returns null or an empty enumerable, no service endpoints are added.
        /// Existing service endpoints in the document are preserved and new endpoints are appended.
        /// The method internally uses the builder's <c>With</c> method to apply the transformation.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Add multiple dynamic services for did:web
        /// var builder = new WebDidBuilder()
        ///     .AddServices&lt;WebDidBuilder, WebDidBuildState&gt;(buildState =&gt; [
        ///         new Service
        ///         {
        ///             Id = new Uri($"did:web:{buildState.WebDomain}#service-a"),
        ///             Type = "ServiceTypeA",
        ///             ServiceEndpoint = $"https://{buildState.WebDomain.Replace(":", "/")}/service-a"
        ///         },
        ///         new Service
        ///         {
        ///             Id = new Uri($"did:web:{buildState.WebDomain}#service-b"),
        ///             Type = "ServiceTypeB",
        ///             ServiceEndpoint = $"https://{buildState.WebDomain.Replace(":", "/")}/service-b"
        ///         }
        ///     ]);
        ///
        /// // Add single static service for did:key
        /// var keyBuilder = new KeyDidBuilder()
        ///     .AddServices&lt;KeyDidBuilder, KeyDidBuildState&gt;(_ =&gt; [
        ///         new Service
        ///         {
        ///             Id = new Uri("did:key:example#messaging"),
        ///             Type = "MessagingService",
        ///             ServiceEndpoint = "https://example.com/messaging"
        ///         }
        ///     ]);
        /// </code>
        /// </example>
        public static TBuilder AddServices<TBuilder, TState>(this TBuilder builder, Func<TState?, IEnumerable<Service>> servicesFactory)
            where TBuilder : Builder<DidDocument, TState, TBuilder>
        {
            return AddItemsToDocument(builder, servicesFactory,
                doc => doc.Service,
                (doc, items) => doc.Service = items);
        }


        /// <summary>
        /// Creates a verification method with the specified parameters using the default key format selection.
        /// </summary>
        /// <param name="publicKey">The public key material for the verification method.</param>
        /// <param name="verificationMethodType">The verification method type that determines the key format representation.</param>
        /// <param name="verificationMethodId">The identifier for the verification method.</param>
        /// <param name="controller">The controller identifier for the verification method.</param>
        /// <returns>A fully configured verification method.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="publicKey"/> or <paramref name="verificationMethodType"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="verificationMethodId"/> or <paramref name="controller"/> is null or whitespace.
        /// </exception>
        /// <remarks>
        /// This method uses the extension method approach for key format selection and creation.
        /// The verification method type determines the default format, but this can be overridden
        /// by customizing the KeyFormatSelector.Default delegate.
        /// </remarks>
        public static VerificationMethod CreateVerificationMethod(
            PublicKeyMemory publicKey,
            VerificationMethodTypeInfo verificationMethodType,
            string verificationMethodId,
            string controller)
        {
            ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));
            ArgumentNullException.ThrowIfNull(verificationMethodType, nameof(verificationMethodType));
            ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId, nameof(verificationMethodId));
            ArgumentException.ThrowIfNullOrWhiteSpace(controller, nameof(controller));

            KeyFormat keyFormat = verificationMethodType.CreateKeyFormat(publicKey);

            return new VerificationMethod
            {
                Id = verificationMethodId,
                Type = verificationMethodType.TypeName,
                Controller = controller,
                KeyFormat = keyFormat
            };
        }


        /// <summary>
        /// Determines whether the cryptographic algorithm supports key agreement operations such as ECDH.
        /// </summary>
        /// <param name="publicKey">The public key to check for key agreement support.</param>
        /// <returns><c>true</c> if the key purpose is for exchange operations; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// <para>
        /// Key agreement support is determined by the <see cref="Purpose"/> associated with the public key.
        /// Keys with <see cref="Purpose.Exchange"/> are intended for key agreement operations such as
        /// Elliptic Curve Diffie-Hellman (ECDH) to establish shared secrets for encryption.
        /// </para>
        /// <para>
        /// This method checks the key's intended purpose rather than inferring capabilities from the algorithm,
        /// ensuring that keys are only used for their designated cryptographic operations. Key agreement
        /// operations include:
        /// </para>
        /// <list type="bullet">
        /// <item><description>X25519 and X448 - Designed specifically for ECDH key agreement.</description></item>
        /// <item><description>NIST P-curves (P-256, P-384, P-521) - When configured for key agreement.</description></item>
        /// <item><description>secp256k1 - When configured for key agreement.</description></item>
        /// <item><description>Ed25519 - When derived to X25519 for key agreement purposes.</description></item>
        /// </list>
        /// <para>
        /// Keys with other purposes such as <see cref="Purpose.Signing"/> will return <c>false</c>
        /// even if the underlying algorithm theoretically supports key agreement.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Key specifically created for key agreement
        /// if (publicKey.SupportsKeyAgreement())
        /// {
        ///     // Safe to use for ECDH operations
        ///     document.WithKeyAgreement(verificationMethodId);
        /// }
        /// </code>
        /// </example>
        public static bool SupportsKeyAgreement(this PublicKeyMemory publicKey)
        {
            var purpose = publicKey.Tag.Get<Purpose>();

            return purpose == Purpose.Exchange;
        }


        /// <summary>
        /// Determines whether the cryptographic key supports digital signature operations.
        /// </summary>
        /// <param name="publicKey">The public key to check for signing support.</param>
        /// <returns><c>true</c> if the key purpose is for signing operations; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// <para>
        /// Signing support is determined by the <see cref="Purpose"/> associated with the public key.
        /// Keys with <see cref="Purpose.Signing"/> are intended for digital signature operations
        /// including authentication, assertion methods, and capability invocation/delegation.
        /// </para>
        /// <para>
        /// This method ensures that keys are only used for their designated cryptographic operations
        /// based on their intended purpose. Signing operations are used for:
        /// </para>
        /// <list type="bullet">
        /// <item><description><strong>Authentication</strong> - Proving control of the DID.</description></item>
        /// <item><description><strong>Assertion Methods</strong> - Signing verifiable credentials and claims.</description></item>
        /// <item><description><strong>Capability Invocation</strong> - Authorizing the use of capabilities.</description></item>
        /// <item><description><strong>Capability Delegation</strong> - Delegating capabilities to other entities.</description></item>
        /// </list>
        /// <para>
        /// Keys with other purposes such as <see cref="Purpose.Exchange"/> will return <c>false</c>
        /// as they are designed for key agreement rather than signing operations.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Key specifically created for signing
        /// if (publicKey.SupportsSigning())
        /// {
        ///     // Safe to use for authentication and assertion operations
        ///     document.WithAuthentication(verificationMethodId)
        ///            .WithAssertionMethod(verificationMethodId);
        /// }
        /// </code>
        /// </example>
        public static bool SupportsSigning(this PublicKeyMemory publicKey)
        {
            var purpose = publicKey.Tag.Get<Purpose>();

            return purpose == Purpose.Signing;
        }


        /// <summary>
        /// Generic helper method for adding arrays of items to DID document properties.
        /// This reduces code duplication across verification relationship and service methods.
        /// </summary>
        /// <typeparam name="TBuilder">The type of the builder implementing the builder pattern.</typeparam>
        /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
        /// <typeparam name="TItem">The type of items being added to the document.</typeparam>
        /// <param name="builder">The builder instance to extend.</param>
        /// <param name="itemsFactory">A factory function that creates items based on the current build state.</param>
        /// <param name="propertyGetter">A function to get the current array from the document.</param>
        /// <param name="propertySetter">A function to set the new array on the document.</param>
        /// <returns>The builder instance to enable method chaining.</returns>
        private static TBuilder AddItemsToDocument<TBuilder, TState, TItem>(
            TBuilder builder,
            Func<TState?, IEnumerable<TItem>> itemsFactory,
            Func<DidDocument, TItem[]?> propertyGetter,
            Action<DidDocument, TItem[]> propertySetter)
            where TBuilder : Builder<DidDocument, TState, TBuilder>
        {
            ArgumentNullException.ThrowIfNull(itemsFactory, nameof(itemsFactory));

            return builder.With((document, builder, state) =>
            {
                ArgumentNullException.ThrowIfNull(document, nameof(document));

                var newItems = itemsFactory(state);
                if(newItems != null)
                {
                    var newItemsArray = newItems as TItem[] ?? [.. newItems];
                    if(newItemsArray.Length > 0)
                    {
                        var existingItems = propertyGetter(document);
                        var combinedItems = existingItems == null
                            ? newItemsArray
                            : [.. existingItems, .. newItemsArray];
                        propertySetter(document, combinedItems);
                    }
                }

                return document;
            });
        }
    }
}