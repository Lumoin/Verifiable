using System;
using System.Collections.Generic;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Core.Did.CryptographicSuites;
using Verifiable.Core.Did.Methods;

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
            where TBuilder: IBuilder
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
            where TBuilder: IBuilder
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
        /// Creates a transformation function that conditionally applies another transformation
        /// based on a predicate evaluated against the build state.
        /// </summary>
        /// <typeparam name="TBuilder">The type of the builder implementing <see cref="IBuilder"/>.</typeparam>
        /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
        /// <param name="predicate">A function that determines whether to apply the transformation.</param>
        /// <param name="transformation">The transformation to apply when the predicate returns true.</param>
        /// <returns>
        /// A transformation function that conditionally applies the specified transformation.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="predicate"/> or <paramref name="transformation"/> is null.
        /// </exception>
        /// <remarks>
        /// This method enables conditional logic in builder pipelines, allowing different
        /// transformations to be applied based on runtime conditions or build state properties.
        /// When the predicate returns false, the document is returned unchanged.
        /// </remarks>
        /// <example>
        /// <code>
        /// var builder = new KeyDidBuilder()
        ///     .With(DidBuilderExtensions.ConditionalTransform&lt;KeyDidBuilder, KeyDidBuildState&gt;(
        ///         state => state?.Suite is JsonWebKey2020,
        ///         (doc, builder, state) => {
        ///             // Only applied for JsonWebKey2020 suite
        ///             doc.AddCustomProperty();
        ///             return doc;
        ///         }));
        /// </code>
        /// </example>
        public static Func<DidDocument, TBuilder, TState?, DidDocument> ConditionalTransform<TBuilder, TState>(
            Func<TState?, bool> predicate,
            Func<DidDocument, TBuilder, TState?, DidDocument> transformation)
            where TBuilder: IBuilder
        {
            ArgumentNullException.ThrowIfNull(predicate, nameof(predicate));
            ArgumentNullException.ThrowIfNull(transformation, nameof(transformation));

            return (document, builder, state) =>
            {
                return predicate(state) ? transformation(document, builder, state) : document;
            };
        }


        /// <summary>
        /// Creates a transformation function that composes multiple transformations into a single operation.
        /// The transformations are applied in the order they are provided.
        /// </summary>
        /// <typeparam name="TBuilder">The type of the builder implementing <see cref="IBuilder"/>.</typeparam>
        /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
        /// <param name="transformations">The sequence of transformations to compose.</param>
        /// <returns>
        /// A single transformation function that applies all provided transformations in sequence.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="transformations"/> is null.</exception>
        /// <remarks>
        /// This method is useful for grouping related transformations or creating reusable
        /// transformation pipelines. Each transformation receives the result of the previous
        /// transformation, implementing a left-fold pattern.
        /// </remarks>
        /// <example>
        /// <code>
        /// var composedTransform = DidBuilderExtensions.ComposeTransformations&lt;KeyDidBuilder, KeyDidBuildState&gt;(
        ///     AddDefaultContext&lt;KeyDidBuilder, KeyDidBuildState&gt;(),
        ///     (doc, builder, state) => {
        ///         doc.AddCustomProperty();
        ///         return doc;
        ///     },
        ///     (doc, builder, state) => {
        ///         doc.AddAnotherProperty();
        ///         return doc;
        ///     });
        ///
        /// var builder = new KeyDidBuilder().With(composedTransform);
        /// </code>
        /// </example>
        public static Func<DidDocument, TBuilder, TState?, DidDocument> ComposeTransformations<TBuilder, TState>(
            params Func<DidDocument, TBuilder, TState?, DidDocument>[] transformations)
            where TBuilder: IBuilder
        {
            ArgumentNullException.ThrowIfNull(transformations, nameof(transformations));

            return (document, builder, state) =>
            {
                DidDocument result = document;
                foreach(var transformation in transformations)
                {
                    result = transformation(result, builder, state);
                }
                return result;
            };
        }


        /// <summary>
        /// Adds multiple authentication methods to the DID document using a factory function that can access the build state.
        /// </summary>
        /// <typeparam name="TBuilder">The type of the builder implementing the builder pattern.</typeparam>
        /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
        /// <param name="builder">The builder instance to extend.</param>
        /// <param name="authenticationFactory">A factory function that creates authentication methods based on the current build state.</param>
        /// <returns>The builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> or <paramref name="authenticationFactory"/> is null.</exception>
        /// <remarks>
        /// <para>
        /// This extension method provides a fluent interface for adding multiple authentication methods to DID documents
        /// during the builder process. Authentication methods are used to prove control of the DID and are typically
        /// referenced when authenticating as the DID subject.
        /// </para>
        /// <para>
        /// The factory function receives the build state, allowing for context-sensitive authentication method
        /// configuration based on information like verification method references, encoded keys, or cryptographic suites.
        /// </para>
        /// <para>
        /// If the factory function returns null or an empty enumerable, no authentication methods are added.
        /// Existing authentication methods in the document are preserved and new methods are appended.
        /// The method internally uses the builder's <c>With</c> method to apply the transformation.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Add authentication methods referencing verification methods
        /// var builder = new WebDidBuilder()
        ///     .AddAuthentications&lt;WebDidBuilder, WebDidBuildState&gt;(buildState =&gt; [
        ///         new AuthenticationMethod { Id = $"did:web:{buildState.WebDomain}#key-1" },
        ///         new AuthenticationMethod { Id = $"did:web:{buildState.WebDomain}#key-2" }
        ///     ]);
        /// </code>
        /// </example>
        public static TBuilder AddAuthentications<TBuilder, TState>(this TBuilder builder, Func<TState?, IEnumerable<AuthenticationMethod>> authenticationFactory)
            where TBuilder: Builder<DidDocument, TState, TBuilder>
        {
            return AddItemsToDocument(builder, authenticationFactory,
                doc => doc.Authentication,
                (doc, items) => doc.Authentication = items);
        }


        /// <summary>
        /// Adds multiple assertion methods to the DID document using a factory function that can access the build state.
        /// </summary>
        /// <typeparam name="TBuilder">The type of the builder implementing the builder pattern.</typeparam>
        /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
        /// <param name="builder">The builder instance to extend.</param>
        /// <param name="assertionFactory">A factory function that creates assertion methods based on the current build state.</param>
        /// <returns>The builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> or <paramref name="assertionFactory"/> is null.</exception>
        /// <remarks>
        /// <para>
        /// This extension method provides a fluent interface for adding multiple assertion methods to DID documents
        /// during the builder process. Assertion methods are used for making claims and assertions, such as
        /// issuing verifiable credentials.
        /// </para>
        /// <para>
        /// The factory function receives the build state, allowing for context-sensitive assertion method
        /// configuration based on information like verification method references, encoded keys, or cryptographic suites.
        /// </para>
        /// <para>
        /// If the factory function returns null or an empty enumerable, no assertion methods are added.
        /// Existing assertion methods in the document are preserved and new methods are appended.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Add assertion methods for credential issuance
        /// var builder = new KeyDidBuilder()
        ///     .AddAssertionMethods&lt;KeyDidBuilder, KeyDidBuildState&gt;(buildState =&gt; [
        ///         new AssertionMethod { Id = $"did:key:{buildState.EncodedKey}#{buildState.EncodedKey}" }
        ///     ]);
        /// </code>
        /// </example>
        public static TBuilder AddAssertionMethods<TBuilder, TState>(this TBuilder builder, Func<TState?, IEnumerable<AssertionMethod>> assertionFactory)
            where TBuilder: Builder<DidDocument, TState, TBuilder>
        {
            return AddItemsToDocument(builder, assertionFactory,
                doc => doc.AssertionMethod,
                (doc, items) => doc.AssertionMethod = items);
        }


        /// <summary>
        /// Adds multiple key agreement methods to the DID document using a factory function that can access the build state.
        /// </summary>
        /// <typeparam name="TBuilder">The type of the builder implementing the builder pattern.</typeparam>
        /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
        /// <param name="builder">The builder instance to extend.</param>
        /// <param name="keyAgreementFactory">A factory function that creates key agreement methods based on the current build state.</param>
        /// <returns>The builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> or <paramref name="keyAgreementFactory"/> is null.</exception>
        /// <remarks>
        /// <para>
        /// This extension method provides a fluent interface for adding multiple key agreement methods to DID documents
        /// during the builder process. Key agreement methods are used for establishing secure communication channels
        /// and shared secrets with other parties.
        /// </para>
        /// <para>
        /// The factory function receives the build state, allowing for context-sensitive key agreement method
        /// configuration based on information like verification method references, encoded keys, or cryptographic suites.
        /// </para>
        /// <para>
        /// If the factory function returns null or an empty enumerable, no key agreement methods are added.
        /// Existing key agreement methods in the document are preserved and new methods are appended.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Add key agreement methods for secure communication
        /// var builder = new WebDidBuilder()
        ///     .AddKeyAgreements&lt;WebDidBuilder, WebDidBuildState&gt;(buildState =&gt; [
        ///         new KeyAgreementMethod { Id = $"did:web:{buildState.WebDomain}#key-agreement-1" }
        ///     ]);
        /// </code>
        /// </example>
        public static TBuilder AddKeyAgreements<TBuilder, TState>(this TBuilder builder, Func<TState?, IEnumerable<KeyAgreementMethod>> keyAgreementFactory)
            where TBuilder: Builder<DidDocument, TState, TBuilder>
        {
            return AddItemsToDocument(builder, keyAgreementFactory,
                doc => doc.KeyAgreement,
                (doc, items) => doc.KeyAgreement = items);
        }


        /// <summary>
        /// Adds multiple capability invocation methods to the DID document using a factory function that can access the build state.
        /// </summary>
        /// <typeparam name="TBuilder">The type of the builder implementing the builder pattern.</typeparam>
        /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
        /// <param name="builder">The builder instance to extend.</param>
        /// <param name="capabilityInvocationFactory">A factory function that creates capability invocation methods based on the current build state.</param>
        /// <returns>The builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> or <paramref name="capabilityInvocationFactory"/> is null.</exception>
        /// <remarks>
        /// <para>
        /// This extension method provides a fluent interface for adding multiple capability invocation methods to DID documents
        /// during the builder process. Capability invocation methods are used for invoking cryptographic capabilities
        /// and performing privileged operations on behalf of the DID subject.
        /// </para>
        /// <para>
        /// The factory function receives the build state, allowing for context-sensitive capability invocation method
        /// configuration based on information like verification method references, encoded keys, or cryptographic suites.
        /// </para>
        /// <para>
        /// If the factory function returns null or an empty enumerable, no capability invocation methods are added.
        /// Existing capability invocation methods in the document are preserved and new methods are appended.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Add capability invocation methods for privileged operations
        /// var builder = new KeyDidBuilder()
        ///     .AddCapabilityInvocations&lt;KeyDidBuilder, KeyDidBuildState&gt;(buildState =&gt; [
        ///         new CapabilityInvocationMethod { Id = $"did:key:{buildState.EncodedKey}#{buildState.EncodedKey}" }
        ///     ]);
        /// </code>
        /// </example>
        public static TBuilder AddCapabilityInvocations<TBuilder, TState>(this TBuilder builder, Func<TState?, IEnumerable<CapabilityInvocationMethod>> capabilityInvocationFactory)
            where TBuilder: Builder<DidDocument, TState, TBuilder>
        {
            return AddItemsToDocument(builder, capabilityInvocationFactory,
                doc => doc.CapabilityInvocation,
                (doc, items) => doc.CapabilityInvocation = items);
        }

        /// <summary>
        /// Adds multiple capability delegation methods to the DID document using a factory function that can access the build state.
        /// </summary>
        /// <typeparam name="TBuilder">The type of the builder implementing the builder pattern.</typeparam>
        /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
        /// <param name="builder">The builder instance to extend.</param>
        /// <param name="capabilityDelegationFactory">A factory function that creates capability delegation methods based on the current build state.</param>
        /// <returns>The builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> or <paramref name="capabilityDelegationFactory"/> is null.</exception>
        /// <remarks>
        /// <para>
        /// This extension method provides a fluent interface for adding multiple capability delegation methods to DID documents
        /// during the builder process. Capability delegation methods are used for delegating cryptographic capabilities
        /// to other entities, allowing them to act on behalf of the DID subject.
        /// </para>
        /// <para>
        /// The factory function receives the build state, allowing for context-sensitive capability delegation method
        /// configuration based on information like verification method references, encoded keys, or cryptographic suites.
        /// </para>
        /// <para>
        /// If the factory function returns null or an empty enumerable, no capability delegation methods are added.
        /// Existing capability delegation methods in the document are preserved and new methods are appended.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Add capability delegation methods for delegated operations
        /// var builder = new WebDidBuilder()
        ///     .AddCapabilityDelegations&lt;WebDidBuilder, WebDidBuildState&gt;(buildState =&gt; [
        ///         new CapabilityDelegationMethod { Id = $"did:web:{buildState.WebDomain}#delegation-1" }
        ///     ]);
        /// </code>
        /// </example>
        public static TBuilder AddCapabilityDelegations<TBuilder, TState>(this TBuilder builder, Func<TState?, IEnumerable<CapabilityDelegationMethod>> capabilityDelegationFactory)
            where TBuilder: Builder<DidDocument, TState, TBuilder>
        {
            return AddItemsToDocument(builder, capabilityDelegationFactory,
                doc => doc.CapabilityDelegation,
                (doc, items) => doc.CapabilityDelegation = items);
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
            where TBuilder: Builder<DidDocument, TState, TBuilder>
        {
            return AddItemsToDocument(builder, servicesFactory,
                doc => doc.Service,
                (doc, items) => doc.Service = items);
        }


        /// <summary>
        /// Creates a verification method with the specified parameters and cryptographic suite.
        /// This is a convenience method for creating verification methods with default key format selection.
        /// </summary>
        /// <param name="publicKey">The public key material for the verification method.</param>
        /// <param name="cryptoSuite">The cryptographic suite that determines the key format representation.</param>
        /// <param name="verificationMethodId">The identifier for the verification method.</param>
        /// <param name="controller">The controller identifier for the verification method.</param>
        /// <returns>A fully configured verification method.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="publicKey"/> or <paramref name="cryptoSuite"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="verificationMethodId"/> or <paramref name="controller"/> is null or whitespace.
        /// </exception>
        /// <remarks>
        /// This method uses the default key format selector to determine the appropriate key format
        /// based on the cryptographic suite. It's suitable for most common verification method creation scenarios.
        /// </remarks>
        /// <example>
        /// <code>
        /// var verificationMethod = DidBuilderExtensions.CreateVerificationMethod(
        ///     publicKey,
        ///     JsonWebKey2020.DefaultInstance,
        ///     "did:key:example#key-1",
        ///     "did:key:example");
        /// </code>
        /// </example>
        public static VerificationMethod CreateVerificationMethod(
            PublicKeyMemory publicKey,
            CryptographicSuite cryptoSuite,
            string verificationMethodId,
            string controller)
        {
            return CreateVerificationMethod<GenericDidMethod>(
                publicKey,
                cryptoSuite,
                verificationMethodId,
                controller,
                SsiKeyFormatSelector.DefaultKeyFormatSelector,
                SsiKeyFormatSelector.DefaultKeyFormatCreator);
        }


        /// <summary>
        /// Creates a verification method with the specified parameters, cryptographic suite, and DID method type.
        /// This overload allows specifying the DID method type for more precise key format selection.
        /// </summary>
        /// <typeparam name="TDidMethod">The type of DID method, used for key format selection.</typeparam>
        /// <param name="publicKey">The public key material for the verification method.</param>
        /// <param name="cryptoSuite">The cryptographic suite that determines the key format representation.</param>
        /// <param name="verificationMethodId">The identifier for the verification method.</param>
        /// <param name="controller">The controller identifier for the verification method.</param>
        /// <returns>A fully configured verification method.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="publicKey"/> or <paramref name="cryptoSuite"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="verificationMethodId"/> or <paramref name="controller"/> is null or whitespace.
        /// </exception>
        /// <remarks>
        /// This method provides more control over key format selection by allowing specification
        /// of the DID method type, which influences how the key format selector operates.
        /// </remarks>
        /// <example>
        /// <code>
        /// var verificationMethod = DidBuilderExtensions.CreateVerificationMethod&lt;KeyDidMethod&gt;(
        ///     publicKey,
        ///     Multikey.DefaultInstance,
        ///     "did:key:example#key-1",
        ///     "did:key:example");
        /// </code>
        /// </example>
        public static VerificationMethod CreateVerificationMethod<TDidMethod>(
            PublicKeyMemory publicKey,
            CryptographicSuite cryptoSuite,
            string verificationMethodId,
            string controller) where TDidMethod: GenericDidMethod
        {
            return CreateVerificationMethod<TDidMethod>(
                publicKey,
                cryptoSuite,
                verificationMethodId,
                controller,
                SsiKeyFormatSelector.DefaultKeyFormatSelector,
                SsiKeyFormatSelector.DefaultKeyFormatCreator);
        }


        /// <summary>
        /// Creates a verification method with full control over key format selection and creation.
        /// This overload provides the most flexibility by allowing custom key format selectors and creators.
        /// </summary>
        /// <typeparam name="TDidMethod">The type of DID method, used for key format selection.</typeparam>
        /// <param name="publicKey">The public key material for the verification method.</param>
        /// <param name="cryptoSuite">The cryptographic suite that determines the key format representation.</param>
        /// <param name="verificationMethodId">The identifier for the verification method.</param>
        /// <param name="controller">The controller identifier for the verification method.</param>
        /// <param name="keyFormatSelector">A function that selects the appropriate key format type.</param>
        /// <param name="keyFormatCreator">A function that creates the key format instance.</param>
        /// <returns>A fully configured verification method.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when any of the parameters is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="verificationMethodId"/> or <paramref name="controller"/> is null or whitespace.
        /// </exception>
        /// <remarks>
        /// This method provides complete control over the verification method creation process,
        /// allowing custom key format selection and creation logic. It's useful for specialized
        /// scenarios that require non-standard key format handling.
        /// </remarks>
        /// <example>
        /// <code>
        /// var verificationMethod = DidBuilderExtensions.CreateVerificationMethod&lt;GenericDidMethod&gt;(
        ///     publicKey,
        ///     cryptoSuite,
        ///     "did:key:example#key-1",
        ///     "did:key:example",
        ///     (didMethodType, suite, preferredFormat) => typeof(PublicKeyJwk),
        ///     (keyFormatType, pubKey) => new PublicKeyJwk { /* custom logic */ });
        /// </code>
        /// </example>
        public static VerificationMethod CreateVerificationMethod<TDidMethod>(
            PublicKeyMemory publicKey,
            CryptographicSuite cryptoSuite,
            string verificationMethodId,
            string controller,
            KeyFormatSelector keyFormatSelector,
            KeyFormatCreator keyFormatCreator) where TDidMethod: GenericDidMethod
        {
            ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));
            ArgumentNullException.ThrowIfNull(cryptoSuite, nameof(cryptoSuite));
            ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId, nameof(verificationMethodId));
            ArgumentException.ThrowIfNullOrWhiteSpace(controller, nameof(controller));
            ArgumentNullException.ThrowIfNull(keyFormatSelector, nameof(keyFormatSelector));
            ArgumentNullException.ThrowIfNull(keyFormatCreator, nameof(keyFormatCreator));

            //Determine the key format type using the provided selector.
            Type keyFormatType = keyFormatSelector(typeof(TDidMethod), cryptoSuite, null);

            //Create the key format using the provided creator.
            KeyFormat keyFormat = keyFormatCreator(keyFormatType, publicKey);

            //Finally, construct the verification method.
            return new VerificationMethod
            {
                Id = verificationMethodId,
                Type = cryptoSuite.VerificationMethodType,
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
            where TBuilder: Builder<DidDocument, TState, TBuilder>
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
                            : [.. existingItems, ..newItemsArray];
                        propertySetter(document, combinedItems);
                    }
                }

                return document;
            });
        }


        /// <summary>
        /// Generic helper method for adding a verification method along with its corresponding verification relationship.
        /// This method ensures proper separation of cryptographic keys by creating one verification method per relationship type.
        /// </summary>
        /// <typeparam name="TBuilder">The type of the builder implementing the builder pattern.</typeparam>
        /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
        /// <typeparam name="TRelationship">The type of verification relationship to create (e.g., AuthenticationMethod, AssertionMethod).</typeparam>
        /// <param name="builder">The builder instance to extend.</param>
        /// <param name="verificationMethodFactory">A factory function that creates a verification method based on the current build state.</param>
        /// <returns>The builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> or <paramref name="verificationMethodFactory"/> is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the verification method ID cannot be parsed or when the relationship type is not supported.</exception>
        /// <remarks>
        /// <para>
        /// This method implements the recommended security practice of using separate verification methods
        /// for different cryptographic purposes. Each call creates both a new verification method and
        /// a corresponding verification relationship that references it using a relative DID URL fragment.
        /// </para>
        /// <para>
        /// The method follows the W3C DID specification for relative DID URL references by:
        /// </para>
        /// <list type="number">
        /// <item><description>Adding the verification method with its complete DID URL identifier</description></item>
        /// <item><description>Parsing the verification method ID to extract the fragment component</description></item>
        /// <item><description>Creating a verification relationship that references the fragment (e.g., "#key-1")</description></item>
        /// <item><description>Adding the relationship to the appropriate document property</description></item>
        /// </list>
        /// <para>
        /// Supported verification relationship types include:
        /// </para>
        /// <list type="bullet">
        /// <item><description><see cref="AuthenticationMethod"/> - For authentication operations</description></item>
        /// <item><description><see cref="AssertionMethod"/> - For signing verifiable credentials</description></item>
        /// <item><description><see cref="KeyAgreementMethod"/> - For establishing secure communication</description></item>
        /// <item><description><see cref="CapabilityInvocationMethod"/> - For invoking cryptographic capabilities</description></item>
        /// <item><description><see cref="CapabilityDelegationMethod"/> - For delegating cryptographic capabilities</description></item>
        /// </list>
        /// <para>
        /// Reference: <see href="https://www.w3.org/TR/did-1.0/#relative-did-urls">W3C DID 1.0 Section 3.2.2</see>
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Add a verification method with authentication capability
        /// var builder = new WebDidBuilder()
        ///     .AddVerificationMethodWithRelationship&lt;WebDidBuilder, WebDidBuildState, AuthenticationMethod&gt;(
        ///         state =&gt; new VerificationMethod
        ///         {
        ///             Id = $"did:web:{state.WebDomain}#key-auth-1",
        ///             Controller = $"did:web:{state.WebDomain}",
        ///             Type = Ed25519VerificationKey2020.DefaultInstance,
        ///             KeyFormat = /* appropriate key format */
        ///         });
        /// </code>
        /// </example>
        private static TBuilder AddVerificationMethodWithRelationship<TBuilder, TState, TRelationship>(
           this TBuilder builder,
           Func<TState?, VerificationMethod> verificationMethodFactory)
           where TBuilder: Builder<DidDocument, TState, TBuilder>
           where TRelationship: VerificationRelationship, new()
        {
            ArgumentNullException.ThrowIfNull(builder, nameof(builder));
            ArgumentNullException.ThrowIfNull(verificationMethodFactory, nameof(verificationMethodFactory));

            return builder.With((document, builder, state) =>
            {
                ArgumentNullException.ThrowIfNull(document, nameof(document));

                //Create the verification method using the provided factory.
                var verificationMethod = verificationMethodFactory(state);
                if(verificationMethod?.Id == null)
                {
                    throw new InvalidOperationException("Verification method must have a valid ID.");
                }

                //Parse the verification method ID to extract the fragment for relative referencing.
                var didUrl = DidUrl.ParseAbsolute(verificationMethod.Id);
                if(didUrl.Fragment == null)
                {
                    throw new InvalidOperationException($"Verification method ID '{verificationMethod.Id}' must contain a fragment identifier for relative referencing.");
                }

                //Create the relative fragment reference as specified in W3C DID 1.0 Section 3.2.2.
                document.VerificationMethod = document.VerificationMethod == null ?
                    [verificationMethod]: [.. document.VerificationMethod, verificationMethod];

                //Parse and create fragment reference.
                var fragmentReference = $"#{didUrl.Fragment}";

                //Add the relationship using the existing extension methods based on type.
                return new TRelationship() switch
                {
                    AuthenticationMethod => document.WithAuthentication(fragmentReference),
                    AssertionMethod => document.WithAssertionMethod(fragmentReference),
                    KeyAgreementMethod => document.WithKeyAgreement(fragmentReference),
                    CapabilityInvocationMethod => document.WithCapabilityInvocation(fragmentReference),
                    CapabilityDelegationMethod => document.WithCapabilityDelegation(fragmentReference),
                    _ => throw new InvalidOperationException($"Unsupported type: {typeof(TRelationship).Name}")
                };
            });
        }
    }
}