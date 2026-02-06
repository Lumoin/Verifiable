using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;


namespace Verifiable.Core.Model.Did;

/// <summary>
/// Provides extension members for DID document builders and related types.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not yet up to date with new extension syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "Analyzer is not yet up to date with new extension syntax.")]
public static class DidBuilderExtensions
{
    /// <summary>
    /// Gets the default JSON-LD context for DID documents as specified by the DID Core specification.
    /// </summary>
    private static Context DefaultContext { get; } = new Context
    {
        Contexts =
        [
            //This should be the first entry in the array.
            //See https://w3c-ccg.github.io/did-method-key/#document-creation-algorithm.
            "https://www.w3.org/ns/did/v1",
            //These come from the cryptographic suite/context.
            //See https://w3c-ccg.github.io/did-method-key/#context-creation-algorithm.
            "https://w3id.org/security/suites/jws-2020/v1"
        ]
    };


    /// <summary>
    /// Extensions for <see cref="DidDocument"/> instances providing context management
    /// and other direct document modifications.
    /// </summary>
    extension(DidDocument document)
    {
        /// <summary>
        /// Adds the default JSON-LD context to this DID document.
        /// </summary>
        /// <returns>This DID document instance with the default context applied.</returns>
        /// <remarks>
        /// The default context includes the DID Core v1 context and common cryptographic suite contexts.
        /// This method modifies the document in-place and returns it for method chaining.
        /// </remarks>
        /// <example>
        /// <code>
        /// var doc = new DidDocument();
        /// doc.AddDefaultContext();
        /// </code>
        /// </example>
        public DidDocument AddDefaultContext()
        {
            document.Context = DefaultContext;

            return document;
        }


        /// <summary>
        /// Adds a custom JSON-LD context to this DID document.
        /// </summary>
        /// <param name="context">The custom context to apply.</param>
        /// <returns>This DID document instance with the custom context applied.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is null.</exception>
        public DidDocument AddContext(Context context)
        {
            ArgumentNullException.ThrowIfNull(context);

            document.Context = context;

            return document;
        }
    }


    /// <summary>
    /// Extensions for <see cref="PublicKeyMemory"/> providing cryptographic capability checks.
    /// </summary>
    extension(PublicKeyMemory publicKey)
    {
        /// <summary>
        /// Determines whether this key supports key agreement operations such as ECDH.
        /// </summary>
        /// <returns><c>true</c> if the key purpose is for exchange operations; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// <para>
        /// Key agreement support is determined by the <see cref="Purpose"/> associated with the public key.
        /// Keys with <see cref="Purpose.Exchange"/> are intended for key agreement operations such as
        /// Elliptic Curve Diffie-Hellman (ECDH) to establish shared secrets for encryption.
        /// </para>
        /// <para>
        /// This method checks the key's intended purpose rather than inferring capabilities from the algorithm,
        /// ensuring that keys are only used for their designated cryptographic operations.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// if(publicKey.SupportsKeyAgreement())
        /// {
        ///     document.WithKeyAgreement(verificationMethodId);
        /// }
        /// </code>
        /// </example>
        public bool SupportsKeyAgreement()
        {
            var purpose = publicKey.Tag.Get<Purpose>();

            return purpose == Purpose.Exchange;
        }


        /// <summary>
        /// Determines whether this key supports digital signature operations.
        /// </summary>
        /// <returns><c>true</c> if the key purpose is for signing operations; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// <para>
        /// Signing support is determined by the <see cref="Purpose"/> associated with the public key.
        /// Keys with <see cref="Purpose.Signing"/> are intended for digital signature operations
        /// including authentication, assertion methods, and capability invocation/delegation.
        /// </para>
        /// <para>
        /// Signing operations are used for:
        /// </para>
        /// <list type="bullet">
        /// <item><description><strong>Authentication</strong> - Proving control of the DID.</description></item>
        /// <item><description><strong>Assertion Methods</strong> - Signing verifiable credentials and claims.</description></item>
        /// <item><description><strong>Capability Invocation</strong> - Authorizing the use of capabilities.</description></item>
        /// <item><description><strong>Capability Delegation</strong> - Delegating capabilities to other entities.</description></item>
        /// </list>
        /// </remarks>
        /// <example>
        /// <code>
        /// if(publicKey.SupportsSigning())
        /// {
        ///     document.WithAuthentication(verificationMethodId)
        ///             .WithAssertionMethod(verificationMethodId);
        /// }
        /// </code>
        /// </example>
        public bool SupportsSigning()
        {
            var purpose = publicKey.Tag.Get<Purpose>();

            return purpose == Purpose.Signing;
        }
    }


    /// <summary>
    /// Extensions for DID document builders providing fluent methods for adding services
    /// and other document elements during the fold/aggregate build process.
    /// </summary>
    /// <typeparam name="TBuilder">The specific builder type.</typeparam>
    /// <typeparam name="TState">The build state type passed between transformations.</typeparam>
    extension<TBuilder, TState>(TBuilder builder)
        where TBuilder : Builder<DidDocument, TState, TBuilder>
    {
        /// <summary>
        /// Adds multiple service endpoints to the DID document using a factory function
        /// that can access the build state.
        /// </summary>
        /// <param name="servicesFactory">
        /// A factory function that creates service endpoints based on the current build state.
        /// </param>
        /// <returns>This builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="servicesFactory"/> is null.
        /// </exception>
        /// <remarks>
        /// <para>
        /// This extension method provides a fluent interface for adding multiple service endpoints
        /// to DID documents during the builder process. The factory function receives the build state,
        /// allowing for context-sensitive service endpoint configuration.
        /// </para>
        /// <para>
        /// If the factory function returns null or an empty enumerable, no service endpoints are added.
        /// Existing service endpoints in the document are preserved and new endpoints are appended.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// var b = new WebDidBuilder()
        ///     .AddServices(buildState =>
        ///     [
        ///         new Service
        ///         {
        ///             Id = new Uri($"did:web:{buildState.WebDomain}#service-a"),
        ///             Type = "ServiceTypeA",
        ///             ServiceEndpoint = $"https://{buildState.WebDomain.Replace(":", "/")}/service-a"
        ///         }
        ///     ]);
        /// </code>
        /// </example>
        public TBuilder AddServices(Func<TState?, IEnumerable<Service>> servicesFactory)
        {
            return AddItemsToDocument(
                builder,
                servicesFactory,
                doc => doc.Service,
                (doc, items) => doc.Service = items);
        }
    }


    /// <summary>
    /// Generic helper method for adding arrays of items to DID document properties.
    /// </summary>
    /// <typeparam name="TBuilder">The specific builder type.</typeparam>
    /// <typeparam name="TState">The build state type passed between transformations.</typeparam>
    /// <typeparam name="TItem">The type of items being added to the document.</typeparam>
    /// <param name="builder">The builder instance.</param>
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
        ArgumentNullException.ThrowIfNull(itemsFactory);

        return builder.With((document, bldr, state) =>
        {
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

            return ValueTask.FromResult(document);
        });
    }


    /// <summary>
    /// Creates a transformation function that adds the default JSON-LD context to DID documents
    /// during the builder fold/aggregate process.
    /// </summary>
    /// <typeparam name="TBuilder">The type of the builder implementing <see cref="IBuilder"/>.</typeparam>
    /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
    /// <returns>
    /// A transformation function that can be used with <see cref="Builder{TResult, TState, TBuilder}.With"/>
    /// to add default context during document construction.
    /// </returns>
    /// <remarks>
    /// This method provides a reusable transformation function that can be composed with other
    /// builder operations. The returned function ignores the builder and state parameters,
    /// focusing solely on adding the context to the document.
    /// </remarks>
    /// <example>
    /// <code>
    /// var builder = new KeyDidBuilder()
    ///     .With(DidBuilderExtensions.CreateDefaultContextTransformation&lt;KeyDidBuilder, KeyDidBuildState&gt;());
    /// </code>
    /// </example>
    public static Func<DidDocument, TBuilder, TState?, CancellationToken, ValueTask<DidDocument>> CreateDefaultContextTransformation<TBuilder, TState>()
        where TBuilder : IBuilder
    {
        return (document, _, _, _) =>
        {
            document.AddDefaultContext();

            return ValueTask.FromResult(document);
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
    /// A transformation function that can be used with <see cref="Builder{TResult, TState, TBuilder}.With"/>
    /// to add the specified context during document construction.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is null.</exception>
    /// <example>
    /// <code>
    /// var customContext = new Context
    /// {
    ///     Contexes = ["https://www.w3.org/ns/did/v1", "https://example.com/custom/v1"]
    /// };
    /// var builder = new KeyDidBuilder()
    ///     .With(DidBuilderExtensions.CreateContextTransformation&lt;KeyDidBuilder, KeyDidBuildState&gt;(customContext));
    /// </code>
    /// </example>
    public static Func<DidDocument, TBuilder, TState?, CancellationToken, ValueTask<DidDocument>> CreateContextTransformation<TBuilder, TState>(Context context)
        where TBuilder : IBuilder
    {
        ArgumentNullException.ThrowIfNull(context);

        return (document, _, _, _) =>
        {
            document.AddContext(context);

            return ValueTask.FromResult(document);
        };
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
    public static VerificationMethod CreateVerificationMethod(
        PublicKeyMemory publicKey,
        VerificationMethodTypeInfo verificationMethodType,
        string verificationMethodId,
        string controller)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationMethodType);
        ArgumentException.ThrowIfNullOrWhiteSpace(verificationMethodId);
        ArgumentException.ThrowIfNullOrWhiteSpace(controller);

        KeyFormat keyFormat = verificationMethodType.CreateKeyFormat(publicKey);

        return new VerificationMethod
        {
            Id = verificationMethodId,
            Type = verificationMethodType.TypeName,
            Controller = controller,
            KeyFormat = keyFormat
        };
    }
}