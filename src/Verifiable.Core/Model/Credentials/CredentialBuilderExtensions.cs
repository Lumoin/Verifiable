using System;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Proofs;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Provides extension members for Verifiable Credential builders and related types.
/// </summary>
/// <remarks>
/// <para>
/// This class uses C# 14 extension member syntax to provide fluent APIs for credential construction.
/// Extensions are organized by the type they extend, making the API discoverable through IntelliSense.
/// </para>
/// <para>
/// <strong>Extensibility:</strong>
/// </para>
/// <para>
/// Library users can define their own extensions following the same pattern. This enables
/// custom credential types and transformations to appear alongside library-provided ones.
/// </para>
/// <code>
/// public static class MyCredentialExtensions
/// {
///     extension&lt;TBuilder, TState&gt;(TBuilder builder)
///         where TBuilder : Builder&lt;VerifiableCredential, TState, TBuilder&gt;
///     {
///         public TBuilder WithMyCustomProperty(string value)
///         {
///             return builder.With((credential, bldr, state) =&gt;
///             {
///                 credential.AdditionalData ??= new Dictionary&lt;string, object&gt;();
///                 credential.AdditionalData["myProperty"] = value;
///                 return credential;
///             });
///         }
///     }
/// }
/// </code>
/// </remarks>
public static class CredentialBuilderExtensions
{
    /// <summary>
    /// Extensions for <see cref="VerifiableCredential"/> instances providing direct credential modifications.
    /// </summary>
    extension(VerifiableCredential credential)
    {
        /// <summary>
        /// Adds the default VC 2.0 JSON-LD context to this credential.
        /// </summary>
        /// <returns>This credential instance with the default context applied.</returns>
        /// <remarks>
        /// The default context is <c>https://www.w3.org/ns/credentials/v2</c> as required
        /// by the VC Data Model 2.0 specification.
        /// </remarks>
        public VerifiableCredential AddDefaultContext()
        {
            credential.Context = CredentialConstants.DefaultVc20Context;

            return credential;
        }


        /// <summary>
        /// Adds a custom JSON-LD context to this credential.
        /// </summary>
        /// <param name="context">The custom context to apply.</param>
        /// <returns>This credential instance with the custom context applied.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is null.</exception>
        public VerifiableCredential AddContext(Context context)
        {
            ArgumentNullException.ThrowIfNull(context);

            credential.Context = context;

            return credential;
        }


        /// <summary>
        /// Adds a type to this credential's type array.
        /// </summary>
        /// <param name="type">The type to add.</param>
        /// <returns>This credential instance with the type added.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="type"/> is null or whitespace.</exception>
        public VerifiableCredential AddType(string type)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(type);

            credential.Type ??= [];
            if(!credential.Type.Contains(type))
            {
                credential.Type.Add(type);
            }

            return credential;
        }


        /// <summary>
        /// Adds a credential status entry to this credential.
        /// </summary>
        /// <param name="status">The status entry to add.</param>
        /// <returns>This credential instance with the status entry added.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="status"/> is null.</exception>
        /// <remarks>
        /// Credential status enables revocation checking. Common status types include
        /// <c>BitstringStatusListEntry</c> for W3C Bitstring Status List.
        /// </remarks>
        public VerifiableCredential AddCredentialStatus(CredentialStatus status)
        {
            ArgumentNullException.ThrowIfNull(status);

            credential.CredentialStatus ??= [];
            credential.CredentialStatus.Add(status);

            return credential;
        }


        /// <summary>
        /// Adds a credential schema reference to this credential.
        /// </summary>
        /// <param name="schema">The schema reference to add.</param>
        /// <returns>This credential instance with the schema reference added.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="schema"/> is null.</exception>
        public VerifiableCredential AddCredentialSchema(CredentialSchema schema)
        {
            ArgumentNullException.ThrowIfNull(schema);

            credential.CredentialSchema ??= [];
            credential.CredentialSchema.Add(schema);

            return credential;
        }


        /// <summary>
        /// Adds a Data Integrity proof to this credential.
        /// </summary>
        /// <param name="proof">The proof to add.</param>
        /// <returns>This credential instance with the proof added.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="proof"/> is null.</exception>
        /// <remarks>
        /// <para>
        /// This method adds a pre-created proof to the credential. For creating proofs
        /// from signing keys, use the appropriate cryptosuite functions.
        /// </para>
        /// <para>
        /// A credential can have multiple proofs, each created with different keys or cryptosuites.
        /// </para>
        /// </remarks>
        public VerifiableCredential AddProof(DataIntegrityProof proof)
        {
            ArgumentNullException.ThrowIfNull(proof);

            credential.Proof ??= [];
            credential.Proof.Add(proof);

            return credential;
        }
    }


    /// <summary>
    /// Extensions for credential builders providing fluent methods for adding credential elements
    /// during the fold/aggregate build process.
    /// </summary>
    /// <typeparam name="TBuilder">The specific builder type.</typeparam>
    /// <typeparam name="TState">The build state type passed between transformations.</typeparam>
    extension<TBuilder, TState>(TBuilder builder) where TBuilder : Builder<VerifiableCredential, TState, TBuilder>
    {
        /// <summary>
        /// Adds credential status entries to the credential using a factory function
        /// that can access the build state.
        /// </summary>
        /// <param name="statusFactory">
        /// A factory function that creates status entries based on the current build state.
        /// </param>
        /// <returns>This builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="statusFactory"/> is null.
        /// </exception>
        /// <remarks>
        /// <para>
        /// This extension method provides a fluent interface for adding credential status entries
        /// during the builder process. The factory function receives the build state,
        /// allowing for context-sensitive status configuration.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// var builder = new CredentialBuilder()
        ///     .AddCredentialStatuses(buildState =&gt;
        ///     [
        ///         new CredentialStatus
        ///         {
        ///             Id = $"{buildState.CredentialId}#status",
        ///             Type = "BitstringStatusListEntry",
        ///             StatusPurpose = "revocation",
        ///             StatusListIndex = "42",
        ///             StatusListCredential = "https://example.com/status/1"
        ///         }
        ///     ]);
        /// </code>
        /// </example>
        public TBuilder AddCredentialStatuses(Func<TState?, IEnumerable<CredentialStatus>> statusFactory)
        {
            return AddItemsToCredential(
                builder,
                statusFactory,
                cred => cred.CredentialStatus,
                (cred, items) => cred.CredentialStatus = items);
        }


        /// <summary>
        /// Adds credential schema references to the credential using a factory function
        /// that can access the build state.
        /// </summary>
        /// <param name="schemaFactory">
        /// A factory function that creates schema references based on the current build state.
        /// </param>
        /// <returns>This builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="schemaFactory"/> is null.
        /// </exception>
        public TBuilder AddCredentialSchemas(Func<TState?, IEnumerable<CredentialSchema>> schemaFactory)
        {
            return AddItemsToCredential(
                builder,
                schemaFactory,
                cred => cred.CredentialSchema,
                (cred, items) => cred.CredentialSchema = items);
        }


        /// <summary>
        /// Adds additional JSON-LD contexts to the credential using a factory function
        /// that can access the build state.
        /// </summary>
        /// <param name="contextFactory">
        /// A factory function that creates context entries based on the current build state.
        /// </param>
        /// <returns>This builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="contextFactory"/> is null.
        /// </exception>
        /// <remarks>
        /// <para>
        /// Additional contexts extend the vocabulary available in the credential.
        /// The base VC 2.0 context is always included first.
        /// </para>
        /// </remarks>
        public TBuilder AddContexts(Func<TState?, IEnumerable<object>> contextFactory)
        {
            ArgumentNullException.ThrowIfNull(contextFactory);

            return builder.With((credential, bldr, state) =>
            {
                var newContexts = contextFactory(state);
                if(newContexts != null)
                {
                    var newContextsList = newContexts.ToList();
                    if(newContextsList.Count > 0)
                    {
                        credential.Context ??= new Context();
                        credential.Context.Contexes ??= [];
                        foreach(var ctx in newContextsList)
                        {
                            if(!credential.Context.Contexes.Contains(ctx))
                            {
                                credential.Context.Contexes.Add(ctx);
                            }
                        }
                    }
                }

                return credential;
            });
        }


        /// <summary>
        /// Adds a custom transformation that sets additional properties on the credential.
        /// </summary>
        /// <param name="propertySetter">
        /// An action that sets properties on the credential using the build state.
        /// </param>
        /// <returns>This builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="propertySetter"/> is null.
        /// </exception>
        /// <remarks>
        /// <para>
        /// This method provides a general-purpose extension point for setting any credential
        /// properties that aren't covered by more specific extension methods.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// var builder = new CredentialBuilder()
        ///     .WithProperties((credential, state) =&gt;
        ///     {
        ///         credential.Name = "University Degree";
        ///         credential.Description = "A degree issued by Example University.";
        ///     });
        /// </code>
        /// </example>
        public TBuilder WithProperties(Action<VerifiableCredential, TState?> propertySetter)
        {
            ArgumentNullException.ThrowIfNull(propertySetter);

            return builder.With((credential, bldr, state) =>
            {
                propertySetter(credential, state);

                return credential;
            });
        }
    }


    /// <summary>
    /// Generic helper method for adding lists of items to credential properties.
    /// </summary>
    /// <typeparam name="TBuilder">The specific builder type.</typeparam>
    /// <typeparam name="TState">The build state type passed between transformations.</typeparam>
    /// <typeparam name="TItem">The type of items being added to the credential.</typeparam>
    /// <param name="builder">The builder instance.</param>
    /// <param name="itemsFactory">A factory function that creates items based on the current build state.</param>
    /// <param name="propertyGetter">A function to get the current list from the credential.</param>
    /// <param name="propertySetter">A function to set the new list on the credential.</param>
    /// <returns>The builder instance to enable method chaining.</returns>
    private static TBuilder AddItemsToCredential<TBuilder, TState, TItem>(
        TBuilder builder,
        Func<TState?, IEnumerable<TItem>> itemsFactory,
        Func<VerifiableCredential, List<TItem>?> propertyGetter,
        Action<VerifiableCredential, List<TItem>> propertySetter)
        where TBuilder : Builder<VerifiableCredential, TState, TBuilder>
    {
        ArgumentNullException.ThrowIfNull(itemsFactory);

        return builder.With((credential, bldr, state) =>
        {
            var newItems = itemsFactory(state);
            if(newItems != null)
            {
                var newItemsList = newItems.ToList();
                if(newItemsList.Count > 0)
                {
                    var existingItems = propertyGetter(credential);
                    if(existingItems == null)
                    {
                        propertySetter(credential, newItemsList);
                    }
                    else
                    {
                        existingItems.AddRange(newItemsList);
                    }
                }
            }

            return credential;
        });
    }


    /// <summary>
    /// Creates a transformation function that adds the default VC 2.0 context to credentials
    /// during the builder fold/aggregate process.
    /// </summary>
    /// <typeparam name="TBuilder">The type of the builder implementing <see cref="IBuilder"/>.</typeparam>
    /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
    /// <returns>
    /// A transformation function that can be used with <see cref="Builder{TResult, TState, TBuilder}.With"/>
    /// to add the default VC 2.0 context during credential construction.
    /// </returns>
    public static Func<VerifiableCredential, TBuilder, TState?, VerifiableCredential> CreateDefaultContextTransformation<TBuilder, TState>() 
        where TBuilder: IBuilder
    {
        return (credential, _, _) =>
        {
            credential.AddDefaultContext();

            return credential;
        };
    }


    /// <summary>
    /// Creates a transformation function that ensures the base <c>"VerifiableCredential"</c> type
    /// is present in the credential's type array.
    /// </summary>
    /// <typeparam name="TBuilder">The type of the builder implementing <see cref="IBuilder"/>.</typeparam>
    /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
    /// <returns>
    /// A transformation function that can be used with <see cref="Builder{TResult, TState, TBuilder}.With"/>
    /// to ensure the base type is present.
    /// </returns>
    public static Func<VerifiableCredential, TBuilder, TState?, VerifiableCredential>
        CreateEnsureBaseTypeTransformation<TBuilder, TState>()
        where TBuilder : IBuilder
    {
        return (credential, _, _) =>
        {
            credential.AddType(CredentialConstants.VerifiableCredentialType);

            return credential;
        };
    }


    /// <summary>
    /// Creates a transformation function that adds specified types to the credential.
    /// </summary>
    /// <typeparam name="TBuilder">The type of the builder implementing <see cref="IBuilder"/>.</typeparam>
    /// <typeparam name="TState">The type of the build state passed between transformations.</typeparam>
    /// <param name="types">The types to add to the credential.</param>
    /// <returns>
    /// A transformation function that can be used with <see cref="Builder{TResult, TState, TBuilder}.With"/>
    /// to add the specified types.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="types"/> is null.</exception>
    public static Func<VerifiableCredential, TBuilder, TState?, VerifiableCredential>
        CreateAddTypesTransformation<TBuilder, TState>(IEnumerable<string> types)
        where TBuilder : IBuilder
    {
        ArgumentNullException.ThrowIfNull(types);

        var typesList = types.ToList();

        return (credential, _, _) =>
        {
            foreach(var type in typesList)
            {
                credential.AddType(type);
            }

            return credential;
        };
    }
}