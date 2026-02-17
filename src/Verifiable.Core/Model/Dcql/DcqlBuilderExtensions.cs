using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Provides extension members for <see cref="DcqlQueryBuilder"/> and related types,
/// adding named transformation methods for common DCQL query construction patterns.
/// </summary>
/// <remarks>
/// <para>
/// This class follows the same pattern as <c>DidBuilderExtensions</c>: the builder
/// remains focused on the fold/aggregate mechanics while these extensions provide
/// domain-specific, composable construction methods. Each method adds a transformation
/// via <see cref="Verifiable.Core.Model.Common.Builder{TResult, TState, TBuilder}.With"/>
/// that modifies the <see cref="DcqlQueryBuildState"/> during the fold.
/// </para>
/// <para>
/// Vertical-specific extensions (e.g., EUDI, healthcare, transport) can be added in
/// separate extension classes that follow the same pattern, composing into the same
/// builder pipeline.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not yet up to date with new extension syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "Analyzer is not yet up to date with new extension syntax.")]
public static class DcqlBuilderExtensions
{
    /// <summary>
    /// Extensions for <see cref="DcqlQueryBuilder"/> providing named transformations
    /// for adding credentials, credential sets, and other query components.
    /// </summary>
    extension(DcqlQueryBuilder builder)
    {
        /// <summary>
        /// Adds a transformation that registers a credential query in the build state.
        /// </summary>
        /// <param name="credential">The credential query to add.</param>
        /// <returns>This builder instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="credential"/> is null.
        /// </exception>
        public DcqlQueryBuilder WithCredential(CredentialQuery credential)
        {
            ArgumentNullException.ThrowIfNull(credential);

            return builder.With((query, bldr, state) =>
            {
                state!.AddCredential(credential);

                return ValueTask.FromResult(query);
            });
        }

        /// <summary>
        /// Adds a transformation that registers an SD-JWT credential query with the given claims.
        /// </summary>
        /// <param name="id">The credential query identifier.</param>
        /// <param name="claims">The claims to request.</param>
        /// <returns>This builder instance for method chaining.</returns>
        /// <example>
        /// <code>
        /// var builder = new DcqlQueryBuilder()
        ///     .WithSdJwtCredential("pid",
        ///         ClaimsQuery.ForPath("given_name"),
        ///         ClaimsQuery.ForPath("family_name"));
        /// </code>
        /// </example>
        public DcqlQueryBuilder WithSdJwtCredential(string id, ClaimsQuery[] claims)
        {
            ArgumentNullException.ThrowIfNull(id);
            ArgumentNullException.ThrowIfNull(claims);

            return builder.WithCredential(new CredentialQuery
            {
                Id = id,
                Format = DcqlCredentialFormats.SdJwt,
                Claims = claims.Length > 0 ? claims : null
            });
        }

        /// <summary>
        /// Adds a transformation that registers an SD-JWT credential query with type
        /// constraints and claims.
        /// </summary>
        /// <param name="id">The credential query identifier.</param>
        /// <param name="vctValues">The acceptable Verifiable Credential Type values.</param>
        /// <param name="claims">The claims to request.</param>
        /// <returns>This builder instance for method chaining.</returns>
        /// <example>
        /// <code>
        /// var builder = new DcqlQueryBuilder()
        ///     .WithSdJwtCredential("identity",
        ///         ["https://credentials.example/identity_credential"],
        ///         new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("given_name") });
        /// </code>
        /// </example>
        public DcqlQueryBuilder WithSdJwtCredential(string id, IReadOnlyList<string> vctValues, ClaimsQuery[] claims)
        {
            ArgumentNullException.ThrowIfNull(id);
            ArgumentNullException.ThrowIfNull(vctValues);
            ArgumentNullException.ThrowIfNull(claims);

            return builder.WithCredential(new CredentialQuery
            {
                Id = id,
                Format = DcqlCredentialFormats.SdJwt,
                Meta = new CredentialQueryMeta { VctValues = vctValues },
                Claims = claims.Length > 0 ? claims : null
            });
        }

        /// <summary>
        /// Adds a transformation that registers an ISO mdoc credential query with
        /// the given doctype and claims.
        /// </summary>
        /// <param name="builder">The builder instance.</param>
        /// <param name="id">The credential query identifier.</param>
        /// <param name="doctypeValue">The required mdoc document type.</param>
        /// <param name="claims">The claims to request.</param>
        /// <returns>This builder instance for method chaining.</returns>
        /// <example>
        /// <code>
        /// var builder = new DcqlQueryBuilder()
        ///     .WithMdocCredential("mdl", "org.iso.18013.5.1.mDL",
        ///         ClaimsQuery.ForMdocPath(true, "org.iso.18013.5.1", "family_name"),
        ///         ClaimsQuery.ForMdocPath(true, "org.iso.18013.5.1", "given_name"));
        /// </code>
        /// </example>
        public DcqlQueryBuilder WithMdocCredential(string id, string doctypeValue, ClaimsQuery[] claims)
        {
            ArgumentNullException.ThrowIfNull(id);
            ArgumentNullException.ThrowIfNull(doctypeValue);
            ArgumentNullException.ThrowIfNull(claims);

            return builder.WithCredential(new CredentialQuery
            {
                Id = id,
                Format = DcqlCredentialFormats.MsoMdoc,
                Meta = new CredentialQueryMeta { DoctypeValue = doctypeValue },
                Claims = claims.Length > 0 ? claims : null
            });
        }

        /// <summary>
        /// Adds a transformation that registers a W3C JSON-LD credential query.
        /// </summary>
        /// <param name="id">The credential query identifier.</param>
        /// <param name="claims">The claims to request.</param>
        /// <returns>This builder instance for method chaining.</returns>
        public DcqlQueryBuilder WithLdpVcCredential(string id, ClaimsQuery[] claims)
        {
            ArgumentNullException.ThrowIfNull(id);
            ArgumentNullException.ThrowIfNull(claims);

            return builder.WithCredential(new CredentialQuery
            {
                Id = id,
                Format = DcqlCredentialFormats.LdpVc,
                Claims = claims.Length > 0 ? claims : null
            });
        }

        /// <summary>
        /// Adds a transformation that registers a credential set defining which
        /// combinations of credentials can satisfy the query.
        /// </summary>
        /// <param name="required">Whether satisfying this credential set is required.</param>
        /// <param name="options">
        /// Alternative groups of credential IDs. Each array is a group where all credentials
        /// must be presented together. The query succeeds if any single group is fully satisfied.
        /// </param>
        /// <returns>This builder instance for method chaining.</returns>
        /// <example>
        /// <code>
        /// // "Present PID alone, or both email and phone together."
        /// builder.WithCredentialSet(true, ["pid"], ["email", "phone"]);
        /// </code>
        /// </example>
        public DcqlQueryBuilder WithCredentialSet(bool required, string[][] options)
        {
            ArgumentNullException.ThrowIfNull(options);

            return builder.With((query, bldr, state) =>
            {
                state!.AddCredentialSet(new CredentialSetQuery
                {
                    Options = options
                        .Select(o => (IReadOnlyList<string>)o.ToList().AsReadOnly())
                        .ToList()
                        .AsReadOnly(),
                    Required = required
                });

                return ValueTask.FromResult(query);
            });
        }

        /// <summary>
        /// Adds a transformation that registers a credential set with a purpose description.
        /// </summary>
        /// <param name="required">Whether satisfying this credential set is required.</param>
        /// <param name="purpose">A human-readable description of why these credentials are requested.</param>
        /// <param name="options">Alternative groups of credential IDs.</param>
        /// <returns>This builder instance for method chaining.</returns>
        public DcqlQueryBuilder WithCredentialSet(bool required, string purpose, string[][] options)
        {
            ArgumentNullException.ThrowIfNull(purpose);
            ArgumentNullException.ThrowIfNull(options);

            return builder.With((query, bldr, state) =>
            {
                state!.AddCredentialSet(new CredentialSetQuery
                {
                    Options = options
                        .Select(o => (IReadOnlyList<string>)o.ToList().AsReadOnly())
                        .ToList()
                        .AsReadOnly(),
                    Required = required,
                    Purpose = purpose
                });

                return ValueTask.FromResult(query);
            });
        }
    }


    /// <summary>
    /// Extensions for <see cref="ClaimsQuery"/> providing static factory methods
    /// for common claim path patterns.
    /// </summary>
    extension(ClaimsQuery)
    {
        /// <summary>
        /// Creates a claim query for a simple property path. Each string becomes
        /// a <see cref="PatternSegment.Key"/> segment.
        /// </summary>
        /// <param name="keys">One or more property name keys forming the path.</param>
        /// <returns>A new claim query with a concrete key-only path.</returns>
        /// <example>
        /// <code>
        /// var claim = ClaimsQuery.ForPath("credentialSubject", "email");
        /// </code>
        /// </example>
        public static ClaimsQuery ForPath(string[] keys)
        {
            return new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(keys) };
        }

        /// <summary>
        /// Creates a claim query for a property path constrained to specific values.
        /// </summary>
        /// <param name="keys">The property name keys forming the path.</param>
        /// <param name="values">The acceptable values for the claim.</param>
        /// <returns>A new claim query with path and value constraints.</returns>
        /// <example>
        /// <code>
        /// var claim = ClaimsQuery.ForPathWithValues(
        ///     ["issuer"],
        ///     "did:web:university.example", "did:web:college.example");
        /// </code>
        /// </example>
        public static ClaimsQuery ForPathWithValues(string[] keys, object[] values)
        {
            ArgumentNullException.ThrowIfNull(keys);
            ArgumentNullException.ThrowIfNull(values);

            return new ClaimsQuery
            {
                Path = DcqlClaimPattern.FromKeys(keys),
                Values = values
            };
        }

        /// <summary>
        /// Creates a claim query with a wildcard array traversal. Null elements in the
        /// segment list become <see cref="PatternSegment.Wildcard"/> segments, matching
        /// any array element at that position.
        /// </summary>
        /// <param name="segments">
        /// The path segments. Non-null strings become key segments, null values
        /// become wildcard segments.
        /// </param>
        /// <returns>A new claim query with a wildcard-containing path.</returns>
        /// <example>
        /// <code>
        /// // Matches credential.citizenship[*].country.
        /// var claim = ClaimsQuery.ForWildcardPath("citizenship", null, "country");
        /// </code>
        /// </example>
        public static ClaimsQuery ForWildcardPath(string?[] segments)
        {
            ArgumentNullException.ThrowIfNull(segments);

            if(segments.Length == 0)
            {
                throw new ArgumentException("At least one segment is required.", nameof(segments));
            }

            var patternSegments = new PatternSegment[segments.Length];
            for(int i = 0; i < segments.Length; i++)
            {
                patternSegments[i] = segments[i] is not null
                    ? PatternSegment.Key(segments[i]!)
                    : PatternSegment.Wildcard();
            }

            return new ClaimsQuery { Path = new DcqlClaimPattern(patternSegments) };
        }

        /// <summary>
        /// Creates a claim query for an <c>mso_mdoc</c> element with the intent-to-retain flag.
        /// </summary>
        /// <param name="intentToRetain">Whether the verifier intends to retain this claim value.</param>
        /// <param name="nameSpace">The mdoc namespace (e.g., "org.iso.18013.5.1").</param>
        /// <param name="elementIdentifier">The element name (e.g., "family_name").</param>
        /// <returns>A new claim query with mdoc path and retention intent.</returns>
        /// <example>
        /// <code>
        /// var claim = ClaimsQuery.ForMdocPath(true, "org.iso.18013.5.1", "family_name");
        /// </code>
        /// </example>
        public static ClaimsQuery ForMdocPath(bool intentToRetain, string nameSpace, string elementIdentifier)
        {
            ArgumentNullException.ThrowIfNull(nameSpace);
            ArgumentNullException.ThrowIfNull(elementIdentifier);

            return new ClaimsQuery
            {
                Path = DcqlClaimPattern.ForMdoc(nameSpace, elementIdentifier),
                IntentToRetain = intentToRetain
            };
        }
    }


    /// <summary>
    /// Extensions for <see cref="DcqlQuery"/> providing static factory methods
    /// for common query shapes.
    /// </summary>
    extension(DcqlQuery)
    {
        /// <summary>
        /// Creates a DCQL query requesting a single credential.
        /// </summary>
        /// <param name="credential">The credential query to include.</param>
        /// <returns>A DCQL query containing one credential requirement.</returns>
        /// <example>
        /// <code>
        /// var query = DcqlQuery.Single(
        ///     new CredentialQuery
        ///     {
        ///         Id = "pid",
        ///         Format = DcqlCredentialFormats.SdJwt,
        ///         Claims = [ClaimsQuery.ForPath("given_name")]
        ///     });
        /// </code>
        /// </example>
        public static DcqlQuery Single(CredentialQuery credential)
        {
            ArgumentNullException.ThrowIfNull(credential);

            return new DcqlQuery { Credentials = [credential] };
        }

        /// <summary>
        /// Creates a DCQL query requesting multiple independent credentials.
        /// All listed credentials must be presented (no credential sets, implicit AND).
        /// </summary>
        /// <param name="credentials">The credential queries to include.</param>
        /// <returns>A DCQL query requiring all specified credentials.</returns>
        public static DcqlQuery All(CredentialQuery[] credentials)
        {
            ArgumentNullException.ThrowIfNull(credentials);

            return new DcqlQuery { Credentials = credentials };
        }
    }
}