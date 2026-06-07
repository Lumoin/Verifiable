using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Extension methods for attaching signing configuration to a
/// <see cref="CredentialBuilder"/>.
/// </summary>
/// <remarks>
/// <para>
/// These extensions store typed configuration records on the builder. The
/// builder's <c>BuildAndSignAsync</c>, <c>BuildJwsAsync</c>, and
/// <c>BuildJwsFullAsync</c> methods read the stored config and apply the
/// matching signing operation after the credential is built.
/// </para>
/// <para>
/// Two securing mechanisms are supported:
/// </para>
/// <list type="bullet">
/// <item><description>Data Integrity proofs (embedded in the credential JSON).</description></item>
/// <item><description>JOSE/JWS envelopes (credential becomes the JWS payload).</description></item>
/// </list>
/// <para>
/// Building and signing are kept as separate concerns. The fold over
/// <c>WithActions</c> assembles the credential; signing is a post-build
/// operation that reads its configuration from the builder. Configuration is
/// fixed across calls; per-call parameters (issuer, subject, validity period,
/// additional types) are supplied at build time.
/// </para>
/// <para>
/// <strong>Time handling.</strong>
#pragma warning disable RS0030 // Banned API referenced in documentation only.
/// All timestamps are provided explicitly by the caller via the build-method
/// parameters and the configuration record's
/// <see cref="DataIntegritySigningConfig.ProofCreated"/> field. The library
/// does not consult <see cref="DateTime.UtcNow"/> or
/// <see cref="System.TimeProvider"/>; this preserves deterministic testing
/// and explicit control over time sources.
#pragma warning restore RS0030
/// </para>
/// <para>
/// <strong>Closure-free.</strong>
/// These methods deliberately do not capture parameters into lambdas. The
/// configuration record is the boundary between caller and builder; reads at
/// signing time go through builder fields, not through captured locals.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with latest syntax.")]
public static class CredentialBuilderExtensions
{
    extension(CredentialBuilder builder)
    {
        /// <summary>
        /// Stores Data Integrity signing configuration on the builder. The
        /// configuration is applied by
        /// <see cref="CredentialBuilder.BuildAndSignAsync(Issuer, CredentialSubjectInput, DateTime, System.Collections.Generic.IEnumerable{string}?, DateTime?, string?, System.Threading.CancellationToken)"/>.
        /// </summary>
        /// <param name="config">
        /// The signing configuration. Calling this method again replaces the
        /// previously stored configuration; only one Data Integrity
        /// configuration is held at a time.
        /// </param>
        /// <returns>The builder instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="config"/> is <see langword="null"/>.
        /// </exception>        
        public CredentialBuilder WithDataIntegritySigning(DataIntegritySigningConfig config)
        {
            ArgumentNullException.ThrowIfNull(config);
            builder.DataIntegritySigning = config;

            return builder;
        }


        /// <summary>
        /// Stores JWS-envelope (JOSE) signing configuration on the builder.
        /// The configuration is applied by
        /// <see cref="CredentialBuilder.BuildJwsAsync(Issuer, CredentialSubjectInput, DateTime, System.Threading.CancellationToken)"/>
        /// and
        /// <see cref="CredentialBuilder.BuildJwsFullAsync(Issuer, CredentialSubjectInput, DateTime, System.Collections.Generic.IEnumerable{string}?, DateTime?, System.Threading.CancellationToken)"/>.
        /// </summary>
        /// <param name="config">
        /// The signing configuration. Calling this method again replaces the
        /// previously stored configuration; only one JOSE configuration is
        /// held at a time.
        /// </param>
        /// <returns>The builder instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="config"/> is <see langword="null"/>.
        /// </exception>
        /// <remarks>
        /// A single configuration covers both
        /// <see cref="CredentialBuilder.BuildJwsAsync(Issuer, CredentialSubjectInput, DateTime, System.Threading.CancellationToken)"/>
        /// (no additional types or expiration) and
        /// <see cref="CredentialBuilder.BuildJwsFullAsync(Issuer, CredentialSubjectInput, DateTime, System.Collections.Generic.IEnumerable{string}?, DateTime?, System.Threading.CancellationToken)"/>
        /// (with additional types and expiration). The choice between them is
        /// at the call site, not in the configuration.
        /// </remarks>        
        public CredentialBuilder WithJoseSigning(JoseSigningConfig config)
        {
            ArgumentNullException.ThrowIfNull(config);
            builder.JoseSigning = config;

            return builder;
        }
    }
}
