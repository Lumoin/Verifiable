using System;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Core.Model.Common;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Represents input for creating a credential subject within a Verifiable Credential.
/// This encapsulates all the necessary information to create a credential subject.
/// </summary>
public class CredentialSubjectInput
{
    /// <summary>
    /// Gets or sets the optional identifier for the credential subject.
    /// When present, this should be a URI that uniquely identifies the subject.
    /// </summary>
    /// <remarks>
    /// Common forms include DIDs (e.g., <c>did:example:123</c>) or other URIs.
    /// If omitted, the credential makes claims about an unidentified subject.
    /// </remarks>
    public string? Id { get; init; }

    /// <summary>
    /// Gets or sets the claims to be made about this subject.
    /// These are the key-value pairs that form the credential's assertions.
    /// </summary>
    public IDictionary<string, object>? Claims { get; init; }
}


/// <summary>
/// Builds Verifiable Credentials using a fold/aggregate pattern with sensible defaults.
/// This builder follows the W3C Verifiable Credentials Data Model 2.0 specification
/// for creating credentials from issuer information and subject claims.
/// </summary>
/// <remarks>
/// <para>
/// The CredentialBuilder implements a fold/aggregate pattern where transformation functions
/// are applied sequentially to build up a complete Verifiable Credential. The builder provides
/// default transformations that:
/// </para>
/// <list type="number">
/// <item><description>Set up the JSON-LD context for VC 2.0.</description></item>
/// <item><description>Configure the credential types.</description></item>
/// <item><description>Set the issuer and validity period.</description></item>
/// <item><description>Create credential subjects with the specified claims.</description></item>
/// </list>
/// <para>
/// The builder supports reuse: configure transformations once, then call <c>Build</c> multiple
/// times with different parameters to create multiple credentials with similar structure.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/">
/// W3C Verifiable Credentials Data Model 2.0</see>.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// var builder = new CredentialBuilder();
/// var credential = builder.Build(
///     issuer: new Issuer { Id = "did:web:example.com" },
///     subjects: [new CredentialSubjectInput { Id = "did:example:123", Claims = claims }],
///     additionalTypes: ["UniversityDegreeCredential"]);
/// </code>
/// </example>
public sealed class CredentialBuilder: Builder<VerifiableCredential, CredentialBuildState, CredentialBuilder>
{
    /// <summary>
    /// Gets or sets the credential ID generator used to create unique identifiers for credentials.
    /// Defaults to generating URN:UUID identifiers.
    /// </summary>
    public CredentialIdGenerator CredentialIdGenerator { get; set; } = DefaultCredentialIdGenerator;


    /// <summary>
    /// Default credential ID generator that creates URN:UUID identifiers.
    /// </summary>
    public static CredentialIdGenerator DefaultCredentialIdGenerator { get; } = _ =>
        $"urn:uuid:{Guid.NewGuid()}";


    /// <summary>
    /// Alternative credential ID generator that creates HTTPS URL identifiers.
    /// Requires the issuer to have a resolvable domain.
    /// </summary>
    /// <param name="baseUrl">The base URL for credential identifiers.</param>
    /// <returns>A credential ID generator function.</returns>
    public static CredentialIdGenerator HttpsCredentialIdGenerator(string baseUrl) => _ =>
        $"{baseUrl.TrimEnd('/')}/credentials/{Guid.NewGuid()}";


    /// <summary>
    /// Initializes a new instance of the <see cref="CredentialBuilder"/> class with default transformations.
    /// The default configuration creates a compliant VC 2.0 credential with context, types, issuer,
    /// validity period, and credential subjects.
    /// </summary>
    public CredentialBuilder()
    {
        //First transformation: Set up JSON-LD context.
        _ = With((credential, builder, buildState) =>
        {
            credential.Context = CredentialConstants.DefaultVc20Context;

            return credential;
        })
        //Second transformation: Configure credential types.
        .With((credential, builder, buildState) =>
        {
            var types = new List<string> { CredentialConstants.VerifiableCredentialType };
            if(buildState.AdditionalTypes != null)
            {
                types.AddRange(buildState.AdditionalTypes);
            }

            credential.Type = types;

            return credential;
        })
        //Third transformation: Set issuer and validity period.
        .With((credential, builder, buildState) =>
        {
            credential.Issuer = buildState.Issuer;
            credential.ValidFrom = buildState.ValidFrom;
            credential.ValidUntil = buildState.ValidUntil;

            //Set credential ID if provided or generate one.
            credential.Id = buildState.CredentialId ?? builder.CredentialIdGenerator(buildState);

            return credential;
        })
        //Fourth transformation: Create credential subjects.
        .With((credential, builder, buildState) =>
        {
            if(buildState.Subjects != null && buildState.Subjects.Count > 0)
            {
                credential.CredentialSubject = buildState.Subjects.ToList();
            }

            return credential;
        });
    }


    /// <summary>
    /// Builds a Verifiable Credential from the provided parameters.
    /// </summary>
    /// <param name="issuer">The issuer of the credential.</param>
    /// <param name="subjects">The credential subject inputs containing claims.</param>
    /// <param name="additionalTypes">
    /// Additional credential types beyond the base <c>"VerifiableCredential"</c> type.
    /// </param>
    /// <param name="validFrom">
    /// The date and time from which the credential is valid.
    /// Defaults to the current UTC time if not specified.
    /// </param>
    /// <param name="validUntil">Optional expiration date and time for the credential.</param>
    /// <param name="credentialId">
    /// Optional identifier for the credential. If not specified, one will be generated.
    /// </param>
    /// <returns>A fully constructed Verifiable Credential.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="issuer"/> or <paramref name="subjects"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="subjects"/> is empty.
    /// </exception>
    /// <remarks>
    /// <para>
    /// This method creates a credential following the VC Data Model 2.0 specification.
    /// The credential will include:
    /// </para>
    /// <list type="bullet">
    /// <item><description>The VC 2.0 JSON-LD context.</description></item>
    /// <item><description>The specified types including <c>"VerifiableCredential"</c>.</description></item>
    /// <item><description>The issuer information.</description></item>
    /// <item><description>The validity period if specified.</description></item>
    /// <item><description>The credential subjects with their claims.</description></item>
    /// </list>
    /// </remarks>
    public VerifiableCredential Build(
        Issuer issuer,
        IEnumerable<CredentialSubjectInput> subjects,
        IEnumerable<string>? additionalTypes = null,
        DateTime? validFrom = null,
        DateTime? validUntil = null,
        string? credentialId = null)
    {
        ArgumentNullException.ThrowIfNull(issuer, nameof(issuer));
        ArgumentNullException.ThrowIfNull(subjects, nameof(subjects));

        var subjectsList = subjects.ToList();
        if(subjectsList.Count == 0)
        {
            throw new ArgumentException("At least one credential subject is required.", nameof(subjects));
        }

        //Convert inputs to CredentialSubject instances.
        var credentialSubjects = subjectsList.Select(input => new CredentialSubject
        {
            Id = input.Id,
            AdditionalData = input.Claims
        }).ToList();

        var additionalTypesList = additionalTypes?.ToList();

        //Create the build state for the fold/aggregate operation.
        CredentialBuildState buildState = new()
        {
            Issuer = issuer,
            ValidFrom = validFrom ?? DateTime.UtcNow,
            ValidUntil = validUntil,
            CredentialId = credentialId,
            AdditionalTypes = additionalTypesList,
            Subjects = credentialSubjects,
            CurrentSubjectIndex = 0
        };

        return Build(
            param: subjectsList,
            preBuildAction: (_, _) => buildState);
    }


    /// <summary>
    /// Builds a Verifiable Credential with a single subject from the provided parameters.
    /// This is a convenience method for single-subject credentials.
    /// </summary>
    /// <param name="issuer">The issuer of the credential.</param>
    /// <param name="subject">The credential subject input containing claims.</param>
    /// <param name="additionalTypes">
    /// Additional credential types beyond the base <c>"VerifiableCredential"</c> type.
    /// </param>
    /// <param name="validFrom">
    /// The date and time from which the credential is valid.
    /// Defaults to the current UTC time if not specified.
    /// </param>
    /// <param name="validUntil">Optional expiration date and time for the credential.</param>
    /// <param name="credentialId">
    /// Optional identifier for the credential. If not specified, one will be generated.
    /// </param>
    /// <returns>A fully constructed Verifiable Credential.</returns>
    public VerifiableCredential Build(
        Issuer issuer,
        CredentialSubjectInput subject,
        IEnumerable<string>? additionalTypes = null,
        DateTime? validFrom = null,
        DateTime? validUntil = null,
        string? credentialId = null)
    {
        ArgumentNullException.ThrowIfNull(subject, nameof(subject));

        return Build(issuer, [subject], additionalTypes, validFrom, validUntil, credentialId);
    }


    /// <summary>
    /// Builds a Verifiable Credential using a pre-configured seed credential.
    /// This allows starting with a partially configured credential.
    /// </summary>
    /// <param name="seedCredential">The pre-configured credential to use as a starting point.</param>
    /// <param name="issuer">The issuer of the credential.</param>
    /// <param name="subjects">The credential subject inputs containing claims.</param>
    /// <param name="additionalTypes">
    /// Additional credential types beyond the base <c>"VerifiableCredential"</c> type.
    /// </param>
    /// <param name="validFrom">
    /// The date and time from which the credential is valid.
    /// Defaults to the current UTC time if not specified.
    /// </param>
    /// <param name="validUntil">Optional expiration date and time for the credential.</param>
    /// <param name="credentialId">
    /// Optional identifier for the credential. If not specified, one will be generated.
    /// </param>
    /// <returns>A fully constructed Verifiable Credential.</returns>
    public VerifiableCredential Build(
        VerifiableCredential seedCredential,
        Issuer issuer,
        IEnumerable<CredentialSubjectInput> subjects,
        IEnumerable<string>? additionalTypes = null,
        DateTime? validFrom = null,
        DateTime? validUntil = null,
        string? credentialId = null)
    {
        ArgumentNullException.ThrowIfNull(seedCredential, nameof(seedCredential));
        ArgumentNullException.ThrowIfNull(issuer, nameof(issuer));
        ArgumentNullException.ThrowIfNull(subjects, nameof(subjects));

        var subjectsList = subjects.ToList();
        if(subjectsList.Count == 0)
        {
            throw new ArgumentException("At least one credential subject is required.", nameof(subjects));
        }

        var credentialSubjects = subjectsList.Select(input => new CredentialSubject
        {
            Id = input.Id,
            AdditionalData = input.Claims
        }).ToList();

        var additionalTypesList = additionalTypes?.ToList();

        CredentialBuildState buildState = new()
        {
            Issuer = issuer,
            ValidFrom = validFrom ?? DateTime.UtcNow,
            ValidUntil = validUntil,
            CredentialId = credentialId,
            AdditionalTypes = additionalTypesList,
            Subjects = credentialSubjects,
            CurrentSubjectIndex = 0
        };

        return Build(
            seedGenerator: _ => seedCredential,
            seedGeneratorParameter: subjectsList,
            preBuildAction: (_, _) => buildState);
    }
}


/// <summary>
/// Delegate for generating credential identifiers.
/// </summary>
/// <param name="state">The current build state.</param>
/// <returns>A unique identifier for the credential.</returns>
public delegate string CredentialIdGenerator(CredentialBuildState state);