using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Represents a Digital Credentials Query Language (DCQL) query.
/// </summary>
/// <remarks>
/// <para>
/// DCQL is a JSON-encoded query language defined in the OpenID for Verifiable Presentations
/// specification. It allows verifiers to request specific credentials with precise claim
/// requirements and express constraints on credential combinations.
/// </para>
/// <para>
/// A DCQL query consists of:
/// <list type="bullet">
///   <item><description><see cref="Credentials"/> — individual credential requirements.</description></item>
///   <item><description><see cref="CredentialSets"/> — optional constraints on credential combinations.</description></item>
/// </list>
/// </para>
/// <para>
/// The system evaluates the query against stored credentials and returns
/// presentations that satisfy the requirements.
/// </para>
/// </remarks>
/// <example>
/// A query requesting either an SD-JWT identity credential or an mdoc driving license:
/// <code>
/// var query = new DcqlQuery
/// {
///     Credentials =
///     [
///         new CredentialQuery
///         {
///             Id = "identity",
///             Format = "dc+sd-jwt",
///             Meta = new CredentialQueryMeta
///             {
///                 VctValues = ["https://example.com/IdentityCredential"]
///             },
///             Claims =
///             [
///                 new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("given_name") },
///                 new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("family_name") }
///             ]
///         },
///         new CredentialQuery
///         {
///             Id = "mdl",
///             Format = "mso_mdoc",
///             Meta = new CredentialQueryMeta
///             {
///                 DoctypeValue = "org.iso.18013.5.1.mDL"
///             },
///             Claims =
///             [
///                 new ClaimsQuery { Path = DcqlClaimPattern.ForMdoc("org.iso.18013.5.1", "given_name") },
///                 new ClaimsQuery { Path = DcqlClaimPattern.ForMdoc("org.iso.18013.5.1", "family_name") }
///             ]
///         }
///     ],
///     CredentialSets =
///     [
///         new CredentialSetQuery
///         {
///             Options = [["identity"], ["mdl"]]
///         }
///     ]
/// };
/// </code>
/// </example>
[DebuggerDisplay("Credentials={Credentials.Count} CredentialSets={CredentialSets?.Count ?? 0}")]
public record DcqlQuery
{
    /// <summary>
    /// The JSON property name for <see cref="Credentials"/>.
    /// </summary>
    public const string CredentialsPropertyName = "credentials";

    /// <summary>
    /// The JSON property name for <see cref="CredentialSets"/>.
    /// </summary>
    public const string CredentialSetsPropertyName = "credential_sets";

    /// <summary>
    /// The credential queries specifying requirements for individual credentials.
    /// </summary>
    public IReadOnlyList<CredentialQuery>? Credentials { get; set; }

    /// <summary>
    /// Optional constraints on which combinations of credentials must be presented.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When specified, credential sets define which combinations of the requested
    /// credentials can satisfy the overall query. This enables expressing
    /// alternatives (OR) and requirements (AND) for multiple credentials.
    /// </para>
    /// <para>
    /// When not specified or empty, each credential query is evaluated independently,
    /// and the system may return any matching credentials.
    /// </para>
    /// </remarks>
    public IReadOnlyList<CredentialSetQuery>? CredentialSets { get; set; }
}