using Verifiable.Core.Dcql;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// Selects the subset of an SD-JWT VC credential's disclosures to reveal in a
/// presentation.
/// </summary>
/// <remarks>
/// <para>
/// The wallet client calls this delegate with the chosen credential and the
/// prepared DCQL query, and the delegate returns the set of disclosure claim
/// names to include in the presentation. Disclosures not in the returned set
/// are omitted; the corresponding claim digest in the SD-JWT is unresolved on
/// the Verifier side per
/// <see href="https://www.rfc-editor.org/rfc/rfc9900">RFC 9900</see>.
/// </para>
/// <para>
/// When the delegate is <see langword="null"/>, the wallet client reveals every
/// disclosure the credential carries — the maximal-disclosure default.
/// Applications that need minimal disclosure compute the strict set from the
/// query's claim paths.
/// </para>
/// </remarks>
/// <typeparam name="TCredential">
/// The application-supplied credential type. For SD-JWT VC use
/// <see cref="SdJwtVcCredential"/> or a derived type.
/// </typeparam>
/// <param name="credential">The credential the wallet selected for presentation.</param>
/// <param name="preparedQuery">The prepared DCQL query from the inbound JAR.</param>
/// <returns>The set of disclosure claim names to reveal.</returns>
public delegate IReadOnlySet<string> DisclosureSelectionDelegate<TCredential>(
    TCredential credential,
    PreparedDcqlQuery preparedQuery);
