namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Extracts the authority identifier an mdoc IssuerAuth's certificate chain attests to —
/// the base64url <c>KeyIdentifier</c> of the leaf certificate's AuthorityKeyIdentifier
/// extension (OID4VP 1.0 §6.1.1.1, DCQL <c>trusted_authorities</c> type <c>aki</c>) — or
/// <see langword="null"/> when the IssuerAuth carries no x5chain or the leaf has no such
/// identifier.
/// </summary>
/// <remarks>
/// The verifier surfaces the result so the DCQL evaluator can enforce a
/// <c>trusted_authorities</c> (<c>aki</c>) constraint. Compose one with
/// <c>Verifiable.Cbor.Mdoc.MdocCborAuthorityIdentifierExtractor.Create</c>, mirroring how
/// <c>MdocCborIacaTrustResolver.Create</c> composes the
/// <see cref="ResolveMdocIssuerKeyDelegate"/> — both pull the x5chain out of the COSE_Sign1
/// unprotected header and keep the X.509 reading behind an application-wired delegate. The
/// memory pool for the x5chain extraction is captured by the factory, so this delegate takes
/// only the <see cref="MdocIssuerAuth"/>, matching the pool-free shape of
/// <see cref="ResolveMdocIssuerKeyDelegate"/>.
/// </remarks>
/// <param name="issuerAuth">The parsed IssuerAuth whose x5chain leaf supplies the identifier.</param>
/// <returns>The base64url AuthorityKeyIdentifier, or <see langword="null"/> when none is present.</returns>
public delegate string? ExtractMdocAuthorityIdentifierDelegate(MdocIssuerAuth issuerAuth);
