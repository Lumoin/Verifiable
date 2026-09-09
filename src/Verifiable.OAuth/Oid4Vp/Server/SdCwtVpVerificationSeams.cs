using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// The CBOR/COSE serialization seams <see cref="SdCwtVpTokenVerification.VerifyAsync"/>
/// needs, bundled so the OID4VP executor can be constructed with SD-CWT support as one
/// cohesive parameter rather than nine loose delegates.
/// </summary>
/// <remarks>
/// <para>
/// Verifiable.OAuth carries no serialization dependency (the layering rule enforced by
/// BannedSymbols.Serialization). Every member here is a delegate the application wires to
/// a concrete implementation in <c>Verifiable.Cbor.Sd</c> / <c>Verifiable.Cbor</c> /
/// <c>Verifiable.JCose</c> at composition time — the same seam pattern the SD-JWT and
/// mdoc paths use. Pass an instance to
/// <see cref="Verifiable.OAuth.Oid4Vp.HaipOid4VpVerifierExecutor.Create"/> to enable
/// <c>dc+sd-cwt</c> VP-token verification; leave it <see langword="null"/> for
/// deployments that do not accept SD-CWT.
/// </para>
/// <para>
/// The members mirror the parameters of
/// <see cref="Core.Model.SelectiveDisclosure.KbCwtVerification.VerifyAsync"/>, which this
/// carrier feeds. The SD-CWT holder binding is the Key Binding Token (KBT) COSE_Sign1;
/// there is no <c>sd_hash</c> and no SessionTranscript, so those axes report N/A.
/// </para>
/// </remarks>
public sealed record SdCwtVpVerificationSeams
{
    /// <summary>Parses the KBT COSE_Sign1. Wired to <c>CoseSerialization.ParseCoseSign1</c>.</summary>
    public required ParseCoseSign1Delegate ParseCoseSign1 { get; init; }

    /// <summary>
    /// Extracts the embedded SD-CWT from the KBT <c>kcwt</c> protected header. Wired to
    /// <c>SdCwtVpParsing.ExtractKcwt</c> — see <see cref="ExtractKcwtFromKbtDelegate"/>'s remarks for
    /// the <see cref="FormatException"/> contract that method carries at its public boundary.
    /// </summary>
    public required ExtractKcwtFromKbtDelegate ExtractKcwt { get; init; }

    /// <summary>
    /// Parses the embedded SD-CWT into an SdToken. Wired to <c>SdCwtVpParsing.ParseEmbeddedSdCwt</c> —
    /// see <see cref="ParseSdCwtTokenDelegate"/>'s remarks for the <see cref="FormatException"/>
    /// contract that method carries at its public boundary.
    /// </summary>
    public required ParseSdCwtTokenDelegate ParseSdCwt { get; init; }

    /// <summary>Reconstructs the holder key from the embedded SD-CWT <c>cnf</c> COSE_Key. Wired to <c>SdCwtVpParsing.ExtractHolderKey</c>.</summary>
    public required ExtractSdCwtHolderKeyDelegate ExtractHolderKey { get; init; }

    /// <summary>Reads the KBT payload <c>aud</c>/<c>iat</c>/<c>cnonce</c>. Wired to <c>SdCwtVpParsing.ReadKbtClaims</c>.</summary>
    public required ReadKbtCwtClaimsDelegate ReadKbtClaims { get; init; }

    /// <summary>Reads the <c>iss</c> claim from the embedded SD-CWT. Wired to <c>SdCwtVpParsing.ExtractIssuer</c>.</summary>
    public required ExtractSdCwtIssuerDelegate ExtractIssuer { get; init; }

    /// <summary>Reads the <c>vct</c> claim from the embedded SD-CWT. Wired to <c>SdCwtVpParsing.ExtractCredentialType</c>.</summary>
    public required ExtractSdCwtCredentialTypeDelegate ExtractCredentialType { get; init; }

    /// <summary>
    /// Reads the <c>status</c> claim (CWT claim 65535) from the embedded SD-CWT. Wired to
    /// <c>SdCwtVpParsing.ExtractStatus</c>.
    /// </summary>
    /// <remarks>
    /// Required rather than optional: a seat that cannot read the status claim cannot tell a
    /// credential whose issuer gated its validity on a status list apart from one that carries no
    /// status at all, and would admit a revoked credential without ever looking — the fail-open case
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">
    /// Token Status List, Section 8.3</see> step 1 exists to close: "Check for the existence of a
    /// status claim, check for the existence of a status_list claim within the status claim and
    /// validate that the content of status_list adheres to the rules defined in Section 6.2 for
    /// JOSE-based Referenced Tokens and Section 6.3 for COSE-based Referenced Tokens."
    /// </remarks>
    public required ExtractSdCwtStatusDelegate ExtractStatus { get; init; }

    /// <summary>Resolves the issuer verification key from its identifier (the application's trust framework).</summary>
    public required ResolveSdCwtIssuerKeyDelegate ResolveIssuerKey { get; init; }

    /// <summary>Verifies the embedded SD-CWT (issuer signature + per-disclosure digest binding). Wired over <c>SdCwtVerificationExtensions.VerifyAsync</c>.</summary>
    public required VerifySdCwtCredentialDelegate VerifyCredential { get; init; }

    /// <summary>Builds the COSE Sig_structure for the holder-signature check. Wired to <c>CoseSerialization.BuildSigStructure</c>.</summary>
    public required BuildSigStructureDelegate BuildSigStructure { get; init; }

    /// <summary>
    /// Optional: extracts the embedded SD-CWT's <c>x5chain</c> COSE header for OID4VP 1.0 §6.1.1
    /// trust evidence. Wired to <c>Verifiable.Cbor.CoseSign1X5ChainExtractor.Extract</c>.
    /// <see langword="null"/> when the deployment carries no certificate-chain evidence for
    /// SD-CWT issuers.
    /// </summary>
    public ExtractCoseSign1X5ChainDelegate? ExtractCoseSign1X5Chain { get; init; }

    /// <summary>
    /// Optional: resolves the OID4VP 1.0 §6.1.1 trust evidence from the embedded SD-CWT's
    /// certificate chain (when <see cref="ExtractCoseSign1X5Chain"/> is wired) and its verified
    /// <c>iss</c>, surfaced on <see cref="VpCredentialClaims.TrustedAuthorityEvidence"/>.
    /// <see langword="null"/> surfaces no evidence.
    /// </summary>
    public ResolveTrustedAuthorityEvidenceDelegate? ResolveTrustedAuthorityEvidence { get; init; }
}
