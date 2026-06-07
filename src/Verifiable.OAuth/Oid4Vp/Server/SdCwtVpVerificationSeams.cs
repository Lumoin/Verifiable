using System.Diagnostics;
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
[DebuggerDisplay("SdCwtVpVerificationSeams")]
public sealed record SdCwtVpVerificationSeams
{
    /// <summary>Parses the KBT COSE_Sign1. Wired to <c>CoseSerialization.ParseCoseSign1</c>.</summary>
    public required ParseCoseSign1Delegate ParseCoseSign1 { get; init; }

    /// <summary>Extracts the embedded SD-CWT from the KBT <c>kcwt</c> protected header. Wired to <c>SdCwtVpParsing.ExtractKcwt</c>.</summary>
    public required ExtractKcwtFromKbtDelegate ExtractKcwt { get; init; }

    /// <summary>Parses the embedded SD-CWT into an SdToken. Wired to <c>SdCwtVpParsing.ParseEmbeddedSdCwt</c>.</summary>
    public required ParseSdCwtTokenDelegate ParseSdCwt { get; init; }

    /// <summary>Reconstructs the holder key from the embedded SD-CWT <c>cnf</c> COSE_Key. Wired to <c>SdCwtVpParsing.ExtractHolderKey</c>.</summary>
    public required ExtractSdCwtHolderKeyDelegate ExtractHolderKey { get; init; }

    /// <summary>Reads the KBT payload <c>aud</c>/<c>iat</c>/<c>cnonce</c>. Wired to <c>SdCwtVpParsing.ReadKbtClaims</c>.</summary>
    public required ReadKbtCwtClaimsDelegate ReadKbtClaims { get; init; }

    /// <summary>Reads the <c>iss</c> claim from the embedded SD-CWT. Wired to <c>SdCwtVpParsing.ExtractIssuer</c>.</summary>
    public required ExtractSdCwtIssuerDelegate ExtractIssuer { get; init; }

    /// <summary>Resolves the issuer verification key from its identifier (the application's trust framework).</summary>
    public required ResolveSdCwtIssuerKeyDelegate ResolveIssuerKey { get; init; }

    /// <summary>Verifies the embedded SD-CWT (issuer signature + per-disclosure digest binding). Wired over <c>SdCwtVerificationExtensions.VerifyAsync</c>.</summary>
    public required VerifySdCwtCredentialDelegate VerifyCredential { get; init; }

    /// <summary>Builds the COSE Sig_structure for the holder-signature check. Wired to <c>CoseSerialization.BuildSigStructure</c>.</summary>
    public required BuildSigStructureDelegate BuildSigStructure { get; init; }
}
