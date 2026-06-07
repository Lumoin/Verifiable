namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// The wallet pipeline's single drop-out point: given the request-derived
/// <see cref="Oid4VpPresentationContext"/>, the application produces the
/// per-credential-query presentations (and any response-envelope binding) for
/// the <c>vp_token</c>.
/// </summary>
/// <remarks>
/// <para>
/// This is where the application's credential logic lives. Behind it the
/// application runs the wirable Core disclosure engine — <c>DcqlEvaluator</c>
/// to match its held credentials against <see cref="Oid4VpPresentationContext.PreparedQuery"/>,
/// then <c>DisclosureComputation.ComputeAsync</c> for the minimal disclosure
/// decision (lattice + policy assessors + user exclusions) — and the
/// format primitives to build each presentation: SD-JWT VC
/// (<c>SelectDisclosures</c> + <c>KbJwtIssuance</c>), mdoc (<c>MdocDocument.Derive</c>
/// + device-sign + DeviceResponse), or SD-CWT (<c>KbCwtIssuance</c>). The
/// application references the serialization and engine assemblies freely;
/// <c>Verifiable.OAuth</c> only defines this seam and drives the OID4VP
/// protocol mechanics (vp_token assembly, response encryption, POST, PDA).
/// </para>
/// <para>
/// The application holds its own credentials, holder/device keys, and
/// disclosure policy by closure — the wallet client passes only the
/// request-derived facts. The returned <see cref="Oid4VpPresentationSet"/> keys
/// presentations by DCQL credential query id and carries the optional
/// <c>apu</c> binding (mdoc only).
/// </para>
/// </remarks>
/// <param name="context">The request-derived presentation inputs.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The per-query presentations and any response-envelope binding.</returns>
public delegate ValueTask<Oid4VpPresentationSet> ProduceVpTokenPresentationsDelegate(
    Oid4VpPresentationContext context,
    CancellationToken cancellationToken);
