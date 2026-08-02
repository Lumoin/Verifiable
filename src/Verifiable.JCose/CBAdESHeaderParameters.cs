namespace Verifiable.JCose;

/// <summary>
/// CB-AdES header parameter labels — the CBOR integer labels
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see> assigns to the seven new signed (protected-header) parameters
/// of clause 5.2 and the <c>uHeaders</c> unsigned (unprotected-header) container of clause 5.3.1,
/// as registered in the IANA "COSE Header Parameters" registry (Annex B).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="X5ts"/> through <see cref="SigD"/> (labels 261-267) are signed header parameters:
/// each SHALL be part of the protected headers map when present, identified there by its integer
/// label (<see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.2.1</see>). <see cref="UHeaders"/> (label 268) is a
/// different kind of thing — the unprotected-header array TAG of clause 5.3.1, the exclusive
/// incorporation point for every unsigned CB-AdES component (<c>sigPSt</c>, counter signature,
/// <c>sigTst</c>, <c>valData</c>, <c>arcTst</c>, <c>refs</c>, <c>sigRTst</c>, <c>rfsTst</c>).
/// </para>
/// <para>
/// Label/tag assignments were cross-verified against three independent sources within the
/// document — Table 1's rendered pairing, the inline CDDL <c>_l</c> label assignments, and
/// Annex B's IANA registry entries — and all three agree.
/// </para>
/// <para>
/// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.2.1, Table 1</see> and
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, Annex B</see>.
/// </para>
/// </remarks>
public static class CBAdESHeaderParameters
{
    /// <summary>
    /// <c>x5ts</c> — an alternative certificate-reference mechanism to <c>x5t</c>/<c>x5chain</c>
    /// (RFC 9360): an ordered, minimum-length-2 array of <c>COSE_CertHash</c> references, index 0
    /// being the signing certificate. A signed header parameter that qualifies the signature.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.2</see>.
    /// </remarks>
    public const int X5ts = 261;

    /// <summary>
    /// <c>srCms</c> — the commitment(s) made by the signer, each a URI-identified commitment type
    /// with optional qualifiers. A signed header parameter that qualifies the COSE Payload.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.3</see>.
    /// </remarks>
    public const int SrCms = 262;

    /// <summary>
    /// <c>sigPl</c> — the geographical production place of the signature (a schema.org
    /// <c>PostalAddress</c>-shaped map, informative analogy only). A signed header parameter that
    /// qualifies the signer.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.4</see>.
    /// </remarks>
    public const int SigPl = 263;

    /// <summary>
    /// <c>srAts</c> — attributes the signer claims, has certified by an Attribute Authority, or
    /// has as third-party-signed assertions. A signed header parameter that qualifies the signer.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.5</see>.
    /// </remarks>
    public const int SrAts = 264;

    /// <summary>
    /// <c>adoTst</c> — one or more electronic time-stamps generated before signature production,
    /// whose message-imprint input is the COSE Payload. A signed header parameter that qualifies
    /// the COSE Payload.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.6</see>.
    /// </remarks>
    public const int AdoTst = 265;

    /// <summary>
    /// <c>sigPId</c> — an explicit identifier of a signature policy document, by digest plus
    /// optional qualifiers (<c>spURI</c>, <c>spUserNotice</c>, <c>spDSpec</c>). A signed header
    /// parameter that qualifies the signature.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.7.1</see>.
    /// </remarks>
    public const int SigPId = 266;

    /// <summary>
    /// <c>sigD</c> — a reference to, and build procedure for, one or more data objects detached
    /// from the COSE Payload. A signed header parameter, mandatory when the payload is detached
    /// and referenced via URI.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.2.8.1</see>.
    /// </remarks>
    public const int SigD = 267;

    /// <summary>
    /// <c>uHeaders</c> — the single CBOR-array unprotected-header container that holds ALL
    /// post-signature (unsigned) material, in strict append-only, incorporation order, each
    /// element CBOR-byte-string-wrapped. Unlike <see cref="X5ts"/> through <see cref="SigD"/>,
    /// this is NOT a signed header parameter — it lives in the unprotected headers map.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.3.1, Table 8</see>.
    /// </remarks>
    public const int UHeaders = 268;


    /// <summary>
    /// Determines whether <paramref name="label"/> is one of the eight CB-AdES-specific header
    /// parameter labels this registry defines (261-268).
    /// </summary>
    /// <param name="label">The CBOR header parameter label.</param>
    /// <returns><see langword="true"/> if <paramref name="label"/> is a CB-AdES label; otherwise, <see langword="false"/>.</returns>
    public static bool IsCBAdESLabel(int label) => label switch
    {
        X5ts => true,
        SrCms => true,
        SigPl => true,
        SrAts => true,
        AdoTst => true,
        SigPId => true,
        SigD => true,
        UHeaders => true,
        _ => false
    };


    /// <summary>
    /// Gets the wire (CDDL) parameter name for a CB-AdES header parameter label.
    /// </summary>
    /// <param name="label">The CBOR header parameter label.</param>
    /// <returns>The parameter name, or <see langword="null"/> if unknown.</returns>
    public static string? GetParameterName(int label) => label switch
    {
        X5ts => "x5ts",
        SrCms => "srCms",
        SigPl => "sigPl",
        SrAts => "srAts",
        AdoTst => "adoTst",
        SigPId => "sigPId",
        SigD => "sigD",
        UHeaders => "uHeaders",
        _ => null
    };
}
