using Verifiable.Cryptography.Text;


namespace Verifiable.JCose;

/// <summary>
/// JAdES-specific JOSE header parameter NAMES — the string keys clause 5.2 newly defines for JAdES signatures,
/// plus <c>etsiU</c> (clause 4/5.3.1), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>. Wire NAMES only — no serialization shape lives here; the signed-component
/// MODELS these names key are homed in <c>Verifiable.Cryptography.Pki</c>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Reuse, never duplicate.</strong> A name clause 5.1 profiles that RFC 7515/7519/7797 (or this
/// library's own registries) already define is REUSED here, not re-declared: <c>iat</c> is
/// <see cref="WellKnownJwtClaimNames.Iat"/> (RFC 7519 §4.1.6 — clause 5.1.11 profiles it as the mandatory
/// signed claimed-signing-time parameter for creation as of 2025-07-15T00:00:00Z, a date already passed;
/// JA-5.1.11-08); <c>cty</c>/<c>b64</c> are <see cref="WellKnownJoseHeaderNames.Cty"/>/
/// <see cref="WellKnownJoseHeaderNames.B64"/>; <c>x5t</c>/<c>x5t#S256</c>/<c>x5u</c>/<c>x5c</c> are
/// <see cref="WellKnownJwkMemberNames.X5t"/>/<see cref="WellKnownJwkMemberNames.X5tHashS256"/>/
/// <see cref="WellKnownJwkMemberNames.X5u"/>/<see cref="WellKnownJwkMemberNames.X5c"/>. This class registers
/// only the names genuinely new to JAdES: <see cref="SigT"/> (clause 5.2.1 — legacy/validation-only,
/// never emitted by a creation surface built against the present spec version), <see cref="X5tHashO"/> and
/// <see cref="SigX5ts"/> (clause 5.2.2 — alternative signing-certificate-reference mechanisms adjacent to the
/// <c>x5t#S256</c> family), <see cref="SrCms"/>, <see cref="SigPl"/>, <see cref="SrAts"/>, <see cref="AdoTst"/>,
/// <see cref="SigPId"/>, <see cref="SigD"/> (plus its own member names — <see cref="MId"/>, <see cref="Pars"/>,
/// <see cref="HashM"/>, <see cref="HashV"/>, <see cref="Ctys"/>), and <see cref="EtsiU"/>.
/// </para>
/// <para>
/// <strong>A capitalization typo, ruled.</strong> Clause 5.2.1's own prose spells the
/// replacement parameter's name "iaT" once ("Instead, the iaT header parameter should be included") against
/// four lowercase "iat" occurrences elsewhere on the same page — a capitalization typo, ruled read as
/// lowercase <c>iat</c>, i.e. <see cref="WellKnownJwtClaimNames.Iat"/>; no separate constant is needed or
/// created for the typo'd spelling.
/// </para>
/// <para>
/// <strong><c>etsiU</c> is name-only here.</strong> It is the single member the JWS Unprotected Header may
/// carry (JA-4-04) — clause 5.3's unsigned-component array, whose element MODEL and dual-mode (clear-JSON vs.
/// base64url-opaque) carriage is modeled elsewhere. This class's scope is
/// the signed-component models and their header names, so only the wire name is registered on this class.
/// </para>
/// </remarks>
public static class WellKnownJAdESHeaderNames
{
    /// <summary>The UTF-8 source literal of <see cref="SigT"/>.</summary>
    public static ReadOnlySpan<byte> SigTUtf8 => "sigT"u8;

    /// <summary>
    /// The <c>sigT</c> (claimed signing time) signed header parameter per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.1</see> (JA-5.2.1-01/-02). RFC 3339 UTC, no fractional seconds
    /// (JA-5.2.1-04/-05/-06). Superseded by <see cref="WellKnownJwtClaimNames.Iat"/> as of
    /// 2025-07-15T00:00:00Z — a date already passed — at which point <c>sigT</c> SHALL NOT be incorporated in
    /// new JAdES signatures (JA-5.2.1-09); a validating surface must still parse and process it
    /// (JA-5.2.1-10) since pre-cutover signatures remain valid to verify.
    /// </summary>
    public static readonly string SigT = Utf8Constants.ToInternedString(SigTUtf8);

    /// <summary>The UTF-8 source literal of <see cref="X5tHashO"/>.</summary>
    public static ReadOnlySpan<byte> X5tHashOUtf8 => "x5t#o"u8;

    /// <summary>
    /// The <c>x5t#o</c> (X.509 certificate digest, other algorithm) signed header parameter per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.2.2</see> (JA-5.2.2.2-01). Carries a digest-algorithm identifier
    /// OTHER than SHA-256 (SHA-256 is <c>x5t#S256</c>'s own role) plus the digest value of the signing
    /// certificate, and nothing else (JA-5.2.2.2-02/-03). One of the four disjunctive signing-certificate
    /// identification options a JAdES signature must carry at least one of, alongside <c>x5t#S256</c>,
    /// <c>x5c</c>, and <see cref="SigX5ts"/> (JA-5.1.7-04).
    /// </summary>
    public static readonly string X5tHashO = Utf8Constants.ToInternedString(X5tHashOUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SigX5ts"/>.</summary>
    public static ReadOnlySpan<byte> SigX5tsUtf8 => "sigX5ts"u8;

    /// <summary>
    /// The <c>sigX5ts</c> (X.509 certificates digests) signed header parameter per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.2.3</see> (JA-5.2.2.3-01). An array of at least two certificate
    /// digest references spanning the certification path, the first being the signing certificate
    /// (JA-5.2.2.3-02/-03), and nothing else (JA-5.2.2.3-04). One of <c>x5t#S256</c>/<c>x5c</c>/
    /// <see cref="X5tHashO"/>/<c>sigX5ts</c>'s four disjunctive signing-certificate-identification options
    /// (JA-5.1.7-04).
    /// </summary>
    public static readonly string SigX5ts = Utf8Constants.ToInternedString(SigX5tsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SrCms"/>.</summary>
    public static ReadOnlySpan<byte> SrCmsUtf8 => "srCms"u8;

    /// <summary>
    /// The <c>srCms</c> (signer commitments) signed header parameter per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.3</see> (JA-5.2.3-01/-02). Qualifies the JWS Payload; each array
    /// element expresses a URI-typed commitment type with optional qualifiers (JA-5.2.3-03, -M1). Carried in
    /// the JWS Protected Header (JA-5.2.3-04).
    /// </summary>
    public static readonly string SrCms = Utf8Constants.ToInternedString(SrCmsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SigPl"/>.</summary>
    public static ReadOnlySpan<byte> SigPlUtf8 => "sigPl"u8;

    /// <summary>
    /// The <c>sigPl</c> (signature production place) signed header parameter per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.4</see> (JA-5.2.4-01/-02). A schema.org <c>PostalAddress</c>-shaped
    /// map (informative analogy only) qualifying the signer, carried in the JWS Protected Header
    /// (JA-5.2.4-03/-06).
    /// </summary>
    public static readonly string SigPl = Utf8Constants.ToInternedString(SigPlUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SrAts"/>.</summary>
    public static ReadOnlySpan<byte> SrAtsUtf8 => "srAts"u8;

    /// <summary>
    /// The <c>srAts</c> (signer attributes) signed header parameter per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.5</see> (JA-5.2.5-01/-02). Qualifies the signer; encapsulates
    /// claimed attributes, Attribute-Authority-certified attributes, and/or third-party-signed assertions
    /// (JA-5.2.5-M1), never empty (JA-5.2.5-18). Carried in the JWS Protected Header (JA-5.2.5-03).
    /// </summary>
    public static readonly string SrAts = Utf8Constants.ToInternedString(SrAtsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AdoTst"/>.</summary>
    public static ReadOnlySpan<byte> AdoTstUtf8 => "adoTst"u8;

    /// <summary>
    /// The <c>adoTst</c> (signed data time-stamp) signed header parameter per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.6</see> (JA-5.2.6-01/-02). Qualifies the JWS Payload; one or more
    /// electronic time-stamps generated before signature production, whose message-imprint input is the JWS
    /// Payload (JA-5.2.6-03). A <c>tstContainer</c>-shaped value (clause 5.4.3) that shall never carry a
    /// <c>canonAlg</c> member (JA-5.2.6-08). Carried in the JWS Protected Header (JA-5.2.6-04).
    /// </summary>
    public static readonly string AdoTst = Utf8Constants.ToInternedString(AdoTstUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SigPId"/>.</summary>
    public static ReadOnlySpan<byte> SigPIdUtf8 => "sigPId"u8;

    /// <summary>
    /// The <c>sigPId</c> (signature policy identifier) signed header parameter per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.7.1</see> (JA-5.2.7.1-01). Carries either an explicit signature
    /// policy identifier (by digest) or an implied-policy indication (JA-5.2.7.1-02), qualifying the
    /// signature. Carried in the JWS Protected Header (JA-5.2.7.1-03).
    /// </summary>
    public static readonly string SigPId = Utf8Constants.ToInternedString(SigPIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SigD"/>.</summary>
    public static ReadOnlySpan<byte> SigDUtf8 => "sigD"u8;

    /// <summary>
    /// The <c>sigD</c> (detached data object reference) signed header parameter per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1</see> (JA-5.2.8.1-01). References one or more data objects
    /// detached from the JWS Payload and specifies how they build it (JA-5.2.8.1-04); never appears when the
    /// JWS Payload is attached (JA-5.2.8.1-02), only when detached (JA-5.2.8.1-M1); at most one per JWS
    /// Protected Header (JA-5.2.8.1-03). Its own members are <see cref="MId"/>, <see cref="Pars"/>,
    /// <see cref="HashM"/>, <see cref="HashV"/>, and <see cref="Ctys"/>. Three referencing mechanisms are
    /// defined against it — <c>HttpHeaders</c> (5.2.8.2, pure canonicalization over application-supplied HTTP
    /// facts, no dereferencing) and <c>ObjectIdByURI</c>/<c>ObjectIdByURIHash</c> (5.2.8.3.2/5.2.8.3.3, which
    /// share the dereferencing obligation centralized at 5.2.8.3.1).
    /// </summary>
    public static readonly string SigD = Utf8Constants.ToInternedString(SigDUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MId"/>.</summary>
    public static ReadOnlySpan<byte> MIdUtf8 => "mId"u8;

    /// <summary>
    /// The <c>mId</c> member of <see cref="SigD"/> per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1</see> (JA-5.2.8.1-13). Always present; a URI identifying the
    /// referencing/processing mechanism (JA-5.2.8.1-14) — <c>http://uri.etsi.org/19182/HttpHeaders</c>,
    /// <c>http://uri.etsi.org/19182/ObjectIdByURI</c>, or <c>http://uri.etsi.org/19182/ObjectIdByURIHash</c>.
    /// </summary>
    public static readonly string MId = Utf8Constants.ToInternedString(MIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Pars"/>.</summary>
    public static ReadOnlySpan<byte> ParsUtf8 => "pars"u8;

    /// <summary>
    /// The <c>pars</c> member of <see cref="SigD"/> per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1</see> (JA-5.2.8.1-15). Always present; a non-empty string
    /// array whose per-mechanism contents reference the detached data objects (JA-5.2.8.1-16/-17).
    /// </summary>
    public static readonly string Pars = Utf8Constants.ToInternedString(ParsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="HashM"/>.</summary>
    public static ReadOnlySpan<byte> HashMUtf8 => "hashM"u8;

    /// <summary>
    /// The <c>hashM</c> member of <see cref="SigD"/> per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1</see> (JA-5.2.8.1-18). A digest-algorithm identifier from RFC
    /// 7518 (JA-5.2.8.1-19); presence is conditional on the referencing mechanism (JA-5.2.8.1-20) and paired
    /// with <see cref="HashV"/> — each requires the other when present (JA-5.2.8.1-21/-25).
    /// </summary>
    public static readonly string HashM = Utf8Constants.ToInternedString(HashMUtf8);

    /// <summary>The UTF-8 source literal of <see cref="HashV"/>.</summary>
    public static ReadOnlySpan<byte> HashVUtf8 => "hashV"u8;

    /// <summary>
    /// The <c>hashV</c> member of <see cref="SigD"/> per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1</see> (JA-5.2.8.1-22). A non-empty base64url digest-value
    /// array, one entry per <see cref="Pars"/> position (JA-5.2.8.1-23); presence is conditional on the
    /// referencing mechanism (JA-5.2.8.1-24) and paired with <see cref="HashM"/>.
    /// </summary>
    public static readonly string HashV = Utf8Constants.ToInternedString(HashVUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Ctys"/>.</summary>
    public static ReadOnlySpan<byte> CtysUtf8 => "ctys"u8;

    /// <summary>
    /// The <c>ctys</c> member of <see cref="SigD"/> per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1</see> (JA-5.2.8.1-26). A string array, one entry per
    /// <see cref="Pars"/> position, each carrying the referenced data object's content-type information —
    /// the same semantics as <see cref="WellKnownJoseHeaderNames.Cty"/> per referenced object
    /// (JA-5.2.8.1-27/-28/-29).
    /// </summary>
    public static readonly string Ctys = Utf8Constants.ToInternedString(CtysUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EtsiU"/>.</summary>
    public static ReadOnlySpan<byte> EtsiUUtf8 => "etsiU"u8;

    /// <summary>
    /// The <c>etsiU</c> header parameter per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1, clause 4</see> (JA-4-04) and clause 5.3.1 — the single member the JWS
    /// Unprotected Header may carry, defined as a JSON array. Its elements play, for JAdES, the role the
    /// unsigned attributes play for CAdES and the unsigned qualifying properties play for XAdES. Its element
    /// MODEL and dual-mode carriage are out of this file's scope; only the wire
    /// name is registered here.
    /// </summary>
    public static readonly string EtsiU = Utf8Constants.ToInternedString(EtsiUUtf8);


    /// <summary>Whether <paramref name="name"/> is <see cref="SigT"/>.</summary>
    public static bool IsSigT(string name) => Equals(name, SigT);

    /// <summary>Whether <paramref name="name"/> is <see cref="X5tHashO"/>.</summary>
    public static bool IsX5tHashO(string name) => Equals(name, X5tHashO);

    /// <summary>Whether <paramref name="name"/> is <see cref="SigX5ts"/>.</summary>
    public static bool IsSigX5ts(string name) => Equals(name, SigX5ts);

    /// <summary>Whether <paramref name="name"/> is <see cref="SrCms"/>.</summary>
    public static bool IsSrCms(string name) => Equals(name, SrCms);

    /// <summary>Whether <paramref name="name"/> is <see cref="SigPl"/>.</summary>
    public static bool IsSigPl(string name) => Equals(name, SigPl);

    /// <summary>Whether <paramref name="name"/> is <see cref="SrAts"/>.</summary>
    public static bool IsSrAts(string name) => Equals(name, SrAts);

    /// <summary>Whether <paramref name="name"/> is <see cref="AdoTst"/>.</summary>
    public static bool IsAdoTst(string name) => Equals(name, AdoTst);

    /// <summary>Whether <paramref name="name"/> is <see cref="SigPId"/>.</summary>
    public static bool IsSigPId(string name) => Equals(name, SigPId);

    /// <summary>Whether <paramref name="name"/> is <see cref="SigD"/>.</summary>
    public static bool IsSigD(string name) => Equals(name, SigD);

    /// <summary>Whether <paramref name="name"/> is <see cref="MId"/>.</summary>
    public static bool IsMId(string name) => Equals(name, MId);

    /// <summary>Whether <paramref name="name"/> is <see cref="Pars"/>.</summary>
    public static bool IsPars(string name) => Equals(name, Pars);

    /// <summary>Whether <paramref name="name"/> is <see cref="HashM"/>.</summary>
    public static bool IsHashM(string name) => Equals(name, HashM);

    /// <summary>Whether <paramref name="name"/> is <see cref="HashV"/>.</summary>
    public static bool IsHashV(string name) => Equals(name, HashV);

    /// <summary>Whether <paramref name="name"/> is <see cref="Ctys"/>.</summary>
    public static bool IsCtys(string name) => Equals(name, Ctys);

    /// <summary>Whether <paramref name="name"/> is <see cref="EtsiU"/>.</summary>
    public static bool IsEtsiU(string name) => Equals(name, EtsiU);


    /// <summary>
    /// Returns the interned constant for a known JAdES-specific header parameter or <see cref="SigD"/>-member
    /// name, or the original string if unrecognized.
    /// </summary>
    public static string GetCanonicalizedValue(string name) => name switch
    {
        _ when IsSigT(name) => SigT,
        _ when IsX5tHashO(name) => X5tHashO,
        _ when IsSigX5ts(name) => SigX5ts,
        _ when IsSrCms(name) => SrCms,
        _ when IsSigPl(name) => SigPl,
        _ when IsSrAts(name) => SrAts,
        _ when IsAdoTst(name) => AdoTst,
        _ when IsSigPId(name) => SigPId,
        _ when IsSigD(name) => SigD,
        _ when IsMId(name) => MId,
        _ when IsPars(name) => Pars,
        _ when IsHashM(name) => HashM,
        _ when IsHashV(name) => HashV,
        _ when IsCtys(name) => Ctys,
        _ when IsEtsiU(name) => EtsiU,
        _ => name
    };


    /// <summary>
    /// Whether <paramref name="name"/> is one of the fifteen names this registry defines — the nine JAdES-new
    /// header parameters (<see cref="SigT"/>, <see cref="X5tHashO"/>, <see cref="SigX5ts"/>, <see cref="SrCms"/>,
    /// <see cref="SigPl"/>, <see cref="SrAts"/>, <see cref="AdoTst"/>, <see cref="SigPId"/>, <see cref="SigD"/>),
    /// <see cref="SigD"/>'s five own members (<see cref="MId"/>, <see cref="Pars"/>, <see cref="HashM"/>,
    /// <see cref="HashV"/>, <see cref="Ctys"/>), and <see cref="EtsiU"/>.
    /// </summary>
    /// <param name="name">The candidate header parameter or member name.</param>
    public static bool IsJAdESHeaderName(string name) => name switch
    {
        _ when IsSigT(name) => true,
        _ when IsX5tHashO(name) => true,
        _ when IsSigX5ts(name) => true,
        _ when IsSrCms(name) => true,
        _ when IsSigPl(name) => true,
        _ when IsSrAts(name) => true,
        _ when IsAdoTst(name) => true,
        _ when IsSigPId(name) => true,
        _ when IsSigD(name) => true,
        _ when IsMId(name) => true,
        _ when IsPars(name) => true,
        _ when IsHashM(name) => true,
        _ when IsHashV(name) => true,
        _ when IsCtys(name) => true,
        _ when IsEtsiU(name) => true,
        _ => false
    };


    /// <summary>
    /// Compares two JAdES header parameter or member names for equality. Comparison is case-sensitive per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515">RFC 7515</see>.
    /// </summary>
    public static bool Equals(string nameA, string nameB) =>
        object.ReferenceEquals(nameA, nameB) || StringComparer.Ordinal.Equals(nameA, nameB);
}
