namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Integer labels for the COSE header parameters that appear in the
/// COSE_Sign1 structures mdoc uses per ISO/IEC 18013-5 + RFC 9052 +
/// RFC 9360. Distinct namespace from the data-element string keys in
/// <see cref="MdocWellKnownKeys"/> because COSE headers are
/// integer-keyed per RFC 9052 §3.1 (versus mdoc data-element maps which
/// are text-keyed).
/// </summary>
/// <remarks>
/// <para>
/// The constants here are scoped to the labels mdoc actually uses. The
/// broader COSE header registry is at
/// <see href="https://www.iana.org/assignments/cose/cose.xhtml#header-parameters">IANA</see>;
/// adding constants here when an mdoc context needs them is preferred over
/// generic well-known-headers lists.
/// </para>
/// </remarks>
public static class MdocCoseHeaderLabels
{
    /// <summary>
    /// The <c>alg</c> header parameter (label 1) — the COSE algorithm
    /// identifier in the protected header per RFC 9052 §3.1.
    /// </summary>
    public const int Alg = 1;

    /// <summary>
    /// The <c>kid</c> header parameter (label 4) — optional key identifier
    /// per RFC 9052 §3.1.
    /// </summary>
    public const int Kid = 4;

    /// <summary>
    /// The <c>x5chain</c> header parameter (label 33) per RFC 9360 §2.
    /// Carries the X.509 certificate chain in the unprotected header. The
    /// value is either a single DER-encoded bstr (one certificate) or an
    /// array of DER-encoded bstrs (multiple certificates, leaf first).
    /// ISO/IEC 18013-5 §9.1.2.4 mandates its presence for IssuerAuth.
    /// </summary>
    public const int X5Chain = 33;
}
