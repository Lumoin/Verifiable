using System.Collections.Generic;
using Verifiable.JCose;
using Verifiable.JCose.Sd;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// An SD-CWT token consisting of a COSE_Sign1 message and the disclosures.
/// </summary>
/// <remarks>
/// <para>
/// This is the CBOR counterpart of <see cref="SdJwtToken"/>. The COSE_Sign1 message contains:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Protected header</strong>: <c>alg</c>, <c>kid</c>, <c>typ</c> (<c>application/sd-cwt</c>),
/// and <c>sd_alg</c> (hash algorithm for blinded claim hashes).
/// </description></item>
/// <item><description>
/// <strong>Unprotected header</strong>: <c>sd_claims</c> — array of CBOR-encoded disclosures.
/// </description></item>
/// <item><description>
/// <strong>Payload</strong>: CWT claims set with blinded claim hashes under <c>simple(59)</c>
/// replacing disclosable claims.
/// </description></item>
/// </list>
/// <para>
/// At issuance, the unprotected header contains all disclosures. When the Holder presents
/// to a Verifier, it selects a subset of disclosures to include.
/// </para>
/// </remarks>
/// <param name="CoseMessage">The signed COSE_Sign1 message.</param>
/// <param name="Disclosures">The selectively disclosable claims.</param>
public sealed record SdCwtToken(
    CoseSign1Message CoseMessage,
    IReadOnlyList<SdDisclosure> Disclosures);