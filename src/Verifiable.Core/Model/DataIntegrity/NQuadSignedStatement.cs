using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// A signed N-Quad statement for ecdsa-sd-2023 selective disclosure proofs.
/// </summary>
/// <remarks>
/// <para>
/// In ecdsa-sd-2023, each non-mandatory N-Quad statement is signed individually with the
/// ephemeral private key. This type bundles the statement with its signature and
/// index in the canonical statement list.
/// </para>
/// <para>
/// <strong>Usage in Proof Flow:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Issuer:</strong> Creates signed N-Quads for all non-mandatory statements
/// using the ephemeral key. These are included in the base proof.
/// </description></item>
/// <item><description>
/// <strong>Holder:</strong> Selects which signed N-Quads to disclose in the
/// derived proof based on verifier requirements.
/// </description></item>
/// <item><description>
/// <strong>Verifier:</strong> Verifies each disclosed N-Quad signature using
/// the ephemeral public key from the proof.
/// </description></item>
/// </list>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#add-base-proof-ecdsa-sd-2023">
/// VC Data Integrity ECDSA Cryptosuites: Add Base Proof (ecdsa-sd-2023)</see>.
/// </para>
/// </remarks>
/// <param name="Statement">The N-Quad statement text.</param>
/// <param name="Signature">The signature over the UTF-8 encoded statement.</param>
/// <param name="Index">The index in the canonical N-Quad statement list.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct NQuadSignedStatement(string Statement, Signature Signature, int Index)
{
    private string DebuggerDisplay
    {
        get
        {
            var truncated = Statement.Length > 50
                ? Statement[..50] + "..."
                : Statement;

            return $"[{Index}]: {truncated}";
        }
    }
}