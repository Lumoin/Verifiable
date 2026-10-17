using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// A JWS signature verification function bound to the one JWA algorithm it performs, established where the function is
/// selected. <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "The library MUST
/// ensure that the "alg" or "enc" header specifies the same algorithm that is used for the cryptographic operation." A bare
/// function tells a validator nothing of the operation it performs, so a header naming PS256 over an RSA key could be
/// checked by a function performing RS256 and found to verify; carried with its algorithm, the function is used only under a
/// header naming that algorithm (<see cref="JwsKeyAlgorithmBinding.JudgeSuppliedVerification"/>).
/// </summary>
[DebuggerDisplay("JwsAlgorithmVerification Algorithm={Algorithm,nq}")]
public sealed record JwsAlgorithmVerification
{
    /// <summary>The JWA algorithm <see cref="Verification"/> performs, as RFC 7518 Section 3.1 registers it.</summary>
    public string Algorithm { get; }


    /// <summary>The verification function, performing <see cref="Algorithm"/> and no other.</summary>
    public VerificationDelegate Verification { get; }


    /// <summary>Binds a verification function to the algorithm it performs.</summary>
    /// <param name="algorithm">The JWA algorithm the function performs.</param>
    /// <param name="verification">The verification function.</param>
    public JwsAlgorithmVerification(string algorithm, VerificationDelegate verification)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);
        ArgumentNullException.ThrowIfNull(verification);

        Algorithm = algorithm;
        Verification = verification;
    }
}
