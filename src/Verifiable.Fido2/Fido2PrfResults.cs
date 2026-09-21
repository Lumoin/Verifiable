using Verifiable.Cryptography;

namespace Verifiable.Fido2;

/// <summary>
/// The <c>prf</c> extension's decoded evaluation results — the pseudo-random function's SECRET
/// output bytes, owned by the caller that requested them.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfoutputs">W3C Web
/// Authentication Level 3, section 10.1.4: Pseudo-random function extension (prf)</see>, dictionary
/// <c>AuthenticationExtensionsPRFOutputs</c>: <c>results.first</c> is required, <c>results.second</c>
/// is present only when a second evaluation was requested and produced. The sibling of
/// <see cref="Fido2PrfValues"/> (the relying party's OWN evaluation salts, which are not secret);
/// this type carries the authenticator's PRF output instead.
/// </para>
/// <para>
/// <strong>This carries a secret.</strong> <see cref="First"/> and, when present,
/// <see cref="Second"/> are the pseudo-random function's actual output bytes — usable, per section
/// 10.1.4's own motivating example, as a symmetric encryption key. This instance OWNS both carriers
/// and is the only thing that disposes them; a caller that receives a <see cref="Fido2PrfResults"/>
/// from <c>Verifiable.Json.PrfResultsJsonReader.Read</c> disposes it exactly once, normally
/// via a <see langword="using"/> declaration, which wipes both carriers' bytes on the way out. The
/// secret MUST NOT be copied into an unowned array, logged, or claimed through the claim/audit
/// pipeline — <see cref="PrfResultsPresentContext"/> reports only whether a result was present, never
/// the bytes.
/// </para>
/// </remarks>
public sealed class Fido2PrfResults: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run, guarding against a double dispose.</summary>
    private bool IsDisposed { get; set; }

    /// <summary>
    /// Initializes a new <see cref="Fido2PrfResults"/> over already-decoded secret carriers.
    /// Ownership of both <paramref name="first"/> and, when supplied, <paramref name="second"/>
    /// transfers to this instance.
    /// </summary>
    /// <param name="first">The required first evaluation result, per <see cref="First"/>.</param>
    /// <param name="second">The optional second evaluation result, per <see cref="Second"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="first"/> is <see langword="null"/>.</exception>
    public Fido2PrfResults(SymmetricKeyMemory first, SymmetricKeyMemory? second)
    {
        ArgumentNullException.ThrowIfNull(first);

        First = first;
        Second = second;
    }


    /// <summary>
    /// The first (and, absent <see cref="Second"/>, only) PRF evaluation result — the decoded,
    /// pooled, disposable secret bytes this instance owns.
    /// </summary>
    public SymmetricKeyMemory First { get; }

    /// <summary>
    /// The second PRF evaluation result, when a second evaluation was requested and the
    /// authenticator produced one, or <see langword="null"/> otherwise — the decoded, pooled,
    /// disposable secret bytes this instance owns.
    /// </summary>
    public SymmetricKeyMemory? Second { get; }


    /// <summary>
    /// Disposes <see cref="First"/> and, when present, <see cref="Second"/>, wiping both carriers'
    /// secret bytes. Safe to call more than once.
    /// </summary>
    public void Dispose()
    {
        if(IsDisposed)
        {
            return;
        }

        First.Dispose();
        Second?.Dispose();
        IsDisposed = true;
    }
}
