namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Constructs a DPoP proof JWS for a specific request. The application
/// wires the delegate either to the library default
/// (<see cref="DpopProofConstruction.BuildAsync"/>) or to a custom
/// implementation. The cancellation token is honoured by the underlying
/// signing primitive.
/// </summary>
/// <param name="claims">The claim set to embed in the proof.</param>
/// <param name="key">The signing key and its algorithm.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The compact-serialised JWS string.</returns>
public delegate ValueTask<string> ConstructDpopProofDelegate(
    DpopProofClaims claims,
    DpopKey key,
    CancellationToken cancellationToken);
