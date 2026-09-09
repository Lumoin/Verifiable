using System.Collections.Generic;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// The result of <see cref="SdToken{TEnvelope}.SelectDisclosures(IReadOnlySet{CredentialPath}, Cryptography.BaseMemoryPool)"/>.
/// </summary>
/// <typeparam name="TEnvelope">The token's envelope type.</typeparam>
/// <param name="Token">
/// The new token carrying the disclosures at the requested paths plus their disclosable
/// ancestors, each included once.
/// </param>
/// <param name="UnmatchedPaths">
/// The requested paths that addressed nothing this token carries — neither a disclosure nor an
/// always-disclosed claim. An always-disclosed path is never reported here; it selected nothing
/// because it needed no selecting.
/// </param>
public readonly record struct SdDisclosureSelectionResult<TEnvelope>(
    SdToken<TEnvelope> Token,
    IReadOnlySet<CredentialPath> UnmatchedPaths) where TEnvelope : notnull;
