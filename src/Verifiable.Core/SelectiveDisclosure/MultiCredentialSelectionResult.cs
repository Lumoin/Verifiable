using System.Collections.Generic;

namespace Verifiable.Core.SelectiveDisclosure;


/// <summary>
/// Result of multi-credential selection.
/// </summary>
/// <typeparam name="TCredential">The type representing credentials.</typeparam>
/// <typeparam name="TClaim">The type representing individual claims.</typeparam>
/// <param name="Selections">The selected credentials with their disclosure sets.</param>
/// <param name="SatisfiesAllRequirements">Whether all requirements are satisfied.</param>
/// <param name="UnsatisfiedRequirements">Requirements that could not be satisfied, if any.</param>
public readonly record struct MultiCredentialSelectionResult<TCredential, TClaim>(
    IReadOnlyList<(TCredential Credential, IReadOnlySet<TClaim> Disclosures)> Selections,
    bool SatisfiesAllRequirements,
    IReadOnlySet<TClaim>? UnsatisfiedRequirements = null);
