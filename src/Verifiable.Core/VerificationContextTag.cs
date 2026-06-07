using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core;

/// <summary>
/// Builds the verification-context <see cref="Tag"/> carried by a <see cref="Verified{T}"/>.
/// </summary>
/// <remarks>
/// The verification context records the provenance visible at the decision point — that this
/// value was produced by a verification (<see cref="Purpose.Verification"/>) and, when known, the
/// verification method / key identifier the signature was checked against. It reuses the
/// library's <see cref="Tag"/> mechanism rather than a bespoke provenance type.
/// </remarks>
internal static class VerificationContextTag
{
    /// <summary>
    /// Creates a verification context tagged with <see cref="Purpose.Verification"/>, adding the
    /// verification method / key identifier as a <see cref="KeyId"/> when one is available.
    /// </summary>
    /// <param name="verificationMethod">The verification method / key id, or <see langword="null"/>.</param>
    internal static Tag Create(string? verificationMethod)
    {
        var tag = Tag.Create((typeof(Purpose), Purpose.Verification));
        if(!string.IsNullOrWhiteSpace(verificationMethod))
        {
            tag = tag.With(new KeyId(verificationMethod));
        }

        return tag;
    }
}
