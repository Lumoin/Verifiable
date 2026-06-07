using Verifiable.Cryptography;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Generates a freshly-allocated <see cref="Salt"/> for use as the
/// <c>random</c> field of one <see cref="MdocIssuerSignedItem"/>.
/// </summary>
/// <remarks>
/// <para>
/// Matches the shape of <c>GenerateDisclosureSaltDelegate</c> used by SD-JWT
/// and SD-CWT: the application binds byte length, <see cref="Tag"/>
/// (<c>CryptoTags.MdocIssuerSignedItemRandom</c>), and memory pool when it
/// constructs the delegate, so each invocation is parameterless. Length must
/// be at least
/// <see cref="MdocWellKnownKeys.IssuerSignedItemRandomMinimumLength"/> per
/// ISO/IEC 18013-5 §9.1.2.5.
/// </para>
/// <para>
/// The builder receives ownership of the returned <see cref="Salt"/>, copies
/// its bytes onto the produced <see cref="MdocIssuerSignedItem.Random"/>, and
/// disposes the <see cref="Salt"/> before returning — the data-model record
/// holds a plain <see cref="ReadOnlyMemory{T}"/> so it can travel beyond the
/// <c>SensitiveMemory</c> ownership window.
/// </para>
/// <para>
/// Both test and production wiring bind to the application's entropy backend
/// (<c>MicrosoftEntropyFunctions.GenerateSalt</c> or
/// <c>BouncyCastleEntropyFunctions.GenerateSalt</c>) so that CBOM provenance and
/// entropy-tracking events flow through onto the salt's tag; there is no convenience
/// that fills from the OS CSPRNG directly.
/// </para>
/// </remarks>
/// <returns>A freshly-allocated tagged <see cref="Salt"/>.</returns>
public delegate Salt GenerateMdocItemRandomDelegate();
