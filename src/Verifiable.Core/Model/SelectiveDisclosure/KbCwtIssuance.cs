using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Issues an SD-CWT Key Binding Token (KBT) that binds an SD-CWT presentation
/// to the holder's session with a specific Verifier per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see>. The CBOR twin of <c>KbJwtIssuance</c>.
/// </summary>
/// <remarks>
/// <para>
/// The KBT is a COSE_Sign1 signed by the holder's key — the same key whose
/// COSE_Key is in the SD-CWT's <c>cnf</c> claim. Unlike the SD-JWT KB-JWT, there
/// is <strong>no <c>sd_hash</c></strong>: the binding is that the holder signs
/// over the embedded presentation SD-CWT. The KBT <em>is</em> the presentation.
/// </para>
/// <list type="bullet">
///   <item><description>Protected header — <c>typ</c> (16) = the KBT type value, <c>alg</c> (1) = the holder key's COSE algorithm, <c>kcwt</c> (13) = the entire embedded presentation SD-CWT.</description></item>
///   <item><description>Unprotected header — empty.</description></item>
///   <item><description>Payload — CWT claims map: <c>aud</c> (3, MUST), <c>iat</c> (6), and optionally <c>cnonce</c> (39). <c>iss</c> (1) and <c>sub</c> (2) MUST NOT be present.</description></item>
/// </list>
/// <para>
/// This orchestrator is serialization-agnostic and VP-neutral: it never imports a
/// CBOR library. The CBOR construction is supplied through the
/// <see cref="BuildKbtProtectedHeaderDelegate"/> and
/// <see cref="BuildKbtPayloadDelegate"/> seams (wired to <c>Verifiable.Cbor</c>),
/// and signing flows through <c>Cose.SignAsync</c>, which resolves the
/// per-algorithm signing function from the holder key's <see cref="Tag"/> via
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>.
/// </para>
/// <para>
/// What this is: the holder's presentation-time proof of possession of the key the issuer bound into
/// the credential (the <c>cnf</c> claim) — the SD-CWT form of the holder binding a verifiable
/// presentation carries. The same role appears as SD-JWT's <c>KB-JWT</c>, mdoc's <c>DeviceAuth</c>,
/// and Data Integrity's authentication-purpose presentation proof.
/// </para>
/// </remarks>
[DebuggerDisplay("KbCwtIssuance")]
public static class KbCwtIssuance
{
    /// <summary>
    /// Issues a serialized SD-CWT Key Binding Token as a tracked
    /// <see cref="EncodedCoseSign1"/> carrier.
    /// </summary>
    /// <param name="presentationToken">
    /// The SD-CWT presentation token (issuer COSE_Sign1 plus the holder-selected
    /// disclosures). Embedded under the <c>kcwt</c> protected-header parameter as
    /// the presentation SD-CWT the holder signs over.
    /// </param>
    /// <param name="holderKey">
    /// The holder's signing key. The COSE <c>alg</c> is derived from the key's
    /// <see cref="Tag"/>; the matching public key must appear in the SD-CWT's
    /// <c>cnf</c> claim for the Verifier to bind the credential to this presentation.
    /// </param>
    /// <param name="verifierAud">The <c>aud</c> claim value identifying the Verifier.</param>
    /// <param name="verifierCnonce">The <c>cnonce</c> claim value, or <see langword="null"/> to omit it.</param>
    /// <param name="iat">The <c>iat</c> claim value, encoded as Unix seconds.</param>
    /// <param name="buildProtectedHeader">Seam that builds the KBT protected header (embeds <c>kcwt</c>).</param>
    /// <param name="buildPayload">Seam that builds the KBT CWT-claims payload.</param>
    /// <param name="buildSigStructure">Delegate that builds the COSE Sig_structure for signing.</param>
    /// <param name="serializeCoseSign1">Delegate that serializes the signed message to its COSE_Sign1 wire carrier.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token, propagated through the registry-resolved signing delegate.</param>
    /// <returns>The serialized KBT wrapped in an <see cref="EncodedCoseSign1"/> carrier the caller owns and disposes.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the protected header transfers to the CoseSign1Message returned by Cose.SignAsync; that message is disposed via the using statement before the method returns, and the returned EncodedCoseSign1 carrier is independent of it.")]
    public static async ValueTask<EncodedCoseSign1> IssueAsync(
        SdToken<ReadOnlyMemory<byte>> presentationToken,
        PrivateKeyMemory holderKey,
        string verifierAud,
        string? verifierCnonce,
        DateTimeOffset iat,
        BuildKbtProtectedHeaderDelegate buildProtectedHeader,
        BuildKbtPayloadDelegate buildPayload,
        BuildSigStructureDelegate buildSigStructure,
        SerializeCoseSign1Delegate serializeCoseSign1,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(presentationToken);
        ArgumentNullException.ThrowIfNull(holderKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(verifierAud);
        ArgumentNullException.ThrowIfNull(buildProtectedHeader);
        ArgumentNullException.ThrowIfNull(buildPayload);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(serializeCoseSign1);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        int coseAlg = CryptoFormatConversions.DefaultTagToCoseConverter(holderKey.Tag);

        EncodedCoseProtectedHeader protectedHeader = buildProtectedHeader(coseAlg, presentationToken, memoryPool);

        //The payload buffer outlives the signing call and the serialization below — the
        //returned message borrows it (it is not copied into the message) and the serializer
        //reads it — so it is released only after serializeCoseSign1 has produced its own carrier.
        using IMemoryOwner<byte> payloadOwner = buildPayload(verifierAud, iat.ToUnixTimeSeconds(), verifierCnonce, memoryPool);

        using CoseSign1Message message = await Cose.SignAsync(
            protectedHeader,
            null,
            payloadOwner.Memory,
            buildSigStructure,
            holderKey,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        return serializeCoseSign1(message, memoryPool);
    }
}
