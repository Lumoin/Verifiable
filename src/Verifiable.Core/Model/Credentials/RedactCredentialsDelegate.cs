using System;
using System.Collections.Generic;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Delegate for redacting selectively disclosable claims from a credential JSON document,
/// embedding <c>_sd</c> digest arrays at the correct nesting levels.
/// </summary>
/// <remarks>
/// <para>
/// This delegate abstracts the format-specific logic for splitting a JSON credential into
/// a ready-to-sign payload with embedded digests and the corresponding disclosures. The
/// implementation lives in <c>Verifiable.Json</c> (<c>SdJwtClaimRedaction.Redact</c>),
/// which uses <c>System.Text.Json</c> internally. By accepting this as a delegate,
/// <see cref="CredentialSdJwtExtensions"/> remains independent of any JSON library.
/// </para>
/// <para>
/// The implementation composes three phases:
/// </para>
/// <list type="number">
/// <item><description>
/// <see cref="DisclosurePathGrouping.GroupByParent"/> groups paths by parent (format-agnostic).
/// </description></item>
/// <item><description>
/// Format-specific JSON walking creates disclosures and computes digests.
/// </description></item>
/// <item><description>
/// <see cref="DigestPlacement.PlaceDigests"/> inserts <c>_sd</c> arrays at the correct
/// locations (format-agnostic).
/// </description></item>
/// </list>
/// </remarks>
/// <param name="credentialJson">
/// The credential as a JSON string, produced by <see cref="CredentialSerializeDelegate"/>.
/// </param>
/// <param name="disclosablePaths">
/// Paths to claims that should become selectively disclosable.
/// </param>
/// <param name="saltFactory">
/// Factory for generating cryptographic salt bytes for each disclosure.
/// </param>
/// <param name="serializeDisclosure">
/// Delegate for serializing a disclosure to its Base64Url-encoded form.
/// </param>
/// <param name="computeDigest">
/// Delegate for computing the digest of an encoded disclosure.
/// </param>
/// <param name="encoder">Delegate for Base64Url encoding.</param>
/// <param name="hashAlgorithm">
/// The hash algorithm identifier in IANA format (e.g., <c>"sha-256"</c>).
/// </param>
/// <returns>
/// A tuple containing the ready-to-sign <see cref="JwtPayload"/> (with embedded <c>_sd</c>
/// arrays and <c>_sd_alg</c>) and the list of <see cref="SdDisclosure"/> instances.
/// </returns>
public delegate (JwtPayload Payload, IReadOnlyList<SdDisclosure> Disclosures) RedactCredentialDelegate(
    string credentialJson,
    IReadOnlySet<CredentialPath> disclosablePaths,
    Func<byte[]> saltFactory,
    SerializeDisclosureDelegate<SdDisclosure> serializeDisclosure,
    ComputeDisclosureDigestDelegate computeDigest,
    EncodeDelegate encoder,
    string hashAlgorithm);