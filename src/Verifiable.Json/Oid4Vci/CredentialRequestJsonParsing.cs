using System.Text.Json;
using Verifiable.Core;
using Verifiable.OAuth.Oid4Vci;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> parser for the OID4VCI 1.0 §8.2 Credential Request body —
/// the JSON side the <c>Verifiable.OAuth</c> serialization firewall keeps out of the core
/// library. Wire it onto an
/// <see cref="Verifiable.OAuth.Server.AuthorizationServerIntegration"/> with
/// <see cref="CredentialRequestJsonExtensions.UseDefaultCredentialRequestJsonParsing"/>.
/// </summary>
public static class CredentialRequestJsonParsing
{
    /// <summary>
    /// Parses a Credential Request body: a JSON object carrying an optional
    /// <c>credential_configuration_id</c> / <c>credential_identifier</c> string and an optional
    /// <c>proofs</c> object mapping each proof type name to its array of key proofs.
    /// </summary>
    /// <remarks>
    /// STRICT only on structure: a body that is not a JSON object yields
    /// <see langword="null"/>, and the endpoint responds <c>400 invalid_credential_request</c>.
    /// The §8.2 identifier-shape rule (exactly one of the two) and proof verification are
    /// enforced downstream — the parser extracts the wire shape and never throws to the caller.
    /// §8.2 constrains the <c>proofs</c> object itself: "The proofs parameter contains exactly one
    /// parameter named as the proof type in Appendix F, the value set for this parameter is a
    /// non-empty array." A <c>proofs</c> object with more than one proof-type member, or whose array
    /// is empty, is malformed and yields <see langword="null"/> so the endpoint answers
    /// <c>invalid_credential_request</c>. String proof types (<c>jwt</c> / <c>attestation</c>,
    /// Appendix F.1 / F.3) surface in <see cref="CredentialRequest.Proofs"/>; the object-valued
    /// <c>di_vp</c> proof type (Appendix F.2) surfaces in
    /// <see cref="CredentialRequest.DiVpProofs"/> rather than being dropped.
    /// </remarks>
    /// <param name="requestBody">The raw JSON request body.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static ValueTask<CredentialRequest?> ParseCredentialRequest(
        string requestBody, ExchangeContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestBody);

        try
        {
            using JsonDocument doc = JsonDocument.Parse(requestBody);
            JsonElement root = doc.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return ValueTask.FromResult<CredentialRequest?>(null);
            }

            string? configurationId = ReadOptionalString(
                root, Oid4VciCredentialParameterNames.CredentialConfigurationId);
            string? identifier = ReadOptionalString(
                root, Oid4VciCredentialParameterNames.CredentialIdentifier);

            //§8.2: an ill-shaped proofs object (more than one proof-type member, or an empty array)
            //is malformed; the endpoint answers invalid_credential_request on a null parse.
            if(!TryReadProofs(root, out ProofSet proofSet))
            {
                return ValueTask.FromResult<CredentialRequest?>(null);
            }

            return ValueTask.FromResult<CredentialRequest?>(new CredentialRequest
            {
                CredentialConfigurationId = configurationId,
                CredentialIdentifier = identifier,
                Proofs = proofSet.StringProofs,
                DiVpProofs = proofSet.DiVpProofs,
                ResponseEncryption = ReadResponseEncryption(root)
            });
        }
        catch(JsonException)
        {
            return ValueTask.FromResult<CredentialRequest?>(null);
        }
    }


    /// <summary>
    /// Reads the §8.2 <c>credential_response_encryption</c> object — <c>jwk</c> as its
    /// string-valued members, <c>enc</c>, and the optional <c>zip</c>. Member-level
    /// requiredness is the endpoint's check (it answers
    /// <c>invalid_encryption_parameters</c>); the parser extracts the wire shape only.
    /// </summary>
    private static CredentialResponseEncryption? ReadResponseEncryption(JsonElement root)
    {
        if(!root.TryGetProperty(
                Oid4VciCredentialParameterNames.CredentialResponseEncryption,
                out JsonElement encryptionElement)
            || encryptionElement.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        Dictionary<string, object>? jwk = null;
        if(encryptionElement.TryGetProperty(Oid4VciCredentialParameterNames.Jwk, out JsonElement jwkElement)
            && jwkElement.ValueKind == JsonValueKind.Object)
        {
            jwk = new Dictionary<string, object>(StringComparer.Ordinal);
            foreach(JsonProperty member in jwkElement.EnumerateObject())
            {
                if(member.Value.ValueKind == JsonValueKind.String)
                {
                    jwk[member.Name] = member.Value.GetString()!;
                }
            }
        }

        return new CredentialResponseEncryption
        {
            Jwk = jwk,
            Enc = ReadOptionalString(encryptionElement, Oid4VciCredentialParameterNames.Enc),
            Zip = ReadOptionalString(encryptionElement, Oid4VciCredentialParameterNames.Zip)
        };
    }


    private static string? ReadOptionalString(JsonElement root, string member)
    {
        return root.TryGetProperty(member, out JsonElement value)
            && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }


    /// <summary>
    /// Reads the §8.2 <c>proofs</c> object into <paramref name="proofSet"/>, enforcing the §8.2
    /// shape: "The proofs parameter contains exactly one parameter named as the proof type in
    /// Appendix F, the value set for this parameter is a non-empty array." An absent <c>proofs</c>
    /// member is valid (no proofs); a present one with more than one proof-type member, a non-array
    /// value, or an empty array is malformed and returns <see langword="false"/>. String proof types
    /// (<c>jwt</c> / <c>attestation</c>) surface as <see cref="ProofSet.StringProofs"/>; the
    /// object-valued <c>di_vp</c> proof type surfaces as <see cref="ProofSet.DiVpProofs"/>.
    /// </summary>
    private static bool TryReadProofs(JsonElement root, out ProofSet proofSet)
    {
        proofSet = ProofSet.Empty;
        if(!root.TryGetProperty(Oid4VciCredentialParameterNames.Proofs, out JsonElement proofsElement))
        {
            return true;
        }

        //§8.2: proofs is an object whose single member is named for the proof type.
        if(proofsElement.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        Dictionary<string, IReadOnlyList<string>> stringProofs = new(StringComparer.Ordinal);
        IReadOnlyList<string> diVpProofs = [];
        int proofTypeCount = 0;
        foreach(JsonProperty proofType in proofsElement.EnumerateObject())
        {
            proofTypeCount++;

            //§8.2: "the value set for this parameter is a non-empty array."
            if(proofType.Value.ValueKind != JsonValueKind.Array
                || proofType.Value.GetArrayLength() == 0)
            {
                return false;
            }

            if(string.Equals(proofType.Name, Oid4VciCredentialParameterNames.DiVpProofType, StringComparison.Ordinal))
            {
                //Appendix F.2: each di_vp entry is a W3C Verifiable Presentation JSON object,
                //preserved verbatim as its serialized JSON rather than dropped as a non-string.
                List<string> presentations = [];
                foreach(JsonElement entry in proofType.Value.EnumerateArray())
                {
                    if(entry.ValueKind != JsonValueKind.Object)
                    {
                        return false;
                    }

                    presentations.Add(entry.GetRawText());
                }

                diVpProofs = presentations;
            }
            else
            {
                List<string> values = [];
                foreach(JsonElement entry in proofType.Value.EnumerateArray())
                {
                    if(entry.ValueKind != JsonValueKind.String)
                    {
                        return false;
                    }

                    values.Add(entry.GetString()!);
                }

                stringProofs[proofType.Name] = values;
            }
        }

        //§8.2: "The proofs parameter contains exactly one parameter named as the proof type."
        if(proofTypeCount > 1)
        {
            return false;
        }

        proofSet = new ProofSet(stringProofs, diVpProofs);

        return true;
    }


    /// <summary>
    /// The parsed §8.2 <c>proofs</c> object: string proof types (<c>jwt</c> / <c>attestation</c>)
    /// keyed by name, and the object-valued <c>di_vp</c> presentations carried as their serialized
    /// JSON.
    /// </summary>
    private readonly record struct ProofSet(
        IReadOnlyDictionary<string, IReadOnlyList<string>> StringProofs,
        IReadOnlyList<string> DiVpProofs)
    {
        public static ProofSet Empty { get; } =
            new(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal), []);
    }
}
