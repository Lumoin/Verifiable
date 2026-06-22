using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core.Did.Methods.WebVh;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.Json;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Mints valid (and deliberately invalid) did:webvh <c>did.jsonl</c> logs for the resolver tests by
/// executing the specification's Create and Update steps: compute the SCID over the preliminary entry,
/// chain each entryHash to its predecessor, and sign each entry with an <c>eddsa-jcs-2022</c> Data
/// Integrity proof. The verification path under test re-derives every one of those values, so a faithfully
/// minted log is the round-trip oracle for the SCID, entryHash, controller-proof and pre-rotation checks.
/// </summary>
internal static class WebVhTestLog
{
    public static HashFunctionDelegate Hash { get; } = SHA256.HashData;

    public static EncodeDelegate Base58Encoder { get; } = DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase));

    public static DecodeDelegate Base58Decoder { get; } = DefaultCoderSelector.SelectDecoder(typeof(PublicKeyMultibase));


    /// <summary>Mints a single-entry (genesis-only) log signed by <paramref name="signer"/>.</summary>
    public static Task<WebVhMintedLog> MintGenesisAsync(
        string domain,
        WebVhController signer,
        string versionTime,
        ImmutableArray<string>? nextKeyHashes = null,
        WebVhController? authentication = null,
        string? explicitFilesServiceEndpoint = null,
        string? explicitFilesServiceEndpointMap = null,
        string? explicitWhoisServiceEndpoint = null,
        ImmutableArray<string>? genesisAlsoKnownAs = null)
    {
        return MintAsync(domain,
        [
            new WebVhEntryPlan(signer, [signer.Multikey], nextKeyHashes, Deactivated: false, versionTime, Authentication: authentication, ExplicitFilesServiceEndpoint: explicitFilesServiceEndpoint, ExplicitFilesServiceEndpointMap: explicitFilesServiceEndpointMap, ExplicitWhoisServiceEndpoint: explicitWhoisServiceEndpoint, GenesisAlsoKnownAs: genesisAlsoKnownAs)
        ]);
    }


    /// <summary>Mints a multi-entry log, executing the Create step for the first plan and Update for the rest.</summary>
    public static async Task<WebVhMintedLog> MintAsync(string domain, IReadOnlyList<WebVhEntryPlan> plans)
    {
        JsonObject genesisParameters = new()
        {
            ["method"] = WebVhParameters.SupportedMethod,
            ["scid"] = ScidPlaceholder,
            ["updateKeys"] = ToJsonArray(plans[0].UpdateKeys)
        };

        if(plans[0].NextKeyHashes is { } genesisNextKeyHashes)
        {
            genesisParameters["nextKeyHashes"] = ToJsonArray(genesisNextKeyHashes);
        }

        if(plans[0].Portable)
        {
            genesisParameters["portable"] = true;
        }

        ApplyWitness(genesisParameters, plans[0].Witness);
        ApplyWatchers(genesisParameters, plans[0].Watchers);

        JsonArray? genesisAlsoKnownAs = plans[0].GenesisAlsoKnownAs is { } akaValues ? ToJsonArray(akaValues) : null;

        JsonObject genesisPreliminary = new()
        {
            ["versionId"] = ScidPlaceholder,
            ["versionTime"] = plans[0].VersionTime,
            ["parameters"] = genesisParameters,
            ["state"] = BuildState($"did:webvh:{ScidPlaceholder}:{domain}", alsoKnownAs: genesisAlsoKnownAs, authentication: plans[0].Authentication, explicitFilesServiceEndpoint: plans[0].ExplicitFilesServiceEndpoint, explicitFilesServiceEndpointMap: plans[0].ExplicitFilesServiceEndpointMap, explicitWhoisServiceEndpoint: plans[0].ExplicitWhoisServiceEndpoint)
        };

        string scid = ComputeBase58OfCanonical(genesisPreliminary.ToJsonString());
        string currentDid = $"did:webvh:{scid}:{domain}";

        var lines = ImmutableArray.CreateBuilder<string>(plans.Count);
        var versionIds = ImmutableArray.CreateBuilder<string>(plans.Count);
        string predecessor = scid;

        for(int index = 0; index < plans.Count; index++)
        {
            WebVhEntryPlan plan = plans[index];
            JsonObject entry;
            if(index == 0)
            {
                entry = JsonNode.Parse(genesisPreliminary.ToJsonString().Replace(ScidPlaceholder, scid, System.StringComparison.Ordinal))!.AsObject();
            }
            else
            {
                string entryDid = currentDid;
                JsonArray? alsoKnownAs = null;
                if(plan.MoveToDomain is { } moveTo)
                {
                    //A move keeps the established SCID; a negative test overrides it with a different SCID in the
                    //moved id to exercise the scid-same-across-a-move enforcement.
                    string moveScid = plan.MoveChangeScid ?? scid;
                    entryDid = $"did:webvh:{moveScid}:{moveTo}";
                    if(!plan.SuppressAlsoKnownAs)
                    {
                        alsoKnownAs = [currentDid];
                        if(plan.MalformAlsoKnownAs)
                        {
                            alsoKnownAs.Add(123);
                        }
                    }

                    currentDid = entryDid;
                }

                entry = BuildUpdateEntry(plan, entryDid, alsoKnownAs);
            }

            //entryHash is computed over the entry with versionId set to the predecessor and no proof.
            JsonObject entryForHash = JsonNode.Parse(entry.ToJsonString())!.AsObject();
            entryForHash["versionId"] = predecessor;
            string entryHash = ComputeBase58OfCanonical(entryForHash.ToJsonString());
            string versionId = $"{index + 1}-{entryHash}";
            entry["versionId"] = versionId;

            JsonObject proof = await SignAsync(entry, plan).ConfigureAwait(false);
            entry["proof"] = new JsonArray(proof);

            lines.Add(entry.ToJsonString());
            versionIds.Add(versionId);
            predecessor = versionId;
        }

        return new WebVhMintedLog(lines.ToImmutable(), scid, currentDid, versionIds.ToImmutable());
    }


    private static JsonObject BuildUpdateEntry(WebVhEntryPlan plan, string did, JsonArray? alsoKnownAs)
    {
        JsonObject parameters = new()
        {
            ["updateKeys"] = ToJsonArray(plan.UpdateKeys)
        };

        if(plan.NextKeyHashes is { } nextKeyHashes)
        {
            parameters["nextKeyHashes"] = ToJsonArray(nextKeyHashes);
        }

        if(plan.Deactivated)
        {
            parameters["deactivated"] = true;
        }

        ApplyWitness(parameters, plan.Witness);
        ApplyWatchers(parameters, plan.Watchers);

        return new JsonObject
        {
            ["versionId"] = "placeholder",
            ["versionTime"] = plan.VersionTime,
            ["parameters"] = parameters,
            ["state"] = BuildState(did, alsoKnownAs, authentication: plan.Authentication)
        };
    }


    //Emits the watchers parameter declared by an entry plan: omitted when absent, otherwise the URL array.
    private static void ApplyWatchers(JsonObject parameters, ImmutableArray<string>? watchers)
    {
        if(watchers is { } declared)
        {
            parameters["watchers"] = ToJsonArray(declared);
        }
    }


    //Emits the witness parameter declared by an entry plan: omitted when absent, the empty object {} to
    //disable witnessing, or {threshold, witnesses:[{id}]} for an active rule.
    private static void ApplyWitness(JsonObject parameters, WebVhWitnessSpec? witness)
    {
        if(witness is null)
        {
            return;
        }

        if(witness.IsDisable)
        {
            parameters["witness"] = new JsonObject();

            return;
        }

        var witnesses = new JsonArray();
        foreach(WebVhController controller in witness.Witnesses)
        {
            witnesses.Add(new JsonObject { ["id"] = controller.WitnessId });
        }

        parameters["witness"] = new JsonObject
        {
            ["threshold"] = witness.Threshold,
            ["witnesses"] = witnesses
        };
    }


    /// <summary>Mints a <c>did-witness.json</c> file: each approval signs <c>JCS({"versionId"})</c> with its witnesses.</summary>
    public static async Task<string> MintWitnessFileAsync(IReadOnlyList<WebVhWitnessApproval> approvals)
    {
        var records = new JsonArray();
        foreach(WebVhWitnessApproval approval in approvals)
        {
            var proofs = new JsonArray();
            foreach(WebVhController witness in approval.Witnesses)
            {
                proofs.Add(await SignWitnessProofAsync(approval.VersionId, witness, approval.Created).ConfigureAwait(false));
            }

            records.Add(new JsonObject
            {
                ["versionId"] = approval.VersionId,
                ["proof"] = proofs
            });
        }

        return records.ToJsonString();
    }


    //Signs one witness proof over JCS({"versionId": versionId}); eddsa-jcs-2022 signs
    //SHA-256(JCS(proofOptions)) concatenated with SHA-256(JCS(document)).
    private static async Task<JsonObject> SignWitnessProofAsync(string versionId, WebVhController witness, string created)
    {
        JsonObject document = new() { ["versionId"] = versionId };
        JsonObject proofOptions = new()
        {
            ["type"] = "DataIntegrityProof",
            ["cryptosuite"] = "eddsa-jcs-2022",
            ["created"] = created,
            ["verificationMethod"] = witness.VerificationMethod,
            ["proofPurpose"] = "assertionMethod"
        };

        using IMemoryOwner<byte> hashOwner = BaseMemoryPool.Shared.Rent(64);
        Memory<byte> hashData = hashOwner.Memory[..64];
        HashCanonical(proofOptions.ToJsonString(), hashData.Span[..32]);
        HashCanonical(document.ToJsonString(), hashData.Span[32..]);

        string proofValue = await witness.SignProofValueAsync(hashData).ConfigureAwait(false);
        proofOptions["proofValue"] = proofValue;

        return proofOptions;
    }


    /// <summary>
    /// Mints a did:webvh <c>whois.vp</c>: a static linked Verifiable Presentation signed by <paramref name="authController"/>
    /// (the DID's authentication key) over a credential whose <c>credentialSubject.id</c> is <paramref name="did"/>.
    /// </summary>
    /// <remarks>
    /// This mirrors the production bound presentation <c>SignAsync</c> exactly MINUS the <c>challenge</c>/<c>domain</c>
    /// replay binding, so the resolver-side <c>VerifyLinkedPresentationAsync</c> (which is fail-closed against a bound
    /// proof) verifies it. With <paramref name="boundChallenge"/>/<paramref name="boundDomain"/> supplied, the proof
    /// instead carries the binding, producing a presentation the static verify MUST reject.
    /// </remarks>
    public static async Task<string> MintWhoisPresentationAsync(
        string did,
        WebVhController authController,
        string created,
        PresentationSerializeDelegate serializePresentation,
        ProofOptionsSerializeDelegate serializeProofOptions,
        string? boundChallenge = null,
        string? boundDomain = null,
        string? verificationMethodId = null)
    {
        VerifiablePresentation unsignedPresentation = new()
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = did,
            VerifiableCredential = [BuildWhoisCredential(did)]
        };

        //The proof MAY reference a parallel did:web DID's verification method (an alsoKnownAs DID) rather than
        //the did:webvh DID's; the signing key is the same, so the bytes are signed over the referenced id.
        DataIntegrityProof newProof = new()
        {
            Type = DataIntegrityProof.DataIntegrityProofType,
            Cryptosuite = EddsaJcs2022CryptosuiteInfo.Instance,
            Created = created,
            VerificationMethod = new AuthenticationMethod(verificationMethodId ?? $"{did}#key-1"),
            ProofPurpose = AuthenticationMethod.Purpose
        };

        if(boundChallenge is not null)
        {
            newProof.Challenge = boundChallenge;
        }

        if(boundDomain is not null)
        {
            newProof.Domain = [boundDomain];
        }

        ProofOptionsDocument proofOptions = ProofOptionsDocument.FromProof(newProof, null);
        string proofOptionsSerialized = serializeProofOptions(proofOptions);
        string presentationSerialized = serializePresentation(unsignedPresentation);

        //eddsa-jcs-2022 signs SHA-256(JCS(proofOptions)) concatenated with SHA-256(JCS(presentation)).
        using IMemoryOwner<byte> hashOwner = BaseMemoryPool.Shared.Rent(64);
        Memory<byte> hashData = hashOwner.Memory[..64];
        HashCanonical(proofOptionsSerialized, hashData.Span[..32]);
        HashCanonical(presentationSerialized, hashData.Span[32..]);

        newProof.ProofValue = await authController.SignProofValueAsync(hashData).ConfigureAwait(false);

        DataIntegritySecuredPresentation securedPresentation = new()
        {
            Context = unsignedPresentation.Context,
            Type = unsignedPresentation.Type,
            Holder = unsignedPresentation.Holder,
            VerifiableCredential = unsignedPresentation.VerifiableCredential,
            Proof = [newProof]
        };

        return serializePresentation(securedPresentation);
    }


    //A minimal Verifiable Credential whose single credentialSubject.id is the DID — the whois conformance
    //requirement is only that the VP carries at least one credential ABOUT the DID; it need not be independently
    //signed (the VP itself is the signed object).
    private static VerifiableCredential BuildWhoisCredential(string did)
    {
        return new VerifiableCredential
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiableCredential"],
            CredentialSubject = [new CredentialSubject { Id = did }]
        };
    }


    private static async Task<JsonObject> SignAsync(JsonObject entry, WebVhEntryPlan plan)
    {
        JsonObject document = JsonNode.Parse(entry.ToJsonString())!.AsObject();
        document.Remove("proof");

        JsonObject proofOptions = new()
        {
            ["type"] = "DataIntegrityProof",
            ["cryptosuite"] = "eddsa-jcs-2022",
            ["created"] = plan.VersionTime,
            ["verificationMethod"] = plan.Signer.VerificationMethod,
            ["proofPurpose"] = "assertionMethod"
        };

        //eddsa-jcs-2022 signs SHA-256(JCS(proofOptions)) concatenated with SHA-256(JCS(document)).
        using IMemoryOwner<byte> hashOwner = BaseMemoryPool.Shared.Rent(64);
        Memory<byte> hashData = hashOwner.Memory[..64];
        HashCanonical(proofOptions.ToJsonString(), hashData.Span[..32]);
        HashCanonical(document.ToJsonString(), hashData.Span[32..]);

        string proofValue = await plan.Signer.SignProofValueAsync(hashData).ConfigureAwait(false);
        proofOptions["proofValue"] = proofValue;

        return proofOptions;
    }


    //base58btc(multihash(JCS(json), SHA-256)), wrapping the JCS serializer output as JSON-tagged memory.
    private static string ComputeBase58OfCanonical(string json)
    {
        var canonical = new TaggedMemory<byte>(Jcs.CanonicalizeToUtf8Bytes(json), BufferTags.Json);

        return WebVhHash.ComputeBase58(canonical.Span, Hash, Base58Encoder);
    }


    //Hashes the JCS canonicalization of a JSON object into a destination span.
    private static void HashCanonical(string json, Span<byte> destination)
    {
        var canonical = new TaggedMemory<byte>(Jcs.CanonicalizeToUtf8Bytes(json), BufferTags.Json);
        Hash(canonical.Span, destination);
    }


    private static JsonObject BuildState(
        string id,
        JsonArray? alsoKnownAs = null,
        WebVhController? authentication = null,
        string? explicitFilesServiceEndpoint = null,
        string? explicitFilesServiceEndpointMap = null,
        string? explicitWhoisServiceEndpoint = null)
    {
        var state = new JsonObject
        {
            ["@context"] = new JsonArray("https://www.w3.org/ns/did/v1"),
            ["id"] = id
        };

        if(alsoKnownAs is not null)
        {
            state["alsoKnownAs"] = alsoKnownAs;
        }

        //An authentication verification method backed by the controller's Ed25519 multikey, so a whois
        //presentation signed by that key resolves through the holder's authentication relationship and
        //verifies against this resolved document. The type is "Multikey" (publicKeyMultibase): the crypto
        //converter dispatches on the key format, and the JSON layer recognizes the "Multikey" type name.
        if(authentication is { } authenticationKey)
        {
            string verificationMethodId = $"{id}#key-1";
            state["verificationMethod"] = new JsonArray(new JsonObject
            {
                ["id"] = verificationMethodId,
                ["type"] = AuthenticationVerificationMethodType,
                ["controller"] = id,
                ["publicKeyMultibase"] = authenticationKey.Multikey
            });
            state["authentication"] = new JsonArray(verificationMethodId);
        }

        //Explicit #files / #whois services override the implicit services the resolver would otherwise
        //synthesize (did:webvh v1.0, DID URL Resolution). A #files override is used to mint a non-HTTP(S)
        //endpoint (the invalidDid path test), a serviceEndpoint MAP form (the map-resolution test), or a string
        //endpoint; a #whois override points the whois dereference at a different HTTP(S) location.
        var services = new JsonArray();

        if(explicitFilesServiceEndpoint is not null)
        {
            services.Add(new JsonObject
            {
                ["id"] = $"{id}{WellKnownWebVhValues.FilesServiceFragment}",
                ["type"] = WellKnownServiceTypes.RelativeRef,
                ["serviceEndpoint"] = explicitFilesServiceEndpoint
            });
        }

        if(explicitFilesServiceEndpointMap is not null)
        {
            //The serviceEndpoint MAP form: the endpoint URL is a member value of an object, not a bare string.
            services.Add(new JsonObject
            {
                ["id"] = $"{id}{WellKnownWebVhValues.FilesServiceFragment}",
                ["type"] = WellKnownServiceTypes.RelativeRef,
                ["serviceEndpoint"] = new JsonObject { ["uri"] = explicitFilesServiceEndpointMap }
            });
        }

        if(explicitWhoisServiceEndpoint is not null)
        {
            services.Add(new JsonObject
            {
                ["id"] = $"{id}{WellKnownWebVhValues.WhoisServiceFragment}",
                ["type"] = WellKnownServiceTypes.LinkedVerifiablePresentation,
                ["serviceEndpoint"] = explicitWhoisServiceEndpoint
            });
        }

        if(services.Count > 0)
        {
            state["service"] = services;
        }

        return state;
    }


    /// <summary>The verification-method type minted for an authentication key: a multibase Multikey.</summary>
    public const string AuthenticationVerificationMethodType = "Multikey";


    private static JsonArray ToJsonArray(ImmutableArray<string> values)
    {
        var array = new JsonArray();
        foreach(string value in values)
        {
            array.Add(value);
        }

        return array;
    }


    private const string ScidPlaceholder = "{SCID}";
}


/// <summary>
/// A did:webvh DID controller backed by a freshly generated Ed25519 key: its multikey form for the
/// <c>updateKeys</c> list, the <c>did:key</c> verificationMethod its proofs reference, and the eddsa-jcs-2022
/// signing used to produce each entry's proofValue.
/// </summary>
internal sealed class WebVhController: IDisposable
{
    private readonly PublicKeyMemory publicKeyMemory;
    private readonly PrivateKey privateKey;

    private WebVhController(PublicKeyMemory publicKeyMemory, PrivateKey privateKey, string multikey)
    {
        this.publicKeyMemory = publicKeyMemory;
        this.privateKey = privateKey;
        Multikey = multikey;
    }


    /// <summary>The Ed25519 public key in multikey form, as it appears in an <c>updateKeys</c> list.</summary>
    public string Multikey { get; }

    /// <summary>The <c>did:key</c> verificationMethod a controller proof references.</summary>
    public string VerificationMethod => $"did:key:{Multikey}#{Multikey}";

    /// <summary>The bare <c>did:key</c> DID this controller is identified by in a witness list.</summary>
    public string WitnessId => $"did:key:{Multikey}";

    /// <summary>The pre-rotation commitment hash of this key's multikey, for a previous entry's <c>nextKeyHashes</c>.</summary>
    public string KeyHash => WebVhHash.ComputeBase58(Encoding.UTF8.GetBytes(Multikey), WebVhTestLog.Hash, WebVhTestLog.Base58Encoder);


    /// <summary>Generates a new Ed25519 controller key.</summary>
    public static WebVhController Create()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
        string multikey = MultibaseSerializer.EncodeKey(keys.PublicKey, WebVhTestLog.Base58Encoder);
        PrivateKey signingKey = CryptographicKeyFactory.CreatePrivateKey(keys.PrivateKey, "webvh-test", keys.PrivateKey.Tag);

        return new WebVhController(keys.PublicKey, signingKey, multikey);
    }


    /// <summary>Signs the eddsa-jcs-2022 hash data and encodes the signature as a multibase proofValue.</summary>
    public async Task<string> SignProofValueAsync(ReadOnlyMemory<byte> hashData)
    {
        using Signature signature = await privateKey.SignAsync(hashData, BaseMemoryPool.Shared).ConfigureAwait(false);

        return ProofValueCodecs.EncodeBase58Btc(signature.AsReadOnlyMemory().Span, WebVhTestLog.Base58Encoder, BaseMemoryPool.Shared);
    }


    public void Dispose()
    {
        privateKey.Dispose();
        publicKeyMemory.Dispose();
    }
}


/// <summary>One did:webvh log entry to mint: who signs it and the parameters it declares.</summary>
/// <param name="Signer">The controller whose key signs this entry.</param>
/// <param name="UpdateKeys">The <c>updateKeys</c> this entry declares.</param>
/// <param name="NextKeyHashes">The <c>nextKeyHashes</c> this entry declares, or <see langword="null"/> to omit them.</param>
/// <param name="Deactivated">Whether this entry declares <c>deactivated</c>.</param>
/// <param name="VersionTime">The entry's <c>versionTime</c>.</param>
/// <param name="Witness">The <c>witness</c> parameter this entry declares, or <see langword="null"/> to omit it.</param>
/// <param name="Portable">Whether the genesis entry declares <c>portable: true</c>.</param>
/// <param name="MoveToDomain">When set, this entry moves the DID to a new domain (changes the DIDDoc <c>id</c>).</param>
/// <param name="SuppressAlsoKnownAs">When moving, omit the prior DID from <c>alsoKnownAs</c> (for negative tests).</param>
/// <param name="MalformAlsoKnownAs">When moving, add a non-string member to <c>alsoKnownAs</c> (for negative tests).</param>
/// <param name="Watchers">The <c>watchers</c> parameter this entry declares, or <see langword="null"/> to omit it.</param>
/// <param name="Authentication">An optional controller whose Ed25519 key is emitted as a genesis <c>authentication</c> verification method, so a whois presentation signed by it verifies against the resolved document.</param>
/// <param name="ExplicitFilesServiceEndpoint">An optional explicit <c>#files</c> serviceEndpoint that overrides the implicit one (for example a non-HTTP(S) scheme, for negative dereferencing tests).</param>
/// <param name="ExplicitFilesServiceEndpointMap">An optional explicit <c>#files</c> serviceEndpoint expressed as a map (the URL is a member value), overriding the implicit service.</param>
/// <param name="ExplicitWhoisServiceEndpoint">An optional explicit <c>#whois</c> serviceEndpoint at a different HTTP(S) location, overriding the implicit whois service.</param>
internal sealed record WebVhEntryPlan(
    WebVhController Signer,
    ImmutableArray<string> UpdateKeys,
    ImmutableArray<string>? NextKeyHashes,
    bool Deactivated,
    string VersionTime,
    WebVhWitnessSpec? Witness = null,
    bool Portable = false,
    string? MoveToDomain = null,
    bool SuppressAlsoKnownAs = false,
    bool MalformAlsoKnownAs = false,
    ImmutableArray<string>? Watchers = null,
    WebVhController? Authentication = null,
    string? ExplicitFilesServiceEndpoint = null,
    string? ExplicitFilesServiceEndpointMap = null,
    string? ExplicitWhoisServiceEndpoint = null,
    string? MoveChangeScid = null,
    ImmutableArray<string>? GenesisAlsoKnownAs = null);


/// <summary>
/// The <c>witness</c> parameter an entry plan declares: the empty object <c>{}</c> (<see cref="Disable"/>) or a
/// rule of a threshold over a set of witness controllers (<see cref="Rule"/>). The threshold is carried as a
/// nullable integer so a malformed (for example, out-of-range or missing) threshold can be minted for
/// negative tests.
/// </summary>
internal sealed record WebVhWitnessSpec
{
    public bool IsDisable { get; private init; }

    public int? Threshold { get; private init; }

    public ImmutableArray<WebVhController> Witnesses { get; private init; } = ImmutableArray<WebVhController>.Empty;

    /// <summary>The empty witness object <c>{}</c> that disables witnessing.</summary>
    public static WebVhWitnessSpec Disable { get; } = new() { IsDisable = true };

    /// <summary>A witness rule of <paramref name="threshold"/> over <paramref name="witnesses"/>.</summary>
    public static WebVhWitnessSpec Rule(int? threshold, params WebVhController[] witnesses) =>
        new() { Threshold = threshold, Witnesses = [.. witnesses] };
}


/// <summary>One <c>did-witness.json</c> record to mint: the witnesses approving a <c>versionId</c>.</summary>
/// <param name="VersionId">The <c>versionId</c> being approved.</param>
/// <param name="Witnesses">The witness controllers that sign the approval.</param>
/// <param name="Created">The proof <c>created</c> timestamp.</param>
internal sealed record WebVhWitnessApproval(
    string VersionId,
    ImmutableArray<WebVhController> Witnesses,
    string Created);


/// <summary>A minted did:webvh log: the JSON Lines, the SCID, the resolved DID, and each entry's versionId.</summary>
/// <param name="Lines">The <c>did.jsonl</c> lines, in order.</param>
/// <param name="Scid">The self-certifying identifier.</param>
/// <param name="Did">The resolved <c>did:webvh</c> identifier.</param>
/// <param name="VersionIds">Each entry's <c>versionId</c>, in order.</param>
internal sealed record WebVhMintedLog(
    ImmutableArray<string> Lines,
    string Scid,
    string Did,
    ImmutableArray<string> VersionIds);
