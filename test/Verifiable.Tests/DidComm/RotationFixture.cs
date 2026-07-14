using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.DidComm;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Builds the real-key DID Rotation test environment for <see cref="DidCommFromPriorTests"/>: a prior
/// <c>did:key</c> Ed25519 DID (whose authentication key signs the <c>from_prior</c> JWT), a new
/// <c>did:key</c> Ed25519 DID, and a <see cref="DidResolver"/> resolving <c>did:key</c> (Ed25519 signing
/// and X25519 key-agreement variants alike). The semantic from_prior tests run over the anoncrypt path
/// (which authenticates no sender, so the rotation verify is exercised in isolation, with <c>from</c> the
/// Ed25519 new DID); a single authcrypt round trip proves the spec-MUST encrypted path wires the verify;
/// and the signed path proves reference-impl parity.
/// </summary>
internal sealed class RotationFixture: IAsyncDisposable
{
    //The protected-header serializer the JWE / authcrypt layer hands a Dictionary<string, object> to.
    private static readonly JwtHeaderSerializer JweHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    //A fixed rotation datetime injected as iat — the clock seam, not DateTime.UtcNow.
    private static readonly DateTimeOffset RotationTime = DateTimeOffset.FromUnixTimeSeconds(1516239022);

    private readonly ExchangeContext context = new();
    private readonly MemoryPool<byte> pool;
    private readonly PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> priorKeys;
    private readonly PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> newSignKeys;
    private readonly DidDocument priorDocument;
    private readonly string newSignKid;


    private RotationFixture(
        MemoryPool<byte> pool,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> priorKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> newSignKeys,
        DidDocument priorDocument,
        string priorDid,
        string priorKid,
        string newDid,
        string newSignKid)
    {
        this.pool = pool;
        this.priorKeys = priorKeys;
        this.newSignKeys = newSignKeys;
        this.priorDocument = priorDocument;
        this.newSignKid = newSignKid;
        PriorDid = priorDid;
        PriorKid = priorKid;
        NewDid = newDid;
    }


    public string PriorDid { get; }

    public string PriorKid { get; }

    public string NewDid { get; }

    public PrivateKeyMemory PriorSigningKey => priorKeys.PrivateKey;


    public static async ValueTask<RotationFixture> CreateAsync(MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> priorKeys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> newSignKeys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();

        DidDocument priorDocument = await new KeyDidBuilder().BuildAsync(
            priorKeys.PublicKey, MultikeyVerificationMethodTypeInfo.Instance, cancellationToken: cancellationToken).ConfigureAwait(false);

        DidDocument newSignDocument = await new KeyDidBuilder().BuildAsync(
            newSignKeys.PublicKey, MultikeyVerificationMethodTypeInfo.Instance, cancellationToken: cancellationToken).ConfigureAwait(false);

        string priorDid = priorDocument.Id!.Id;
        string priorKid = AuthenticationKid(priorDocument, priorDid);
        string newDid = newSignDocument.Id!.Id;
        string newSignKid = AuthenticationKid(newSignDocument, newDid);

        return new RotationFixture(pool, priorKeys, newSignKeys, priorDocument, priorDid, priorKid, newDid, newSignKid);
    }


    //Mints the from_prior JWT for the message via the production PackFromPriorAsync registry overload. The
    //message `from` (when present) is the new DID and becomes the JWT sub.
    public ValueTask MintFromPriorAsync(DidCommMessage message, CancellationToken cancellationToken)
    {
        return message.PackFromPriorAsync(
            PriorDid,
            PriorKid,
            PriorSigningKey,
            RotationTime,
            JwtClaimsJson.HeaderSerializer,
            JwtClaimsJson.PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            pool,
            cancellationToken);
    }


    //Mints an adversarial from_prior compact JWT with caller-controlled typ/kid/iss/sub, signed by the
    //prior DID's authentication key — bypassing PackFromPriorAsync's own guards so the consumer's MUSTs are
    //proven independently of producer enforcement.
    public async ValueTask<string> MintRawFromPriorAsync(string typ, string kid, string iss, string? sub, CancellationToken cancellationToken, string? alg = null)
    {
        var header = new JwtHeader
        {
            [WellKnownJoseHeaderNames.Typ] = typ,
            //alg defaults to the truthful EdDSA; a test may inject a LYING alg (the signature stays a real
            //Ed25519 one) to prove verify ignores the header alg and resolves the algorithm from the
            //prior-DID key — the algorithm-substitution defense.
            [WellKnownJwkMemberNames.Alg] = alg ?? WellKnownJwaValues.EdDsa,
            [WellKnownJwkMemberNames.Kid] = kid
        };

        var payload = new JwtPayload
        {
            [WellKnownJwtClaimNames.Iss] = iss,
            [WellKnownJwtClaimNames.Iat] = RotationTime.ToUnixTimeSeconds()
        };

        if(sub is not null)
        {
            payload[WellKnownJwtClaimNames.Sub] = sub;
        }

        var unsigned = new UnsignedJwt(header, payload);

        using JwsMessage jws = await unsigned.SignAsync(
            PriorSigningKey,
            JwtClaimsJson.HeaderSerializer,
            JwtClaimsJson.PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    //Packs the message anoncrypt to a fresh X25519 recipient and unpacks it, threading the from_prior
    //verifiers. Anoncrypt authenticates no sender, so the from_prior verify against the PRIOR DID is the
    //only DID resolution — the rotation semantics are exercised in isolation. The `from` is left as the
    //caller set it. The failing-resolver variant fails the prior-DID resolution inside the rotation verify.
    public async ValueTask<DidCommEncryptedUnpackResult> PackAndUnpackAnoncryptAsync(DidCommMessage message, CancellationToken cancellationToken, bool useFailingResolver = false, DidResolver? resolverOverride = null)
    {
        (string recipientKid, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipientKeys, _) =
            await CreateX25519DidAsync(cancellationToken: cancellationToken).ConfigureAwait(false);

        using PublicKeyMemory recipientPublic = recipientKeys.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipientKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(recipientKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await message.PackAnoncryptAsync(
            recipients,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            JweHeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        DidResolver resolver = resolverOverride ?? BuildResolver(useFailingResolver);

        return await encrypted.UnpackAnoncryptAsync(
            recipientKid,
            recipientPrivate,
            resolver,
            context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            pool,
            JwtClaimsJson.PayloadDeserializer,
            JwtClaimsJson.HeaderDeserializer,
            cancellationToken: cancellationToken);
    }


    //The spec-MUST encrypted rotation: the new DID is an X25519 did:key sender (its keyAgreement key is the
    //authcrypt skid and `from`), so the from_prior is minted with sub = that DID and the message is packed
    //authcrypt to a fresh recipient. Returns the unpack result and the new (X25519) DID for assertions.
    public async ValueTask<(DidCommEncryptedUnpackResult Result, string NewDid)> PackAndUnpackAuthcryptRotationAsync(DidCommMessage message, CancellationToken cancellationToken)
    {
        (string senderSkid, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> senderKeys, DidDocument senderDocument) =
            await CreateX25519DidAsync(cancellationToken: cancellationToken).ConfigureAwait(false);

        using PublicKeyMemory senderPublic = senderKeys.PublicKey;
        using PrivateKeyMemory senderPrivate = senderKeys.PrivateKey;

        //The new DID is the X25519 sender; `from` is bound to the sender skid's DID by the authcrypt
        //addressing-consistency MUST, and the from_prior sub MUST equal it.
        string newAuthcryptDid = senderDocument.Id!.Id;
        message.From = newAuthcryptDid;
        await MintFromPriorAsync(message, cancellationToken: cancellationToken).ConfigureAwait(false);

        (string recipientKid, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipientKeys, _) =
            await CreateX25519DidAsync(cancellationToken: cancellationToken).ConfigureAwait(false);

        using PublicKeyMemory recipientPublic = recipientKeys.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipientKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(recipientKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await message.PackAuthcryptAsync(
            recipients,
            senderSkid,
            senderPrivate,
            WellKnownJweAlgorithms.Ecdh1PuA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            DidCommMessageJson.Serializer,
            JweHeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.Ecdh1PuMultiRecipientAgreementEncryptX25519Async,
            ConcatKdf.DefaultAuthenticatedKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        DidResolver resolver = BuildResolver(useFailingResolver: false);

        DidCommEncryptedUnpackResult result = await encrypted.UnpackAuthcryptAsync(
            recipientKid,
            recipientPrivate,
            resolver,
            context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            pool,
            JwtClaimsJson.PayloadDeserializer,
            JwtClaimsJson.HeaderDeserializer,
            cancellationToken: cancellationToken);

        return (result, newAuthcryptDid);
    }


    //Signs the message with the new DID's Ed25519 authentication key and unpacks it through the signed
    //path, threading the from_prior verifiers (reference-impl parity). The message `from` is the Ed25519
    //new DID, satisfying the signed-message addressing-consistency MUST.
    public async ValueTask<DidCommSignedVerificationResult> PackAndUnpackSignedAsync(DidCommMessage message, CancellationToken cancellationToken)
    {
        using DidCommSignedMessage signed = await message.PackSignedAsync(
            newSignKeys.PrivateKey,
            newSignKid,
            DidCommMessageJson.Serializer,
            DidCommSignedMessageJson.ProtectedHeaderEncoder,
            DidCommSignedMessageJson.Serializer,
            TestSetup.Base64UrlEncoder,
            pool,
            JoseSerializationFormat.GeneralJson,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        DidResolver resolver = BuildResolver(useFailingResolver: false);

        return await signed.UnpackSignedAsync(
            resolver,
            context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            pool,
            JwtClaimsJson.PayloadDeserializer,
            JwtClaimsJson.HeaderDeserializer,
            cancellationToken: cancellationToken);
    }


    //Signs the inner message with the new DID's Ed25519 key, anoncrypts the signed JWM to a fresh X25519
    //recipient, and unpacks it threading the from_prior verifiers — the nested signed-then-encrypted rotation
    //path (C1/C2): a valid from_prior on the inner signed JWM MUST be verified, not force-rejected. The inner
    //signed JWM MUST carry a `to` naming the recipient (the surreptitious-forwarding gate).
    public async ValueTask<DidCommEncryptedUnpackResult> PackSignedThenAnoncryptAndUnpackAsync(DidCommMessage innerMessage, CancellationToken cancellationToken)
    {
        (string recipientKid, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipientKeys, DidDocument recipientDocument) =
            await CreateX25519DidAsync(cancellationToken: cancellationToken).ConfigureAwait(false);

        using PublicKeyMemory recipientPublic = recipientKeys.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipientKeys.PrivateKey;

        innerMessage.To = [recipientDocument.Id!.Id];

        using DidCommSignedMessage signed = await innerMessage.PackSignedAsync(
            newSignKeys.PrivateKey,
            newSignKid,
            DidCommMessageJson.Serializer,
            DidCommSignedMessageJson.ProtectedHeaderEncoder,
            DidCommSignedMessageJson.Serializer,
            TestSetup.Base64UrlEncoder,
            pool,
            JoseSerializationFormat.GeneralJson,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        var recipients = new List<GeneralJweRecipientInput> { new(recipientKid, recipientPublic) };

        using DidCommEncryptedMessage encrypted = await signed.PackAnoncryptAsync(
            recipients,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256CbcHs512,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            JweHeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync,
            pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        DidResolver resolver = BuildResolver(useFailingResolver: false);

        return await encrypted.UnpackAnoncryptAsync(
            recipientKid,
            recipientPrivate,
            resolver,
            context,
            DidCommMessageJson.Parser,
            DidCommSignedMessageJson.Parser,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
            MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync,
            pool,
            JwtClaimsJson.PayloadDeserializer,
            JwtClaimsJson.HeaderDeserializer,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    //Whether the resolved prior-DID document authorizes the prior kid for the authentication relationship.
    public bool IsPriorKidAuthorizedForAuthentication()
    {
        foreach(VerificationMethod method in priorDocument.GetLocalAuthenticationMethods())
        {
            string kid = method.Id!.StartsWith('#') ? PriorDid + method.Id : method.Id;
            if(string.Equals(kid, PriorKid, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    //Builds the did:key resolver (Ed25519 signing + X25519 key-agreement variants are all pure did:key, so
    //one resolver resolves the prior DID, the new DID, and the freshly-minted sender/recipient DIDs). The
    //failing variant rejects every resolution to exercise the unresolvable-prior-DID path.
    private DidResolver BuildResolver(bool useFailingResolver)
    {
        if(useFailingResolver)
        {
            return new DidResolver(DidMethodSelectors.FromResolvers(
                (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));
        }

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(pool))));
    }


    //Builds a resolver that returns the prior DID's document with its authentication relationship removed but
    //assertionMethod intact: the prior kid is a real, validly-signing verification method that IS in the
    //document, but authorized only for assertionMethod. §DID Rotation requires the kid be authorized for the
    //AUTHENTICATION relationship, so the rotation MUST still be rejected — this locks the relationship-scoping
    //gate against a regression that a kid-in-no-relationship test would not catch.
    public DidResolver BuildAuthenticationStrippedPriorResolver()
    {
        var assertionOnlyDocument = new DidDocument
        {
            Id = priorDocument.Id,
            Context = priorDocument.Context,
            VerificationMethod = priorDocument.VerificationMethod,
            AssertionMethod = priorDocument.AssertionMethod
        };

        DidMethodResolverDelegate keyResolver = KeyDidResolver.Build(pool);

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix,
                (did, options, exchangeContext, cancellationToken) =>
                    string.Equals(did, PriorDid, StringComparison.Ordinal)
                        ? ValueTask.FromResult(DidResolutionResult.Success(assertionOnlyDocument, DidDocumentMetadata.Empty))
                        : keyResolver(did, options, exchangeContext, cancellationToken))));
    }


    //Mints a fresh did:key X25519 (key-agreement) DID and returns its keyAgreement kid, the keypair, and
    //the built document.
    private async ValueTask<(string Kid, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Keys, DidDocument Document)> CreateX25519DidAsync(CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateX25519Keys(pool);

        DidDocument document = await new KeyDidBuilder().BuildAsync(
            keys.PublicKey, MultikeyVerificationMethodTypeInfo.Instance, cancellationToken: cancellationToken).ConfigureAwait(false);

        string did = document.Id!.Id;
        string kid = KeyAgreementKid(document, did);

        return (kid, keys, document);
    }


    //The fully-qualified authentication verification-method id of a did:key Ed25519 document.
    private static string AuthenticationKid(DidDocument document, string did)
    {
        VerificationMethod method = document.GetLocalAuthenticationMethods()[0];

        return method.Id!.StartsWith('#') ? did + method.Id : method.Id!;
    }


    //The fully-qualified keyAgreement verification-method id of a did:key X25519 document.
    private static string KeyAgreementKid(DidDocument document, string did)
    {
        VerificationMethod method = document.GetLocalKeyAgreementMethods()[0];

        return method.Id!.StartsWith('#') ? did + method.Id : method.Id!;
    }


    public ValueTask DisposeAsync()
    {
        priorKeys.PublicKey.Dispose();
        priorKeys.PrivateKey.Dispose();
        newSignKeys.PublicKey.Dispose();
        newSignKeys.PrivateKey.Dispose();

        return ValueTask.CompletedTask;
    }
}
