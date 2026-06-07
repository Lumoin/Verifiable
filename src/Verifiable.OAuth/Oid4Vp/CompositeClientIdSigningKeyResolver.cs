using System.Buffers;
using System.Diagnostics;
using System.Security;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.OAuth.Federation;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Builds <see cref="ResolveClientIdSigningKeyAsyncDelegate"/> instances
/// that dispatch by <see cref="WellKnownClientIdPrefixes"/> prefix to the
/// registered per-prefix handler. Also provides handler-builder factories
/// for the well-known prefixes shipped by the library —
/// <c>x509_san_dns:</c> via
/// <see cref="X509SanDnsKeyResolver"/> and <c>openid_federation:</c> via
/// <see cref="FederationBoundJarKeyResolver"/>.
/// </summary>
/// <remarks>
/// <para>
/// Wallets that integrate multiple prefixes wire a single
/// <see cref="ResolveClientIdSigningKeyAsyncDelegate"/> slot; the
/// deployment composes the slot from per-prefix handlers it cares about.
/// New prefixes added later compose without changing the wallet's
/// integration point — just a new entry in the handlers map.
/// </para>
/// <para>
/// Three handler factories ship with the library, one per HAIP-mandatory
/// prefix plus the federation prefix:
/// <see cref="BuildVerifierAttestationHandler"/>,
/// <see cref="BuildX509SanDnsHandler"/>, and
/// <see cref="BuildOpenIdFederationHandler"/>. Each composes against the
/// underlying library-side resolver (
/// <see cref="VerifierAttestationKeyResolver"/>,
/// <see cref="X509SanDnsKeyResolver"/>, and
/// <see cref="FederationBoundJarKeyResolver"/> respectively).
/// </para>
/// </remarks>
[DebuggerDisplay("CompositeClientIdSigningKeyResolver")]
public static class CompositeClientIdSigningKeyResolver
{
    /// <summary>
    /// Builds a composite resolver. The returned delegate inspects the
    /// <c>client_id</c>'s prefix and dispatches to the matching handler
    /// from <paramref name="handlersByPrefix"/>; unrecognised prefixes
    /// throw <see cref="SecurityException"/>.
    /// </summary>
    /// <param name="handlersByPrefix">
    /// Handlers keyed by <see cref="ClientIdPrefix"/>. Match is ordinal-
    /// equal on the underlying prefix value (the <see cref="ClientIdPrefix"/>
    /// struct's <see cref="ClientIdPrefix.Equals(ClientIdPrefix)"/>).
    /// </param>
    public static ResolveClientIdSigningKeyAsyncDelegate Build(
        IReadOnlyDictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate> handlersByPrefix)
    {
        ArgumentNullException.ThrowIfNull(handlersByPrefix);

        //Snapshot so mutations after build don't change dispatch behaviour.
        Dictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate> snapshot = new(handlersByPrefix);

        return (context, clientId, jarHeader, ct) =>
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
            ArgumentNullException.ThrowIfNull(jarHeader);

            if(!WellKnownClientIdPrefixes.TryReadPrefix(clientId, out ClientIdPrefix prefix))
            {
                throw new SecurityException(
                    $"client_id '{clientId}' carries no recognised prefix; cannot dispatch.");
            }

            if(!snapshot.TryGetValue(prefix, out ResolveClientIdSigningKeyAsyncDelegate? handler))
            {
                throw new SecurityException(
                    $"No handler registered for client_id prefix '{prefix.Value}'.");
            }

            return handler(context, clientId, jarHeader, ct);
        };
    }


    /// <summary>
    /// Builds a handler for the <c>verifier_attestation:</c> prefix. The
    /// returned delegate extracts the attestation JWT from the JAR's
    /// <see cref="WellKnownJoseHeaderNames.Jwt"/> header, strips the prefix
    /// from the client_id, and calls
    /// <see cref="VerifierAttestationKeyResolver.ResolveAsync"/>.
    /// </summary>
    /// <remarks>
    /// The trust-anchor public key the attestation is verified against is read
    /// per-call from the threaded
    /// <see cref="Oid4VpExchangeContextExtensions.VerifierAttestationTrustAnchorKey"/>
    /// rather than captured, so one handler serves every tenant. The application
    /// owns the key's lifetime; this handler does not dispose it.
    /// </remarks>
    public static ResolveClientIdSigningKeyAsyncDelegate BuildVerifierAttestationHandler(
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> headerDeserializer,
        Func<ReadOnlySpan<byte>, Dictionary<string, object>> payloadDeserializer,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(payloadDeserializer);
        ArgumentNullException.ThrowIfNull(pool);

        return async (context, clientId, jarHeader, ct) =>
        {
            PublicKeyMemory trustAnchorPublicKey = context.VerifierAttestationTrustAnchorKey
                ?? throw new SecurityException(
                    "verifier_attestation: no trust-anchor public key on the ExchangeContext. " +
                    "The application must call ExchangeContext.SetVerifierAttestationTrustAnchorKey " +
                    "for the current tenant before driving the presentation.");

            string expectedClientId = WellKnownClientIdPrefixes.StripPrefix(clientId);
            if(string.IsNullOrWhiteSpace(expectedClientId))
            {
                throw new SecurityException(
                    $"client_id '{clientId}' yields an empty value after stripping the verifier_attestation: prefix.");
            }

            if(!jarHeader.TryGetValue(WellKnownJoseHeaderNames.Jwt, out object? jwtObj)
                || jwtObj is not string compactAttestation
                || string.IsNullOrWhiteSpace(compactAttestation))
            {
                throw new SecurityException(
                    "verifier_attestation: JAR must carry the attestation JWT in the 'jwt' JOSE header parameter.");
            }

            VerifierAttestationJwt attestation = new(compactAttestation);

            try
            {
                return await VerifierAttestationKeyResolver.ResolveAsync(
                    attestation,
                    expectedClientId,
                    trustAnchorPublicKey,
                    base64UrlDecoder,
                    headerDeserializer,
                    payloadDeserializer,
                    pool,
                    ct).ConfigureAwait(false);
            }
            catch(InvalidOperationException ex)
            {
                //VerifierAttestationKeyResolver throws InvalidOperationException for
                //attestation rejections; surface them as SecurityException to align
                //with the dispatcher's reject contract.
                throw new SecurityException(
                    $"verifier_attestation: attestation rejected: {ex.Message}", ex);
            }
        };
    }


    /// <summary>
    /// Builds a handler for the <c>openid_federation:</c> prefix. The
    /// returned delegate extracts the inline <c>trust_chain</c> header,
    /// strips the prefix from the client_id, and calls
    /// <see cref="FederationBoundJarKeyResolver.ResolveAsync"/>.
    /// </summary>
    /// <remarks>
    /// The federation trust anchors are read per-call from the threaded
    /// <see cref="Oid4VpExchangeContextExtensions.OpenIdFederationTrustAnchors"/>
    /// and the trust-chain validity instant from
    /// <see cref="ExchangeContextExtensions.ValidationTime"/>, rather than
    /// captured, so one handler serves every tenant. The clock-skew tolerance
    /// and the chain-validation algorithm are deployment-stable and stay
    /// captured.
    /// </remarks>
    public static ResolveClientIdSigningKeyAsyncDelegate BuildOpenIdFederationHandler(
        TimeSpan clockSkew,
        ValidateTrustChainAsyncDelegate validateChain,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        return async (context, clientId, jarHeader, ct) =>
        {
            IReadOnlyCollection<EntityIdentifier> trustAnchors = context.OpenIdFederationTrustAnchors
                ?? throw new SecurityException(
                    "openid_federation: no trust anchors on the ExchangeContext. " +
                    "The application must call ExchangeContext.SetOpenIdFederationTrustAnchors " +
                    "for the current tenant before driving the presentation.");
            DateTimeOffset validationTime = context.ValidationTime
                ?? throw new InvalidOperationException(
                    "openid_federation: no ValidationTime on the ExchangeContext. " +
                    "The operation driver must stamp ExchangeContext.SetValidationTime before resolving.");

            string strippedId = WellKnownClientIdPrefixes.StripPrefix(clientId);
            EntityIdentifier expectedSubject;
            try
            {
                expectedSubject = new EntityIdentifier(strippedId);
            }
            catch(ArgumentException ex)
            {
                throw new SecurityException(
                    $"client_id '{clientId}' is not a valid Entity Identifier after stripping the openid_federation: prefix.", ex);
            }

            if(!jarHeader.TryGetValue(WellKnownFederationClaimNames.TrustChain, out object? chainObj)
                || chainObj is not IEnumerable<object> chainItems)
            {
                throw new SecurityException(
                    "openid_federation: JAR must carry trust_chain as an array in its JOSE header.");
            }

            List<string> chainValues = [];
            foreach(object item in chainItems)
            {
                if(item is not string s || string.IsNullOrWhiteSpace(s))
                {
                    throw new SecurityException(
                        "trust_chain entries must be non-empty compact JWS strings.");
                }
                chainValues.Add(s);
            }

            return await FederationBoundJarKeyResolver.ResolveAsync(
                chainValues,
                expectedSubject,
                trustAnchors,
                validationTime,
                clockSkew,
                jarHeader,
                validateChain,
                base64UrlDecoder,
                pool,
                ct).ConfigureAwait(false);
        };
    }


    /// <summary>
    /// Builds a handler for the <c>x509_san_dns:</c> prefix. The returned
    /// delegate extracts the <c>x5c</c> JOSE header, strips the prefix to
    /// recover the expected DNS name, and calls
    /// <see cref="X509SanDnsKeyResolver.ResolveAsync"/>.
    /// </summary>
    /// <remarks>
    /// The X.509 trust anchors are read per-call from the threaded
    /// <see cref="Oid4VpExchangeContextExtensions.X509TrustAnchors"/> and the
    /// chain-validity instant from
    /// <see cref="ExchangeContextExtensions.ValidationTime"/>, rather than
    /// captured, so one handler serves every tenant. The x5c-parse,
    /// chain-validation, and DNS-SAN algorithms are deployment-stable platform
    /// functions and stay captured.
    /// </remarks>
    public static ResolveClientIdSigningKeyAsyncDelegate BuildX509SanDnsHandler(
        ParseX5cDelegate parseX5c,
        ValidateCertificateChainAsyncDelegate validateChain,
        VerifyDnsSanDelegate verifyDnsSan,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(parseX5c);
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(verifyDnsSan);
        ArgumentNullException.ThrowIfNull(pool);

        return async (context, clientId, jarHeader, ct) =>
        {
            IReadOnlyList<PkiCertificateMemory> trustAnchors = context.X509TrustAnchors
                ?? throw new SecurityException(
                    "x509_san_dns: no trust anchors on the ExchangeContext. " +
                    "The application must call ExchangeContext.SetX509TrustAnchors " +
                    "for the current tenant before driving the presentation.");
            DateTimeOffset validationTime = context.ValidationTime
                ?? throw new InvalidOperationException(
                    "x509_san_dns: no ValidationTime on the ExchangeContext. " +
                    "The operation driver must stamp ExchangeContext.SetValidationTime before resolving.");

            string expectedDnsName = WellKnownClientIdPrefixes.StripPrefix(clientId);
            if(string.IsNullOrWhiteSpace(expectedDnsName))
            {
                throw new SecurityException(
                    $"client_id '{clientId}' yields an empty DNS name after stripping the x509_san_dns: prefix.");
            }

            List<string> x5cValues = ReadX5cValues(jarHeader, WellKnownClientIdPrefixes.X509SanDns);

            return await X509SanDnsKeyResolver.ResolveAsync(
                x5cValues,
                expectedDnsName,
                trustAnchors,
                validationTime,
                parseX5c,
                validateChain,
                verifyDnsSan,
                pool,
                ct).ConfigureAwait(false);
        };
    }


    /// <summary>
    /// Builds a handler for the <c>x509_hash:</c> prefix. The returned delegate
    /// extracts the <c>x5c</c> JOSE header, strips the prefix to recover the expected
    /// base64url SHA-256 certificate hash, and calls
    /// <see cref="X509HashKeyResolver.ResolveAsync"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Mirrors <see cref="BuildX509SanDnsHandler"/>: the X.509 trust anchors are read
    /// per-call from the threaded
    /// <see cref="Oid4VpExchangeContextExtensions.X509TrustAnchors"/> and the
    /// chain-validity instant from
    /// <see cref="ExchangeContextExtensions.ValidationTime"/>, rather than captured,
    /// so one handler serves every tenant.
    /// </para>
    /// <para>
    /// The x5c-parse, chain-validation, self-signed, hash, and base64url functions are
    /// deployment-stable platform delegates and stay captured. OID4VP 1.0 §5.9.3 fixes
    /// the digest algorithm to SHA-256, so the application MUST wire a SHA-256
    /// implementation for <paramref name="hashFunction"/>.
    /// </para>
    /// </remarks>
    public static ResolveClientIdSigningKeyAsyncDelegate BuildX509HashHandler(
        ParseX5cDelegate parseX5c,
        ValidateCertificateChainAsyncDelegate validateChain,
        IsSelfSignedCertificateDelegate isSelfSigned,
        HashFunctionDelegate hashFunction,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(parseX5c);
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(isSelfSigned);
        ArgumentNullException.ThrowIfNull(hashFunction);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        return async (context, clientId, jarHeader, ct) =>
        {
            IReadOnlyList<PkiCertificateMemory> trustAnchors = context.X509TrustAnchors
                ?? throw new SecurityException(
                    "x509_hash: no trust anchors on the ExchangeContext. " +
                    "The application must call ExchangeContext.SetX509TrustAnchors " +
                    "for the current tenant before driving the presentation.");
            DateTimeOffset validationTime = context.ValidationTime
                ?? throw new InvalidOperationException(
                    "x509_hash: no ValidationTime on the ExchangeContext. " +
                    "The operation driver must stamp ExchangeContext.SetValidationTime before resolving.");

            string expectedCertificateHash = WellKnownClientIdPrefixes.StripPrefix(clientId);
            if(string.IsNullOrWhiteSpace(expectedCertificateHash))
            {
                throw new SecurityException(
                    $"client_id '{clientId}' yields an empty hash after stripping the x509_hash: prefix.");
            }

            List<string> x5cValues = ReadX5cValues(jarHeader, WellKnownClientIdPrefixes.X509Hash);

            return await X509HashKeyResolver.ResolveAsync(
                x5cValues,
                expectedCertificateHash,
                trustAnchors,
                validationTime,
                parseX5c,
                validateChain,
                isSelfSigned,
                hashFunction,
                base64UrlEncoder,
                pool,
                ct).ConfigureAwait(false);
        };
    }


    /// <summary>
    /// Builds a handler for the <c>decentralized_identifier:</c> prefix per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3">OID4VP 1.0 §5.9.3</see>.
    /// The returned delegate strips the prefix to recover the DID, reads the
    /// <c>kid</c> JOSE header to obtain the verification-method DID URL,
    /// validates that the kid's base DID matches the expected DID, dereferences
    /// it via <paramref name="didResolver"/>, and converts the resulting
    /// <see cref="VerificationMethod"/> into a <see cref="PublicKeyMemory"/>.
    /// </summary>
    /// <param name="didResolver">
    /// The configured DID resolver. Method handlers for the DID methods the
    /// deployment supports (e.g. <c>did:key</c>, <c>did:web</c>) must already
    /// be registered on <see cref="Verifiable.Core.Resolvers.DidResolver"/>.
    /// </param>
    /// <param name="pool">Memory pool for the decoded verification-method key bytes.</param>
    public static ResolveClientIdSigningKeyAsyncDelegate BuildDecentralizedIdentifierHandler(
        DidResolver didResolver,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(didResolver);
        ArgumentNullException.ThrowIfNull(pool);

        //The decentralized_identifier: path resolves the key by dereferencing the
        //DID URL in the kid. It carries no per-tenant trust anchors and is
        //time-independent, but the context is threaded into DereferenceAsync so a
        //network-fetching DID method applies the context's SSRF OutboundFetchPolicy.
        return async (context, clientId, jarHeader, ct) =>
        {
            string strippedDid = WellKnownClientIdPrefixes.StripPrefix(clientId);
            if(string.IsNullOrWhiteSpace(strippedDid))
            {
                throw new SecurityException(
                    $"client_id '{clientId}' yields an empty DID after stripping the decentralized_identifier: prefix.");
            }

            //§5.9.3 — the JAR's kid carries the absolute DID URL of the
            //verification method that signed the JAR. Reject if absent.
            if(!jarHeader.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj)
                || kidObj is not string kid
                || string.IsNullOrWhiteSpace(kid))
            {
                throw new SecurityException(
                    "decentralized_identifier: JAR must carry kid in the JOSE header as the verification method's DID URL.");
            }

            //Security check: the kid's base DID MUST equal the client_id DID.
            //An attacker who can present a JAR signed by a different DID must
            //not be able to satisfy verification just by sending the matching
            //kid value.
            string kidBaseDid = StripFragment(kid);
            if(!string.Equals(kidBaseDid, strippedDid, StringComparison.Ordinal))
            {
                throw new SecurityException(
                    $"decentralized_identifier: JAR kid '{kid}' references a different DID than the client_id '{strippedDid}'.");
            }

            DidDereferencingResult dereferenced = await didResolver.DereferenceAsync(
                kid, context, options: null, cancellationToken: ct).ConfigureAwait(false);

            if(!dereferenced.IsSuccessful
                || dereferenced.ContentStream is not VerificationMethod verificationMethod)
            {
                throw new SecurityException(
                    $"decentralized_identifier: failed to dereference kid '{kid}' to a verification method.");
            }

            (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> keyMaterial) decoded =
                VerificationMethodCryptoConversions.DefaultConverter(verificationMethod, pool);

            Tag tag = Tag.Create(
                (typeof(CryptoAlgorithm), decoded.algorithm),
                (typeof(Purpose), decoded.purpose),
                (typeof(EncodingScheme), decoded.scheme));

            return new PublicKeyMemory(decoded.keyMaterial, tag);
        };
    }


    /// <summary>
    /// Reads the <c>x5c</c> JOSE header as a non-empty list of base64-encoded DER
    /// strings, shared by the <c>x509_san_dns:</c> and <c>x509_hash:</c> handlers.
    /// </summary>
    /// <param name="jarHeader">The JAR's protected JOSE header.</param>
    /// <param name="prefix">
    /// The Client Identifier Prefix the calling handler serves; its
    /// <see cref="ClientIdPrefix.Value"/> labels the rejection message.
    /// </param>
    private static List<string> ReadX5cValues(UnverifiedJwtHeader jarHeader, ClientIdPrefix prefix)
    {
        if(!jarHeader.TryGetValue(WellKnownJwkMemberNames.X5c, out object? x5cObj)
            || x5cObj is not IEnumerable<object> x5cItems)
        {
            throw new SecurityException(
                $"{prefix.Value}: JAR must carry x5c as an array in its JOSE header.");
        }

        List<string> x5cValues = [];
        foreach(object item in x5cItems)
        {
            if(item is not string s || string.IsNullOrWhiteSpace(s))
            {
                throw new SecurityException(
                    "x5c entries must be non-empty base64-encoded DER strings.");
            }
            x5cValues.Add(s);
        }

        return x5cValues;
    }


    private static string StripFragment(string didUrl)
    {
        int hashIndex = didUrl.IndexOf('#', StringComparison.Ordinal);

        return hashIndex >= 0 ? didUrl[..hashIndex] : didUrl;
    }
}
