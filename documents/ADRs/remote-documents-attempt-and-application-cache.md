# Remote Documents: the Library Performs the Attempt, the Application Owns the Cache

## Context

`Verifiable.OAuth` fetches remote documents whose content decides what the authorization server trusts: a Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document-02), the JWK Set a `jwks_uri` names (RFC 7517 §5, reached from that document or from an RFC 7591 registration), and, on the client side, an authorization server's metadata (RFC 8414). Every such fetch goes through one chokepoint, `OutboundFetch.FetchAsync` in `Verifiable.Core`, driven by the application's `OutboundTransportDelegate` and policed by the `OutboundFetchPolicy` on the `ExchangeContext`; the library holds no HTTP client.

Above that chokepoint, `ClientIdMetadataDocuments.BuildResolving` was a factory that closed over an in-process `ConcurrentDictionary` keyed by the document URL, computed a lifetime from the response headers, clamped it by two options, and served hits without dialling. A key set discovered from the document's `jwks_uri` was folded into the document and cached under the document's key, so a rotated key stayed invisible until the document's own entry went stale. When the key-set fetch was lifted into its own resolver, it followed the same shape: a second factory, a second dictionary, its own lifetime bounds, and a thirty-second retry floor after a failed attempt — each a default the application could neither observe nor replace. CIMD composed that resolver internally, so an application that also wired one into client authentication for a registered `jwks_uri` ended up with two caches for the same URL.

The owner's ruling: caching is an application-layer concern, and it goes to the application seam. The library already states the reason in one place — `AuthorizationServerMetadata`'s remarks note that key-set rotation and metadata rotation "are independent concerns with different caching characteristics" — and the storage philosophy for flow state (§4 of the design notes) already says the library defines the contract and the application chooses the backend.

## Decision

**The library performs the attempt and reports its freshness; it stores nothing.**

- `ClientIdMetadataDocuments.ResolveAsync` and `JwksUriResolver.ResolveAsync` are stateless: the policed fetch, the document's validation, and the RFC 9111 §5.2 freshness the response headers imply, returned on the result as `HttpCacheFreshness`. A failed attempt reports a freshness that is not storable, so a caller cannot infer a lifetime from a fetch that produced nothing.
- The step that replaces a document's key set with the one its `jwks_uri` serves is a public, pure helper, `ClientIdMetadataDocuments.RefreshJwksAsync`. The attempt calls it once; an application's cache calls it on a document hit whose `HasJwksUriKeySet` is set, so rotation follows the key set's own lifetime and not the document's.
- `HttpCacheFreshness.Clamp` stays as a pure function an application may apply its own bounds through. Nothing in the library calls it.

**The application's delegate implementation is the cache.** `ResolveClientMetadataDelegate` and `ResolveJwksUriDelegate` are the seams; whatever implements them owns the store — a process dictionary, a distributed cache, a grain, a database row — the lifetime bounds, what follows a failure, and whether a stale entry is ever served, which RFC 9111 §4.2.4 forbids without the origin's or the client's permission. The delegate docs say so, and say that the key-set delegate is asked on every resolution, including by a caller serving a cached document, so an implementation that does not bound its own retries after a failure puts one outbound request on a host the client itself names for every authorization request.

**Every library consumer of a document takes the application's delegate.** `ClientIdMetadataDocumentResolverOptions.ResolveJwksUri` carries the key-set delegate into the document attempt; `PrivateKeyJwtClientAuthentication.BuildValidator` takes the same delegate for a registered `jwks_uri`. One instance serves both. With none wired, a `jwks_uri` is never dereferenced and the document resolves without a key set, the same non-fatal path a discovery failure already takes; the token endpoint then refuses the client for want of a key.

**The test suite carries the reference implementation.** `ClientMetadataResolutionCache` in `test/Verifiable.Tests/TestInfrastructure` implements both delegates over process dictionaries, honours the reported freshness, drops a stale entry on a failed re-attempt, holds off a failed key set for its own interval, and refreshes a discovered key set on a document hit through the helper. It is what an application starts from, swapping the store and the hold policy for its own.

## Rationale

**A library cache is policy the application did not choose.** How long a document may be served, whether an unreachable host is retried per request or held for a minute, whether last-known-good is served during an outage — each answer depends on the deployment: a single-instance demonstrator, a horizontally scaled cluster with a shared store, or a grain per client. A dictionary inside a library factory answers all of them the same way and hides the answer.

**Two caches for one URL is a correctness problem, not a tidiness one.** CIMD composing its own key-set resolver meant client authentication and document resolution could disagree about which key set was current. One delegate instance, wired by the application into both, cannot.

**Freshness is spec logic; storage is not.** RFC 9111 §5.2's calculation from `Cache-Control` and `Expires` is the same for every application and belongs in the library, once. What is done with the computed lifetime is where applications differ. Splitting exactly there keeps the library's conformance obligations in the library and the deployment's choices in the deployment.

**The same rule the design already applied to flow state.** `Load/SaveServerFlowStateDelegate` define a contract and let the application choose Redis, Orleans, in-memory or stateless encoding. Remote documents had drifted from that rule; this decision brings them back to it.

## Alternatives Considered

- **Keep the in-process cache as a library default and expose the retry policy as a delegate.** Ruled in the morning of the same day and withdrawn by the owner's restatement: it still ships a store and a lifetime policy the application cannot see, and a delegate that configures a library cache is still library caching.
- **A generic cached document resolver shared by every document kind** (the scout's shape C). Rejected: it would re-derive the working document pipeline through a type parameter for no behavioural gain, and it still keeps the cache in the library.
- **A separate package holding a default cache.** Rejected under the standing rule against wrapper packages: the seam is the delegate, and the reference implementation lives with the tests, not in a shipped package.
- **Give the key set its own library cache keyed by the `jwks_uri` but leave the document's.** Shipped briefly (`d9094673`) and superseded by this decision: it fixed the rotation defect and introduced a retry floor, and both were library policy.
