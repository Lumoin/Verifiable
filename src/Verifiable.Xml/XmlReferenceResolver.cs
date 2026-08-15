using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// Resolves a non-same-document (external) <c>URI</c> attribute value into the octets it identifies — the
/// seam this library reserves for the caller. This
/// leaf performs no I/O of its own (the house rule against network access inside a library leaf), so any
/// <c>Reference</c> or <c>RetrievalMethod</c> whose <c>URI</c> is not a same-document reference per section
/// 4.3.3.2 of <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
/// Processing (Second Edition)</see> dereferences only through a delegate of this shape the caller supplies —
/// obtaining the entity-body over HTTP, reading a local file, or "through other means such as a local
/// cache" as section 3.2.1 itself allows.
/// </summary>
/// <remarks>
/// The delegate reports only success or failure: a caller-side refusal reason, if any, is the caller's own
/// concern to log or surface, because a missing delegate and a delegate that returns <see langword="false"/>
/// are indistinguishable to the engine — both surface identically as
/// <see cref="XmlSignatureProcessingFailure.ExternalReferenceUnresolved"/>. Nothing in
/// <see cref="XmlReferenceProcessing"/> bounds how many octets a resolver returns before they enter the
/// transform chain (and, for a non-same-document reference a canonicalization transform names, a
/// <see cref="XmlNodeTable.TryParse"/> re-parse): sizing what it fetches is the resolver implementation's
/// own responsibility, the same way an application-layer policed fetch bounds an HTTP
/// response before ever handing bytes to this leaf. The delegate must also not throw: a throwing resolver's
/// own rented buffers are the resolver's own responsibility to release along its exceptional path, since
/// this leaf's ownership of <paramref name="octets"/> begins only once the delegate returns.
/// </remarks>
/// <param name="uri">The <c>URI</c> attribute value exactly as written, un-decoded and never routed through
/// <see cref="System.Uri"/> — the caller interprets its scheme.</param>
/// <param name="pool">The pool the resolved octets must be rented from.</param>
/// <param name="octets">The resolved octets on success; ownership passes to the reference-processing engine,
/// which disposes them once the transform chain has consumed them. <see langword="null"/> when the delegate
/// returns <see langword="false"/>.</param>
/// <returns><see langword="true"/> when the <paramref name="uri"/> resolved to octets.</returns>
public delegate bool XmlReferenceResolver(ReadOnlySpan<byte> uri, BaseMemoryPool pool, out PooledMemory? octets);
