using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.Core.Model.Did;

namespace Verifiable.Vcalm;

/// <summary>
/// Why a verify request could not use the controller document it asked its DID resolver for: the typed failure a
/// <see cref="VcalmControllerResolutionMemo"/> keeps in place of a document, so every later proof of the request that
/// names the same controller is refused for the same step of
/// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID 1.0 §3.3 Retrieve Verification Method</see>
/// without a second resolution.
/// </summary>
internal enum VcalmControllerDocumentFailure
{
    /// <summary>
    /// No conforming controlled identifier document was retrieved, step 5: "If controllerDocument is not a conforming
    /// controlled identifier document, an error MUST be raised and SHOULD convey an error type of
    /// INVALID_CONTROLLED_IDENTIFIER_DOCUMENT."
    /// </summary>
    NotRetrieved,

    /// <summary>
    /// The retrieved document names another identifier, step 6: "If controllerDocument.id does not match the
    /// controllerDocumentUrl, an error MUST be raised and SHOULD convey an error type of
    /// INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID."
    /// </summary>
    IdMismatch
}


/// <summary>
/// The controller documents one verify request has asked its DID resolver for, kept on the request's own
/// <see cref="ExchangeContext"/> so every proof and contained credential of the request that names one controller shares
/// one resolution, while no other request, and so no other tenant, ever reads it.
/// </summary>
/// <remarks>
/// The memo is bounded by what it holds. It keeps the typed <see cref="VcalmControllerDocumentFailure"/> of every
/// controller document the request could not use, a value that holds no document, and at most
/// <see cref="VcalmCredentialVerification.MaxMemoizedControllerDocuments"/> successfully resolved documents. Past that
/// bound the least recently used document is dropped, and a later proof naming its controller resolves it again, so a
/// request naming many controllers never holds more than the bound of resolved documents at once.
/// </remarks>
internal sealed class VcalmControllerResolutionMemo
{
    /// <summary>The <see cref="ExchangeContext"/> key the request's memo is kept under.</summary>
    private static string ContextKey { get; } = "vcalm.verify.controller_resolutions";

    /// <summary>The most resolved documents this memo keeps at once.</summary>
    private int MaxDocuments { get; }

    /// <summary>The typed failure of every controller document URL the request could not use.</summary>
    private Dictionary<string, VcalmControllerDocumentFailure> Failures { get; } = new(StringComparer.Ordinal);

    /// <summary>The kept resolved documents by controller document URL, each pointing at its place in <see cref="RecencyOrder"/>.</summary>
    private Dictionary<string, LinkedListNode<KeyValuePair<string, DidDocument>>> Documents { get; } = new(StringComparer.Ordinal);

    /// <summary>The kept resolved documents from the most to the least recently used, so the last one is dropped first.</summary>
    private LinkedList<KeyValuePair<string, DidDocument>> RecencyOrder { get; } = new();


    /// <summary>Creates an empty memo that keeps at most <paramref name="maxDocuments"/> resolved documents.</summary>
    /// <param name="maxDocuments">The most resolved documents kept at once; zero or less keeps none.</param>
    private VcalmControllerResolutionMemo(int maxDocuments)
    {
        MaxDocuments = maxDocuments;
    }


    /// <summary>How many resolved controller documents the memo holds.</summary>
    public int DocumentCount => Documents.Count;


    /// <summary>
    /// The memo of the request <paramref name="context"/> belongs to, created on first use with the bound
    /// <paramref name="maxDocuments"/>.
    /// </summary>
    /// <param name="context">The verify request's own context.</param>
    /// <param name="maxDocuments">The most resolved documents a memo created now keeps at once.</param>
    /// <returns>The request's memo.</returns>
    public static VcalmControllerResolutionMemo GetOrCreate(ExchangeContext context, int maxDocuments)
    {
        if(context.TryGetValue(ContextKey, out object? existing) && existing is VcalmControllerResolutionMemo memo)
        {
            return memo;
        }

        VcalmControllerResolutionMemo created = new(maxDocuments);
        context[ContextKey] = created;

        return created;
    }


    /// <summary>How many resolved controller documents the memo of the request <paramref name="context"/> holds, zero when it has none.</summary>
    /// <param name="context">The verify request's own context.</param>
    /// <returns>The number of resolved documents the request's memo holds.</returns>
    public static int CountDocuments(ExchangeContext context) =>
        context.TryGetValue(ContextKey, out object? existing) && existing is VcalmControllerResolutionMemo memo ? memo.DocumentCount : 0;


    /// <summary>Whether the request already failed to use the controller document at <paramref name="controllerId"/>, and why.</summary>
    /// <param name="controllerId">The controller document URL.</param>
    /// <param name="failure">The typed failure, when one is kept.</param>
    /// <returns><see langword="true"/> when a failure is kept for the URL.</returns>
    public bool TryGetFailure(string controllerId, out VcalmControllerDocumentFailure failure) =>
        Failures.TryGetValue(controllerId, out failure);


    /// <summary>
    /// Whether the memo holds the resolved document at <paramref name="controllerId"/>; a document found becomes the most
    /// recently used.
    /// </summary>
    /// <param name="controllerId">The controller document URL.</param>
    /// <param name="document">The kept document, when one is held.</param>
    /// <returns><see langword="true"/> when the document is held.</returns>
    public bool TryGetDocument(string controllerId, [NotNullWhen(true)] out DidDocument? document)
    {
        if(Documents.TryGetValue(controllerId, out LinkedListNode<KeyValuePair<string, DidDocument>>? node))
        {
            RecencyOrder.Remove(node);
            RecencyOrder.AddFirst(node);
            document = node.Value.Value;

            return true;
        }

        document = null;

        return false;
    }


    /// <summary>Keeps the typed failure of the controller document at <paramref name="controllerId"/> for the rest of the request.</summary>
    /// <param name="controllerId">The controller document URL.</param>
    /// <param name="failure">Why the document could not be used.</param>
    public void RecordFailure(string controllerId, VcalmControllerDocumentFailure failure) => Failures[controllerId] = failure;


    /// <summary>
    /// Keeps the resolved <paramref name="document"/> at <paramref name="controllerId"/> as the most recently used, first
    /// dropping the least recently used documents while the memo already holds its bound. A document the memo already
    /// holds for the URL is replaced, its place in <see cref="RecencyOrder"/> removed with it, so two verifications of one
    /// request that both resolved the controller before either recorded it leave one document, and the recency order
    /// never holds a document the lookup no longer reaches or grows past the bound.
    /// </summary>
    /// <param name="controllerId">The controller document URL.</param>
    /// <param name="document">The resolved, conforming controller document.</param>
    public void RecordDocument(string controllerId, DidDocument document)
    {
        if(MaxDocuments <= 0)
        {
            return;
        }

        if(Documents.Remove(controllerId, out LinkedListNode<KeyValuePair<string, DidDocument>>? held))
        {
            RecencyOrder.Remove(held);
        }

        while(Documents.Count >= MaxDocuments && RecencyOrder.Last is { } leastRecent)
        {
            RecencyOrder.RemoveLast();
            _ = Documents.Remove(leastRecent.Value.Key);
        }

        Documents[controllerId] = RecencyOrder.AddFirst(new KeyValuePair<string, DidDocument>(controllerId, document));
    }
}


/// <summary>
/// Typed <see cref="ExchangeContext"/> accessors for the per-request state of the W3C VCALM 1.0 §3.3 verifier, read by
/// an application's inspection stage once a verify request has been answered.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class VcalmVerificationContextExtensions
{
    extension(ExchangeContext context)
    {
        /// <summary>
        /// How many resolved controller documents the verify request holds for reuse by its later proofs, never more than
        /// <see cref="VcalmCredentialVerification.MaxMemoizedControllerDocuments"/>: the resolved documents one request
        /// keeps in memory while it runs, which an application's inspection stage can observe per request.
        /// </summary>
        public int VcalmMemoizedControllerDocumentCount => VcalmControllerResolutionMemo.CountDocuments(context);
    }
}
