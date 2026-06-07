namespace Verifiable.OAuth.Federation;

/// <summary>
/// Lists subordinates of a federation entity via its
/// <c>federation_list_endpoint</c> per OpenID Federation 1.0 §8.2.
/// </summary>
/// <param name="listEndpoint">The full URL of the entity's list endpoint.</param>
/// <param name="entityTypeFilter">
/// Optional filter restricting results to a single entity type (the
/// <c>entity_type</c> query parameter on §8.2's HTTP request). Pass
/// <see langword="null"/> to enumerate all subordinates regardless of type.
/// </param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns>
/// The subordinate entities' identifiers, in the order the endpoint
/// returned them.
/// </returns>
public delegate ValueTask<IReadOnlyList<EntityIdentifier>> ListSubordinatesDelegate(
    Uri listEndpoint,
    EntityTypeIdentifier? entityTypeFilter,
    CancellationToken cancellationToken);
