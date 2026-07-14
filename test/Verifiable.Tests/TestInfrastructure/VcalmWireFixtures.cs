using System;
using System.Collections.Generic;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared VCALM §3 credential/presentation wire assembly for the issuer, holder, and multi-tenant flow
/// test corpus — the fixed "ExampleAlumniCredential" shape those tests issue and derive against.
/// </summary>
/// <remarks>
/// Serialization is not baked in here: each caller wires its own <see cref="CredentialSerializeDelegate"/>/
/// <see cref="PresentationSerializeDelegate"/> (its own composition root's <c>JsonSerializerOptions</c>),
/// so this class only assembles the object graph and formats the request-body wrapper JSON.
/// </remarks>
internal static class VcalmWireFixtures
{
    /// <summary>Builds the fixed "ExampleAlumniCredential" test credential.</summary>
    /// <param name="issuerDid">The issuer DID.</param>
    /// <param name="credentialId">The credential's <c>id</c>, or <see langword="null"/> to omit it.</param>
    /// <returns>The assembled credential.</returns>
    internal static VerifiableCredential BuildCredential(string issuerDid, string? credentialId) =>
        new()
        {
            Context = new Context
            {
                Contexts =
                [
                    Context.Credentials20,
                    CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl
                ]
            },
            Id = credentialId,
            Type = ["VerifiableCredential", "ExampleAlumniCredential"],
            Issuer = new Issuer { Id = issuerDid },
            ValidFrom = "2023-01-01T00:00:00Z",
            ValidUntil = "2030-01-01T00:00:00Z",
            CredentialSubject =
            [
                new CredentialSubject
                {
                    Id = "did:example:alumni-subject",
                    AdditionalData = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["alumniOf"] = "The School of Examples"
                    }
                }
            ]
        };


    /// <summary>
    /// Builds the VCALM §3.2 <c>/credentials/issue</c> request body wrapping
    /// <see cref="BuildCredential"/>'s serialization: <c>{"credential":...}</c>.
    /// </summary>
    /// <param name="issuerDid">The issuer DID.</param>
    /// <param name="credentialId">The credential's <c>id</c>, or <see langword="null"/> to omit it.</param>
    /// <param name="serializeCredential">The caller's own credential serialization delegate.</param>
    /// <returns>The issue-request body JSON text.</returns>
    internal static string BuildIssueRequestBody(string issuerDid, string? credentialId, CredentialSerializeDelegate serializeCredential) =>
        "{\"credential\":" + serializeCredential(BuildCredential(issuerDid, credentialId)) + "}";


    /// <summary>Builds and serializes a bare (unproofed) <c>VerifiablePresentation</c> for <paramref name="holderDid"/>.</summary>
    /// <param name="holderDid">The presentation's <c>holder</c>.</param>
    /// <param name="serializePresentation">The caller's own presentation serialization delegate.</param>
    /// <param name="presentationId">The presentation's <c>id</c>, or <see langword="null"/> to omit it.</param>
    /// <returns>The serialized presentation JSON text.</returns>
    internal static string SerializeUnproofedPresentation(string holderDid, PresentationSerializeDelegate serializePresentation, string? presentationId = null) =>
        serializePresentation(new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Id = presentationId,
            Type = ["VerifiablePresentation"],
            Holder = holderDid
        });
}
