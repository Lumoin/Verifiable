using System.Diagnostics;
using Verifiable.Core.Model.Did;

namespace Verifiable.Tests.Did
{
    //TODO: Work in progress.
    //Quickly done some DTOs to test serialization of more specialized services in DidDocumentTests.

    [DebuggerDisplay("OpenIdConnectVersion1(Id = {Id})")]
    internal class OpenIdConnectVersion1: Service
    { }


    [DebuggerDisplay("SpamCost(Amount = {Amount}, Currency = {Currency})")]
    internal class SpamCost
    {
        public string? Amount { get; set; }

        public string? Currency { get; set; }
    }

    [DebuggerDisplay("SocialWebInboxService(Id = {Id})")]
    internal class SocialWebInboxService: Service
    {
        public string? Description { get; set; }

        public SpamCost? SpamCost { get; set; }
    }


    [DebuggerDisplay("VerifiableCredentialService(Id = {Id})")]
    internal class VerifiableCredentialService: Service
    {
    }
}
