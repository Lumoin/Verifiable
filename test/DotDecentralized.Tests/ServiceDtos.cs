using DotDecentralized.Core.Did;
using System.Diagnostics;

namespace DotDecentralized.Tests
{
    //TODO: Work in progress.
    //Quickly done some DTOs to test serialization of more specialized services in DidDocumentTests.

    [DebuggerDisplay("OpenIdConnectVersion1(Id = {Id})")]
    public class OpenIdConnectVersion1: Service
    { }


    [DebuggerDisplay("SpamCost(Amount = {Amount}, Currency = {Currency})")]
    public class SpamCost
    {
        public string? Amount { get; set; }

        public string? Currency { get; set; }
    }

    [DebuggerDisplay("SocialWebInboxService(Id = {Id})")]
    public class SocialWebInboxService: Service
    {
        public string? Description { get; set; }

        public SpamCost? SpamCost { get; set; }
    }


    [DebuggerDisplay("VerifiableCredentialService(Id = {Id})")]
    public class VerifiableCredentialService: Service
    {
    }
}
