using System;
using System.Collections.Generic;
using Verifiable.Core.Did;

namespace Verifiable.Core.Builders
{
    public static class BuilderExtensions
    {
        private static Context DefaultContext { get; } = new Did.Context
        {
            Contexes = new List<object>(new[]
            {
                //This should be the first entry in the array, see https://w3c-ccg.github.io/did-method-key/#document-creation-algorithm.
                "https://www.w3.org/ns/did/v1",

                //These come from the cryptographic suite/context. See previous
                //and https://w3c-ccg.github.io/did-method-key/#context-creation-algorithm.
                "https://w3id.org/security/suites/jws-2020/v1"
            })
        };


        public static DidDocument AddDefaultContext(this DidDocument document)
        {
            document.Context = DefaultContext;
            return document;
        }


        public static Func<DidDocument, TBuilder, TState?, DidDocument> AddDefaultContext<TBuilder, TState>() where TBuilder : IBuilder
        {
            return (document, builder, state) =>
            {
                document.Context = DefaultContext;
                return document;
            };
        }
    }
}
