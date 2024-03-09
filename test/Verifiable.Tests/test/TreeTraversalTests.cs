using System.Collections.Generic;
using System;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.Assessment;
using Xunit;
using Verifiable.Core.Asssesment;


namespace Verifiable.Tests.test
{
    public record TestClaimContext: ClaimContext { }

    public class TreeTraversalTests
    {
        private static ClaimContext TestClaimContext { get; } = new TestClaimContext();


        public static TNodeType NullFormatter<TNodeType>(TreeTraversalNode<TNodeType> node)
        {           
            return node.Node;
        }


        [Fact]
        public async Task ClaimTreeTraversalSucceeds()
        {
            var subClaims = new[] { new Claim(ClaimId.AlgExists, ClaimOutcome.Success), new Claim(ClaimId.KtyMissingOrEmpty, ClaimOutcome.Failure) };
            var mainClaim = new Claim(ClaimId.WebDidIdFormat, ClaimOutcome.Failure, TestClaimContext, subClaims);

            var outputList = new List<Claim>();
            var asyncOutputList = new List<Claim>();
            
            void testSink(Claim output) => outputList.Add(output);
            async Task asyncTestSink(Claim output)
            {
                asyncOutputList.Add(output);
                await Task.CompletedTask;
            }

            NodeFormatter<Claim, Claim> nullFormatter = node => NullFormatter(node);

            TraverseAndOutput(mainClaim, (root) => root.SubClaims.AsEnumerable(), nullFormatter, testSink);
            await TraverseAndOutputAsync(mainClaim, (root) => Task.FromResult(root.SubClaims.AsEnumerable()), nullFormatter, asyncTestSink);

            Assert.NotNull(outputList);
            Assert.NotNull(asyncOutputList);

            Assert.Equal(3, outputList.Count);
            Assert.Equal(3, asyncOutputList.Count);
            
            var expectedOrder = new List<Claim> { mainClaim }.Concat(subClaims).ToList();
            Assert.Equal(expectedOrder, outputList);            
            Assert.Equal(expectedOrder, asyncOutputList);
        }

        
        private static void TraverseAndOutput<TNodeType, TFormat>(TNodeType root, Func<TNodeType, IEnumerable<TNodeType>> descendantsSelector, NodeFormatter<TNodeType, TFormat> formatter, OutputSink<TFormat> sink)
        {
            foreach(TreeTraversalNode<TNodeType> node in TreeTraversalExtensions.DepthFirstTreeTraversal(root, descendantsSelector))
            {
                var formattedData = formatter(node);
                sink(formattedData);
            }
        }


        private static async Task TraverseAndOutputAsync<TNodeType, TFormat>(TNodeType root, Func<TNodeType, Task<IEnumerable<TNodeType>>> descendantsSelector, NodeFormatter<TNodeType, TFormat> formatter, AsyncOutputSink<TFormat> sink)
        {
            await foreach(var node in TreeTraversalExtensions.DepthFirstTreeTraversalAsync(root, descendantsSelector))
            {
                var formattedData = formatter(node);
                await sink(formattedData);
            }
        }
    }
}
