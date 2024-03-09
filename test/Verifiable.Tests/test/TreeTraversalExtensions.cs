using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.Core.Asssesment;

namespace Verifiable.Tests.test
{
    internal class TreeTraversalExtensions
    {
        public static IEnumerable<TreeTraversalNode<TNodeType>> DepthFirstTreeTraversal<TNodeType>(TNodeType root, Func<TNodeType, IEnumerable<TNodeType>> descendantsSelector)
        {
            var stack = new Stack<TreeTraversalNode<TNodeType>>();
            stack.Push(new TreeTraversalNode<TNodeType>(root, 0));
            while(stack.Count != 0)
            {
                TreeTraversalNode<TNodeType> current = stack.Pop();
                yield return current;
                foreach(var child in descendantsSelector(current.Node).Reverse())
                {
                    stack.Push(new TreeTraversalNode<TNodeType>(child, current.Depth + 1));
                }
            }
        }


        public static async IAsyncEnumerable<TreeTraversalNode<TNodeType>> DepthFirstTreeTraversalAsync<TNodeType>(TNodeType root, Func<TNodeType, Task<IEnumerable<TNodeType>>> descendantsSelector)
        {
            var stack = new Stack<TreeTraversalNode<TNodeType>>();
            stack.Push(new TreeTraversalNode<TNodeType>(root, 0));
            while(stack.Count != 0)
            {
                var current = stack.Pop();        
                yield return current;
                
                var children = await descendantsSelector(current.Node);
                foreach(var child in children.Reverse())
                {
                    stack.Push(new TreeTraversalNode<TNodeType>(child, current.Depth + 1));
                }
            }
        }
    }


    public delegate TOutputFormat NodeFormatter<TNodeType, TOutputFormat>(TreeTraversalNode<TNodeType> node);

    public delegate void OutputSink<TFormatted>(TFormatted formattedData);

    public delegate Task AsyncOutputSink<TFormatted>(TFormatted formattedData);

    public static class TreeNodeFormatters
    {
        public static string SimpleNodeFormatter<TNodeType>(TreeTraversalNode<TNodeType> node)
        {            
            var indent = new string(' ', node.Depth * 4);
            return $"{indent}{node.Node?.ToString() ?? "null"}";
        }
    }

    public static class TreeNodeSinks
    {
        public static void ConsoleOutputSink(string formattedData)
        {
            Console.WriteLine(formattedData);
        }


        public static async Task FileOutputSinkAsync(string formattedData)
        {         
            string path = "output.txt";
            await File.AppendAllTextAsync(path, formattedData + Environment.NewLine);
        }
    }
}
