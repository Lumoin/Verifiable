using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.Automata;

/// <summary>
/// Describes what a transition does to the pushdown automaton's stack.
/// </summary>
/// <typeparam name="TStackSymbol">The type of symbols on the stack.</typeparam>
public abstract class StackAction<TStackSymbol>
{
    protected StackAction() { }

    /// <summary>
    /// Leave the stack unchanged.
    /// </summary>
    public static StackAction<TStackSymbol> None { get; } = new NoneAction();

    /// <summary>
    /// Push a symbol onto the stack.
    /// </summary>
    /// <param name="symbol">The symbol to push.</param>
    /// <returns>A push stack action.</returns>
    public static StackAction<TStackSymbol> Push(TStackSymbol symbol) => new PushAction(symbol);

    /// <summary>
    /// Pop the top symbol from the stack.
    /// </summary>
    public static StackAction<TStackSymbol> Pop { get; } = new PopAction();

    /// <summary>
    /// Replace the top symbol with a new symbol.
    /// </summary>
    /// <param name="symbol">The replacement symbol.</param>
    /// <returns>A replace stack action.</returns>
    public static StackAction<TStackSymbol> Replace(TStackSymbol symbol) => new ReplaceAction(symbol);

    [DebuggerDisplay("None")]
    private sealed class NoneAction: StackAction<TStackSymbol> { }

    [DebuggerDisplay("Push({Symbol})")]
    private sealed class PushAction(TStackSymbol symbol): StackAction<TStackSymbol>
    {
        public TStackSymbol Symbol { get; } = symbol;
    }

    [DebuggerDisplay("Pop")]
    private sealed class PopAction: StackAction<TStackSymbol> { }

    [DebuggerDisplay("Replace({Symbol})")]
    private sealed class ReplaceAction(TStackSymbol symbol): StackAction<TStackSymbol>
    {
        public TStackSymbol Symbol { get; } = symbol;
    }

    /// <summary>
    /// Applies this action to the given stack. Enforces the sentinel invariant:
    /// attempting to pop or replace when only the initial stack symbol remains
    /// throws <see cref="InvalidOperationException"/>.
    /// </summary>
    /// <param name="stack">The stack to modify.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a pop or replace is attempted on a stack containing only the sentinel symbol.
    /// This indicates a bug in the transition function.
    /// </exception>
    internal void Apply(Stack<TStackSymbol> stack)
    {
        _ = this switch
        {
            PushAction push => ApplyPush(stack, push.Symbol),
            PopAction => ApplyPop(stack),
            ReplaceAction replace => ApplyReplace(stack, replace.Symbol),
            NoneAction => 0,
            _ => throw new InvalidOperationException($"Unknown stack action: {GetType().Name}.")
        };
    }

    private static int ApplyPush(Stack<TStackSymbol> stack, TStackSymbol symbol)
    {
        stack.Push(symbol);
        return 0;
    }

    private static int ApplyPop(Stack<TStackSymbol> stack)
    {
        if(stack.Count <= 1)
        {
            throw new InvalidOperationException(
                "Cannot pop the sentinel stack symbol. This indicates a bug in the transition function.");
        }

        stack.Pop();
        return 0;
    }

    private static int ApplyReplace(Stack<TStackSymbol> stack, TStackSymbol symbol)
    {
        if(stack.Count <= 1)
        {
            throw new InvalidOperationException(
                "Cannot replace the sentinel stack symbol. This indicates a bug in the transition function.");
        }

        stack.Pop();
        stack.Push(symbol);
        return 0;
    }
}
