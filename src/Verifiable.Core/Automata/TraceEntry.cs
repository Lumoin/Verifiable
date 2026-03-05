using System;
using System.Diagnostics;

namespace Verifiable.Core.Automata;

/// <summary>
/// A single entry emitted by the pushdown automaton after each step. Contains
/// the full context needed for replay journals, structured logging, OTel correlation,
/// and CloudEvents projection.
/// </summary>
/// <remarks>
/// <para>
/// Field mapping to standard formats:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <strong>CloudEvents:</strong> <see cref="RunId"/> maps to <c>source</c>,
///     <see cref="Step"/> + <see cref="RunId"/> maps to <c>id</c>,
///     <see cref="Label"/> maps to <c>type</c>,
///     <see cref="Timestamp"/> maps to <c>time</c>.
///     See <see href="https://cloudevents.io/">CloudEvents specification</see>.
///   </description></item>
///   <item><description>
///     <strong>W3C Trace Context:</strong> <see cref="TraceParent"/> and <see cref="TraceState"/>
///     carry the ambient distributed trace identifiers for OTel correlation.
///     See <see href="https://www.w3.org/TR/trace-context/">W3C Trace Context</see>.
///   </description></item>
/// </list>
/// <para>
/// The PDA emits everything, stores nothing. Subscribers choose what to persist —
/// a replay journal keeps inputs and outcomes, a metrics subscriber keeps labels
/// and timing, a structured logger keeps the full entry.
/// </para>
/// </remarks>
/// <typeparam name="TState">The state type of the automaton.</typeparam>
/// <typeparam name="TInput">The input type of the automaton.</typeparam>
/// <param name="RunId">Stable execution/session identifier provided by the caller at construction.</param>
/// <param name="Step">The zero-based step number in the computation.</param>
/// <param name="Label">The transition label, or <see langword="null"/> if unlabeled.</param>
/// <param name="StackDepth">The stack depth after this step.</param>
/// <param name="Input">The input that was processed in this step.</param>
/// <param name="StateBefore">The state before the transition was applied.</param>
/// <param name="StateAfter">The state after the transition was applied (same as before if halted or faulted).</param>
/// <param name="Outcome">Whether the step transitioned, halted, or faulted.</param>
/// <param name="Timestamp">The timestamp of this step, from the injected <see cref="TimeProvider"/>.</param>
/// <param name="TraceParent">
/// The W3C <c>traceparent</c> captured from <see cref="System.Diagnostics.Activity.Current"/>
/// at the time of the step, or <see langword="null"/> if no ambient activity exists.
/// </param>
/// <param name="TraceState">
/// The W3C <c>tracestate</c> captured from <see cref="System.Diagnostics.Activity.Current"/>
/// at the time of the step, or <see langword="null"/>.
/// </param>
[DebuggerDisplay("#{Step} '{Label}' {Outcome} Depth={StackDepth} Run={RunId}")]
public sealed record TraceEntry<TState, TInput>(
    string RunId,
    int Step,
    string? Label,
    int StackDepth,
    TInput Input,
    TState StateBefore,
    TState StateAfter,
    TraceOutcome Outcome,
    DateTimeOffset Timestamp,
    string? TraceParent,
    string? TraceState);