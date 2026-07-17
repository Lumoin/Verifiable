using System;
using System.Collections.Generic;
using System.Text.Json;

namespace Verifiable.Json;

/// <summary>
/// Internal utilities for converting between <see cref="JsonElement"/> and CLR types.
/// </summary>
internal static class JsonElementConversion
{
    /// <summary>
    /// Converts a <see cref="JsonElement"/> to a CLR object.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The type mapping is:
    /// </para>
    /// <list type="bullet">
    /// <item><description><see cref="JsonValueKind.String"/> -> <see cref="string"/>.</description></item>
    /// <item><description><see cref="JsonValueKind.True"/> and <see cref="JsonValueKind.False"/> -> <see cref="bool"/>.</description></item>
    /// <item><description><see cref="JsonValueKind.Number"/> -> <see cref="int"/> if representable, then <see cref="long"/>, otherwise <see cref="decimal"/>.</description></item>
    /// <item><description><see cref="JsonValueKind.Null"/> -> <see langword="null"/>.</description></item>
    /// <item><description><see cref="JsonValueKind.Object"/> -> <see cref="Dictionary{TKey,TValue}"/> of string to object.</description></item>
    /// <item><description><see cref="JsonValueKind.Array"/> -> <see cref="List{T}"/> of object.</description></item>
    /// </list>
    /// <para>
    /// Collection types use non-nullable generic parameters (<c>Dictionary&lt;string, object&gt;</c>
    /// and <c>List&lt;object&gt;</c>) to match the shapes used by POCO types such as
    /// <c>Service.AdditionalData</c>. Null values are stored as null references within the
    /// collections, which <see cref="object"/> permits.
    /// </para>
    /// <para>
    /// Objects and arrays are materialized <strong>iteratively</strong> with an explicit
    /// work <see cref="Stack{T}"/> rather than by recursion, so the conversion uses bounded
    /// call-stack space regardless of how deeply the input nests — defending against a
    /// stack-overflow on adversarial input independently of the parser's depth limit.
    /// </para>
    /// </remarks>
    internal static object? Convert(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            JsonValueKind.Number => NarrowNumber(element),
            JsonValueKind.Object or JsonValueKind.Array => ConvertContainer(element),
            _ => throw new NotSupportedException($"Unsupported JSON value kind: {element.ValueKind}.")
        };
    }


    /// <summary>
    /// Narrows a JSON number to the smallest fitting CLR integer type,
    /// falling back to <see cref="decimal"/> for non-integer values.
    /// The narrowing order is <see cref="int"/> then <see cref="long"/>
    /// then <see cref="decimal"/>, matching the behavior of
    /// <see cref="ManualJsonReader.ReadNumber"/>.
    /// </summary>
    internal static object NarrowNumber(JsonElement element)
    {
        if(element.TryGetInt32(out int i))
        {
            return i;
        }

        if(element.TryGetInt64(out long l))
        {
            return l;
        }

        return element.GetDecimal();
    }


    //Materializes an object/array (and everything nested within) using an explicit
    //stack. Each frame owns a container being filled and an enumerator over its
    //source element's children; a child object/array creates its container, links it
    //into the parent, and is pushed as a new frame, while scalars are added in place.
    private static object ConvertContainer(JsonElement root)
    {
        object rootContainer = NewContainer(root.ValueKind);

        var stack = new Stack<Frame>();
        stack.Push(new Frame(root, rootContainer));

        while(stack.Count > 0)
        {
            Frame frame = stack.Peek();
            if(!frame.TryGetNext(out string? name, out JsonElement value))
            {
                stack.Pop();
                continue;
            }

            if(value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
            {
                object childContainer = NewContainer(value.ValueKind);
                frame.Add(name, childContainer);
                stack.Push(new Frame(value, childContainer));
            }
            else
            {
                frame.Add(name, ConvertScalar(value));
            }
        }

        return rootContainer;
    }


    private static object NewContainer(JsonValueKind kind) =>
        kind == JsonValueKind.Object ? new Dictionary<string, object>() : new List<object>();


    private static object? ConvertScalar(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        JsonValueKind.Number => NarrowNumber(element),
        _ => throw new NotSupportedException($"Unsupported JSON value kind: {element.ValueKind}.")
    };


    //A mutable work item: the container being filled plus the (struct) enumerator over
    //its source children. Held as a class so the enumerator mutates in place across
    //Stack.Peek() calls — a struct frame would be copied and lose enumerator progress.
    private sealed class Frame
    {
        private object Container { get; }
        private bool IsObject { get; }
        private JsonElement.ObjectEnumerator objectEnumerator;
        private JsonElement.ArrayEnumerator arrayEnumerator;

        public Frame(JsonElement element, object container)
        {
            this.Container = container;
            IsObject = element.ValueKind == JsonValueKind.Object;
            if(IsObject)
            {
                objectEnumerator = element.EnumerateObject();
            }
            else
            {
                arrayEnumerator = element.EnumerateArray();
            }
        }


        public bool TryGetNext(out string? name, out JsonElement value)
        {
            if(IsObject)
            {
                if(objectEnumerator.MoveNext())
                {
                    JsonProperty property = objectEnumerator.Current;
                    name = property.Name;
                    value = property.Value;

                    return true;
                }
            }
            else if(arrayEnumerator.MoveNext())
            {
                name = null;
                value = arrayEnumerator.Current;

                return true;
            }

            name = null;
            value = default;

            return false;
        }


        public void Add(string? name, object? value)
        {
            if(IsObject)
            {
                ((Dictionary<string, object>)Container)[name!] = value!;
            }
            else
            {
                ((List<object>)Container).Add(value!);
            }
        }
    }
}
