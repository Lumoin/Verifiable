// Environment-neutral runner: no DOM access, so the same AppBundle runs under Node in CI and in a
// browser tab when debugging by hand. The C# Main's return value (its failure count) becomes the
// process exit code under Node.
import { dotnet } from './_framework/dotnet.js'

const runtime = await dotnet.create();
const exitCode = await runtime.runMainAndExit();
console.log(`wasm smoke exit code: ${exitCode}`);
