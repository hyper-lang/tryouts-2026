# shim/ — Mode B managed loader shim source

`ApolloShim.cs` is the managed piece of `build-host` (Mode B). It exists to
give the native host a `public static int Main(string[])` entry point that
`ICLRRuntimeHost::ExecuteInDefaultAppDomain` can invoke in the default AppDomain
— Apollo's own `Program.Main` is a `void` WinExe entry point, which that API
cannot call.

## What host.py interpolates

host.py substitutes exactly one marker token in this file before invoking the
.NET build:

| Marker | Replacement | Where |
| --- | --- | --- |
| `__APOLLO_BYTES__` | the hardened Apollo WinExe bytes as a comma-separated byte list filling `new byte[] { ... }` | class field `APOLLO_BYTES` |

Substitution happens **before** compilation, so the compiled shim assembly
embeds the payload and is fully self-contained. The byte-list form is used
rather than any escaping scheme so the interpolation is a trivial text splice
with no escaping surprises. If a payload ever exceeds the compile-time
limits of a single array literal, split it into chunked `new byte[] { ... }`
fields and concatenate in `APOLLO_BYTES`; the marker contract above is
host.py's only obligation.

## What the shim does at runtime

1. `Assembly.Load(APOLLO_BYTES)` loads the embedded hardened payload into the
   default AppDomain.
2. `Type.GetType("Apollo.Program")` resolves Apollo's entry type.
3. Reflection invokes Apollo's real `Main(string[], ...)` (public or
   non-public static) with the string array the CLR hosting API passed through,
   so the agent runs its normal in-process loop. No agent behavior is modified.

## Build expectations

- Target framework `.NET Framework 4.0`, `output_type = Library` (a class
  library — the CLR hosting API loads it by file path from the temp file the
  native host materializes).
- Compiler: the team's Mythic `dotnet build` or a dev-laptop `dotnet`. If
  neither exists, `build-host` reports `shim_unavailable` and skips with exit 0
  (R5) — this is the ONLY build-time skip; a missing native toolchain is still
  a hard failure (exit 2).
- No package references beyond mscorlib; `Assembly.Load(byte[])` requires full
  trust, which the default AppDomain provides.

## Boundary

The shim never touches the network, never writes logs, and carries no keys — the
payload it loads is the already-hardened Apollo image, and the runtime patch is
applied by the native host **before** any managed code runs.