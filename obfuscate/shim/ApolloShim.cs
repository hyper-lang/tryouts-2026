// ApolloShim.cs -- Mode B managed loader shim (R5).
//
// Authorized CCDC-tryout exercise use only.  Compiled wherever a .NET build
// exists (the team's Mythic container build or a dev-laptop `dotnet`); if
// neither is available, `obfuscate build-host` reports `shim_unavailable` and
// skips (exit 0).  host.py interpolates the hardened Apollo bytes into the
// `__APOLLO_BYTES__` marker below BEFORE this file is compiled, so the
// resulting shim assembly is self-contained: it carries the payload and needs
// nothing on the deploy host but this one file.
//
// Why this exists: Apollo's own `Program.Main` is a `void` WinExe entry point,
// which `ICLRRuntimeHost::ExecuteInDefaultAppDomain` cannot invoke -- that API
// requires a `public static int Main(string[])` on a public class (executed in
// the default AppDomain).  This shim provides that shape: its entry point runs,
// loads the embedded hardened payload with `Assembly.Load`, and invokes
// Apollo's real entry point via reflection.  Payload and shim therefore stay
// together in the single self-contained `patched_apollo.exe` produced by
// `build-host`; the native host materializes only this (small) shim assembly to
// a temp file to satisfy the CLR hosting API's file-path load contract.

using System;
using System.Reflection;

namespace CcdcShim
{
    /// <summary>
    /// Managed loader shim executed in the default AppDomain by the native
    /// early-boot CLR host (Mode B).  `Main(string[])` is the entry point shape
    /// `ExecuteInDefaultAppDomain` requires; it loads the embedded hardened
    /// Apollo bytes and forwards to Apollo's real entry point via reflection so
    /// no agent behavior is modified.
    /// </summary>
    public class ApolloShim
    {
        // Injected by host.py before compilation: the hardened Apollo WinExe
        // image bytes as a comma-separated byte list.  The marker token is the
        // interpolation contract documented in shim/README.md.
        private static readonly byte[] APOLLO_BYTES = new byte[] { __APOLLO_BYTES__ };

        /// <summary>
        /// Default-AppDomain entry point.  Loads the embedded payload and
        /// invokes Apollo's real `Program.Main(string[])` via reflection.
        /// Returns 0 on success, non-zero on any failure.
        /// </summary>
        public static int Main(string[] args)
        {
            try
            {
                byte[] payload = APOLLO_BYTES;
                if (payload.Length == 0)
                {
                    return 1;
                }
                Assembly apollo = Assembly.Load(payload);
                Type program = apollo.GetType("Apollo.Program", true);
                MethodInfo main = program.GetMethod(
                    "Main",
                    BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                if (main == null)
                {
                    return 2;
                }
                main.Invoke(null, new object[] { args });
                return 0;
            }
            catch (Exception)
            {
                // The default domain swallows host-side exceptions; signal
                // failure via the return code instead (no logging, no keys).
                return 3;
            }
        }

        /// <summary>Accessor so the payload reference is never dead-code-eliminated.</summary>
        internal static byte[] EmbeddedPayload()
        {
            return APOLLO_BYTES;
        }
    }
}