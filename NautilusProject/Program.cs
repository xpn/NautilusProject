using System;
using System.Runtime.InteropServices;

namespace NautilusProject
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            Console.WriteLine("Weird Ways To Execute Unmanaged Code... by @_xpn_");

            if (Environment.Version.Major != 5 || RuntimeInformation.IsOSPlatform(OSPlatform.Windows) == false || IntPtr.Size != 8)
            {
                Console.WriteLine("[!] Warning: This project was tested on .NET Core 5.0.5 (x64 assembly) with a Windows Host OS.");
                Console.WriteLine("[!] Warning: If running on a different Host OS, architecture or version of .NET, your results may vary.");
            }

            var shellcode = System.IO.File.ReadAllBytes("beacon.bin");
            CombinedExec.Execute(shellcode);

            //ExecStubOverwrite.Execute(shellcode);
            //ExecStubOverwriteWithoutPInvoke.Execute(shellcode);
            //ExecNativeSlot.Execute();
        }
    }
}