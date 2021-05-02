using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace NautilusProject
{
    public class ReadGadget
    {
        public static IntPtr ReadMemory(IntPtr addr)
        {
            var stubHelper = typeof(System.String).Assembly.GetType("System.StubHelpers.StubHelpers");
            var GetNDirectTarget = stubHelper.GetMethod("GetNDirectTarget", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

            IntPtr unmanagedPtr = Marshal.AllocHGlobal(200);
            for (int i = 0; i < 200; i += IntPtr.Size)
            {
                Marshal.Copy(new[] { addr }, 0, unmanagedPtr + i, 1);
            }

            return (IntPtr)GetNDirectTarget.Invoke(null, new object[] { unmanagedPtr });
        }
    }
}