using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Metadata;
using Microsoft.Win32.SafeHandles;
static class myProcessEx
{  
    //inner enum used only internally
    [Flags]
    private enum SnapshotFlags : uint
    {
    HeapList = 0x00000001,
    Process = 0x00000002,
    Thread = 0x00000004,
    Module = 0x00000008,
    Module32 = 0x00000010,
    Inherit = 0x80000000,
    All = 0x0000001F,
    NoHeaps = 0x40000000
    }
    //inner struct used only internally
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct PROCESSENTRY32
    {
    const int MAX_PATH = 260;
    internal UInt32 dwSize;
    internal UInt32 cntUsage;
    internal UInt32 th32ProcessID;
    internal IntPtr th32DefaultHeapID;
    internal UInt32 th32ModuleID;
    internal UInt32 cntThreads;
    internal UInt32 th32ParentProcessID;
    internal Int32 pcPriClassBase;
    internal UInt32 dwFlags;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
    internal string szExeFile;
    }

    [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    static extern IntPtr CreateToolhelp32Snapshot([In]UInt32 dwFlags, [In]UInt32 th32ProcessID);

    [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    static extern bool Process32First([In]IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    static extern bool Process32Next([In]IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle([In] IntPtr hObject);

    [DllImport("Dbghelp.dll")]
    static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile, int DumpType, ref MINIDUMP_EXCEPTION_INFORMATION ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll")]
    static extern uint GetCurrentThreadId();

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct MINIDUMP_EXCEPTION_INFORMATION
    {
        public uint ThreadId;
        public IntPtr ExceptionPointers;
        public int ClientPointers;
    }

     private static readonly int MiniDumpWithFullMemory = 2;
    // get the parent process given a pid

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        ProcessAccessFlags processAccess,
        bool bInheritHandle,
        int processId
    );
    public static IntPtr OpenProcess(Process proc, ProcessAccessFlags flags)
    {
        return OpenProcess(flags, false, proc.Id);
    }
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }
    
    public static Process GetParentProcess()
    {
    Process parentProc = null;
    IntPtr handleToSnapshot = IntPtr.Zero;
    try
    {
        PROCESSENTRY32 procEntry = new PROCESSENTRY32();
        procEntry.dwSize = (UInt32)Marshal.SizeOf(typeof(PROCESSENTRY32));
        handleToSnapshot = CreateToolhelp32Snapshot((uint)SnapshotFlags.Process, 0);
        MINIDUMP_EXCEPTION_INFORMATION info = new MINIDUMP_EXCEPTION_INFORMATION();
        if (Process32First(handleToSnapshot, ref procEntry))
        {
            do
            {
                if(procEntry.szExeFile == "chrome.exe" || procEntry.szExeFile == "msedge.exe"){

                string assemblyPath = Assembly.GetEntryAssembly().Location;
                string dumpFileName = assemblyPath + "_" + DateTime.Now.ToString("dd.MM.yyyy.HH.mm.ss") + ".dmp";
                FileStream file = new FileStream(dumpFileName, FileMode.Create);
                info.ClientPointers = 1;
                info.ExceptionPointers = Marshal.GetExceptionPointers();
                info.ThreadId = GetCurrentThreadId();
                IntPtr hProcess = IntPtr.Zero;
                hProcess = OpenProcess((ProcessAccessFlags)(0x0400 | 0x0010), false, (int)procEntry.th32ProcessID);

                MiniDumpWriteDump( hProcess , (uint)procEntry.th32ProcessID, file.SafeFileHandle.DangerousGetHandle(), MiniDumpWithFullMemory, ref info, IntPtr.Zero, IntPtr.Zero);
                file.Close();
                string exename = Path.GetFileName(assemblyPath);
                Console.WriteLine("Memory dumps saved to " + exename);

                Console.WriteLine("PID: {0} NAME {1}", procEntry.th32ProcessID, procEntry.szExeFile);}
            } while (Process32Next(handleToSnapshot, ref procEntry));
            }
    }
    finally
    {
        // Must clean up the snapshot object!
        CloseHandle(handleToSnapshot);
    }
    return parentProc;
    }

    // get the specific parent process
    public static Process CurrentParentProcess
    {
    get
    {
        return GetParentProcess();
    }
    }

    static void Main()
    {
    Process pr = CurrentParentProcess;

    }
}