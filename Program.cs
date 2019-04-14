/*  Name: CLRSentry
 * 
 * 
 * 
 * 
 * 
 * 
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace CLRSentry
{
    class Program
    {
        //TODO: Rename projec to ModuleMonitor, and add a --clrssentry option to watch for CLR injection
        static void Main(string[] args)
        {

            MonitorModuleLoads();

        }

        /// <summary>
        /// Monitor for module loads using the WMI Event Win32_ModuleLoadTrace.
        /// </summary>
        public static void MonitorModuleLoads()
        {
            //Monitor without any filters
            MonitorModuleLoads(new List<string>());
        }


        /// <summary>
        /// Monitor for module loads using the WMI Event Win32_ModuleLoadTrace. Optionally filter by module names.
        /// </summary>
        /// <param name="filters">A list of module names to filter for.</param>
        public static void MonitorModuleLoads(List<string> filters)
        {
            Console.WriteLine("Monitoring Win32_ModuleLoadTrace...\n");

            //TODO: Add filters for process name and module name using the WHERE clause
            var startWatch = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ModuleLoadTrace"));

            while (true)
            {
                ManagementBaseObject e = startWatch.WaitForNextEvent();

                if (filters.Count == 0 ^ filters.Contains(((ManagementBaseObject)e)["FileName"].ToString()))
                {
                    Console.WriteLine();

                    //Display information from the event
                    Console.WriteLine("[>] Process {0} has loaded a module:", ((ManagementBaseObject)e)["ProcessID"]);
                    Console.WriteLine("{0,15} Win32_ModuleLoadTrace:", "[!]");

                    DateTime time = new DateTime();
                    DateTime.TryParse(((ManagementBaseObject)e)["TIME_CREATED"].ToString(), out time);
                    time.ToLocalTime();

                    //TODO: Time is printing strangley
                    Console.WriteLine("{0,15} (Event)   TIME_CREATED: {1}", "[+]", time.ToString());
                    //TODO: Convert to hex
                    Console.WriteLine("{0,15} (Process) ImageBase: {1}", "[+]", ((ManagementBaseObject)e)["ImageBase"]);
                    Console.WriteLine("{0,15} (Process) DefaultBase: {1}", "[+]", ((ManagementBaseObject)e)["DefaultBase"]);
                    Console.WriteLine("{0,15} (Module)  FileName: {1}", "[+]", ((ManagementBaseObject)e)["FileName"]);
                    Console.WriteLine("{0,15} (Module)  TimeStamp: {1}", "[+]", ((ManagementBaseObject)e)["TimeDateSTamp"]);
                    Console.WriteLine("{0,15} (Module)  ImageSize: {1}", "[+]", ((ManagementBaseObject)e)["ImageSize"]);
                    Console.WriteLine("{0,15} (Module)  ImageChecksum: {1}", "[+]", ((ManagementBaseObject)e)["ImageChecksum"]);

                    Console.WriteLine("{0,15} Additional Information:", "[>]");

                    Process process = SafeGetProcessByID(int.Parse(((ManagementBaseObject)e)["ProcessID"].ToString()));

                    Console.WriteLine("{0,30} Process Name: {1}", "[+]", process.ProcessName);
                    Console.WriteLine("{0,30} Process User: {1}", "[+]", GetProcessUser(process));
                }
            }
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        /// <summary>
        /// Gets the owner of a process.
        /// 
        /// https://stackoverflow.com/questions/777548/how-do-i-determine-the-owner-of-a-process-in-c
        /// </summary>
        /// <param name="process">The process to inspect.</param>
        /// <returns>The name of the user, or null if it could not be read.</returns>
        public static string GetProcessUser(Process process)
        {
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                OpenProcessToken(process.Handle, 8, out processHandle);
                WindowsIdentity wi = new WindowsIdentity(processHandle);
                return wi.Name;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                {
                    CloseHandle(processHandle);
                }
            }
        }//end method


        /// <summary>
        /// Try to get the process by ID and return null if it no longer exists.
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        private static Process SafeGetProcessByID(int id)
        {
            try
            {
                return Process.GetProcessById(id);

            }
            catch
            {
                return null;
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("| Process Manager [v0.1]");
            Console.WriteLine("| Copyright (c) 2019 TheWover");
            Console.WriteLine();

            Console.WriteLine("Usage: ProcessManager.exe [machine]");
            Console.WriteLine();

            Console.WriteLine("{0,-5} {1,-20} {2}", "", "-h, --help", "Display this help menu.");
            Console.WriteLine();

            Console.WriteLine("Examples:");
            Console.WriteLine();

            Console.WriteLine("ProcessManager.exe");
            Console.WriteLine("ProcessManager.exe workstation2");
            Console.WriteLine("ProcessManager.exe 10.30.134.13");
            Console.WriteLine();
        }
    }//end class
}//end namespace
