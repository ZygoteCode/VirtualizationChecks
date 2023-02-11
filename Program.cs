using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;
using System.Reflection;

public class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lib);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr ModuleHandle, string Function);

    public static void Main()
    {
        Console.Title = "Virtualization Checks | Made by https://github.com/GabryB03/";
        Console.ForegroundColor = ConsoleColor.White;

        if (Assembly.GetCallingAssembly() != Assembly.GetExecutingAssembly())
        {
            NotPassed("Entry Point Check", "The assembly that is calling the entry point method is not the currently executing assembly");
        }
        else
        {
            Passed("Entry Point Check", "The assembly that is calling the entry point method is the currently executing assembly");
        }

        DriversCheck();
        UsernameCheck();
        ComputerNameCheck();
        DirectoriesCheck();
        PortConnectionsCheck();
        ProcessesCheck();
        ServicesCheck();
        WineCheck();
        TimingsCheck();
        ModulesCheck();
        SystemNamesCheck();
        RegistryKeysCheck();
        OwnershipCheck();
        ProgramTitleCheck();
        Console.ReadLine();
    }

    public static void Passed(string type, string details)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("[");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write("PASSED");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("] [");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write(type);
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("] " + details);
        Console.WriteLine();
    }

    public static void NotPassed(string type, string details)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("[");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("NOT PASSED");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("] [");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write(type);
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("] " + details);
        Console.WriteLine();
    }

    public static void DriversCheck()
    {
        string[] drives = Directory.GetLogicalDrives();
        string[] drivers = new string[] { "Vmmouse.sys", "vm3dgl.dll", "vmdum.dll", "vm3dver.dll", "vmtray.dll", "vmusbmouse.sys",
            "vmx_svga.sys", "vmxnet.sys", "VMToolsHook.dll", "vmhgfs.dll", "vmmousever.dll", "vmGuestLib.dll", "VmGuestLibJava.dll", "vmscsi.sys",
            "VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys", "VBoxVideo.sys", "vboxdisp.dll", "vboxhook.dll", "vboxmrxnp.dll", "vboxogl.dll",
            "vboxoglarrayspu.dll", "vboxoglcrutil.dll", "vboxoglerrorspu.dll", "vboxoglfeedbackspu.dll", "vboxoglpackspu.dll",
            "vboxoglpassthroughspu.dll", "vboxservice.exe", "vboxtray.exe", "VBoxControl.exe", "balloon.sys", "netkvm.sys",
            "vioinput", "viofs.sys", "vioser.sys" };

        foreach (string drive in drives)
        {
            if (Directory.Exists(drive + "Windows"))
            {
                foreach (string driver in drivers)
                {
                    if (File.Exists(drive + "Windows\\System32\\drivers\\" + driver))
                    {
                        NotPassed("Drivers Checking", drive + "Windows\\System32\\drivers\\" + driver);
                    }
                    else
                    {
                        Passed("Drivers Checking", drive + "Windows\\System32\\drivers\\" + driver);
                    }
                }

                foreach (string driver in drivers)
                {
                    if (File.Exists(drive + "Windows\\System32\\drivers\\UMDF\\" + driver))
                    {
                        NotPassed("Drivers Checking", drive + "Windows\\System32\\drivers\\UMDF\\" + driver);
                    }
                    else
                    {
                        Passed("Drivers Checking", drive + "Windows\\System32\\drivers\\UMDF\\" + driver);
                    }
                }

                foreach (string driver in drivers)
                {
                    if (File.Exists(drive + "Windows\\Sysnative\\drivers\\" + driver))
                    {
                        NotPassed("Drivers Checking", drive + "Windows\\Sysnative\\drivers\\" + driver);
                    }
                    else
                    {
                        Passed("Drivers Checking", drive + "Windows\\Sysnative\\drivers\\" + driver);
                    }
                }

                foreach (string driver in drivers)
                {
                    if (File.Exists(drive + "Windows\\System32\\" + driver))
                    {
                        NotPassed("Drivers Checking", drive + "Windows\\System32\\" + driver);
                    }
                    else
                    {
                        Passed("Drivers Checking", drive + "Windows\\System32\\" + driver);
                    }
                }
            }
        }
    }

    public static void UsernameCheck()
    {
        string[] badNames = { "Johnson", "Miller", "malware", "maltest", "CurrentUser", "Sandbox", "virus", "John Doe", "test user", "sand box", "WDAGUtilityAccount" };
        string username = Environment.UserName.ToLower();

        foreach (string badName in badNames)
        {
            if (username.ToLower().Equals(badName.ToLower()))
            {
                NotPassed("Username Check", badName);
            }
            else
            {
                Passed("Username Check", badName);
            }
        }
    }

    public static void ComputerNameCheck()
    {
        string[] badNames = { "Johnson", "Miller", "malware", "maltest", "CurrentUser", "Sandbox", "virus", "John Doe", "test user", "sand box", "WDAGUtilityAccount" };
        string computerName = Environment.MachineName.ToLower();

        foreach (string badName in badNames)
        {
            if (computerName.ToLower().Equals(badName.ToLower()))
            {
                NotPassed("Computer Name Check", badName);
            }
            else
            {
                Passed("Computer Name Check", badName);
            }
        }
    }

    public static void DirectoriesCheck()
    {
        string[] drives = Directory.GetLogicalDrives();
        string[] directories = new string[] { "Program Files\\VMWare",
            "Program Files\\Oracle\\VirtualBox Guest Additions", "Program Files (x86)\\Oracle\\VirtualBox Guest Additions" };

        foreach (string drive in drives)
        {
            foreach (string directory in directories)
            {
                if (Directory.Exists(drive + directory))
                {
                    NotPassed("Directories Checking", drive + directory);
                }
                else
                {
                    Passed("Directories Checking", drive + directory);
                }
            }
        }
    }

    public static void PortConnectionsCheck()
    {
        int portConnections = new ManagementObjectSearcher("SELECT * FROM Win32_PortConnector").Get().Count;

        if (portConnections == 0)
        {
            NotPassed("Port Connections Check", "Port connections count (SELECT * FROM Win32_PortConnector): " + portConnections);
        }
        else
        {
            Passed("Port Connections Check", "Port connections count (SELECT * FROM Win32_PortConnector): " + portConnections);
        }
    }

    public static void ProcessesCheck()
    {
        string[] badProcessNames = { "vboxservice", "VGAuthService", "vmusrvc", "qemu-ga" };
        List<string> checkedProcesses = new List<string>();

        try
        {
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    foreach (string badProcessName in badProcessNames)
                    {
                        if (process.ProcessName.ToLower().Equals(badProcessName.ToLower()))
                        {
                            if (!checkedProcesses.Contains(badProcessName.ToLower()))
                            {
                                checkedProcesses.Add(badProcessName.ToLower());
                            }
                        }
                    }
                }
                catch
                {

                }
            }
        }
        catch
        {

        }

        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_Process");

            foreach (ManagementObject queryObj in searcher.Get())
            {
                try
                {
                    foreach (string badProcessName in badProcessNames)
                    {
                        if (Path.GetFileNameWithoutExtension(queryObj["Name"].ToString()).ToLower().Equals(badProcessName.ToLower()))
                        {
                            if (!checkedProcesses.Contains(badProcessName.ToLower()))
                            {
                                checkedProcesses.Add(badProcessName.ToLower());
                            }
                        }
                    }
                }
                catch
                {

                }
            }
        }
        catch
        {

        }

        foreach (string badProcessName in badProcessNames)
        {
            if (checkedProcesses.Contains(badProcessName.ToLower()))
            {
                NotPassed("Processes Check", badProcessName);
            }
            else
            {
                Passed("Processes Check", badProcessName);
            }
        }
    }

    public static void ServicesCheck()
    {
        string[] badServices = { "vmbus", "VMBusHID", "hyperkbd" };
        List<string> checkedServices = new List<string>();
        ServiceController[] GetServicesOnSystem = ServiceController.GetServices();

        foreach (ServiceController service in GetServicesOnSystem)
        {
            foreach (string badService in badServices)
            {
                if (service.ServiceName.ToLower().Contains(badService.ToLower()) || badService.ToLower().Contains(service.ServiceName.ToLower()))
                {
                    if (!checkedServices.Contains(badService.ToLower()))
                    {
                        checkedServices.Add(badService.ToLower());
                    }
                }
            }
        }

        foreach (string badService in badServices)
        {
            if (checkedServices.Contains(badService.ToLower()))
            {
                NotPassed("Services Check", badService);
            }
            else
            {
                Passed("Services Check", badService);
            }
        }
    }

    public static void WineCheck()
    {
        IntPtr ModuleHandle = GetModuleHandle("kernel32.dll");

        if (GetProcAddress(ModuleHandle, "wine_get_unix_file_name").ToInt32() != 0)
        {
            NotPassed("Wine Check", "'wine_get_unix_file_name' function is available in 'kernel32.dll'.");
        }
        else
        {
            Passed("Wine Check", "'wine_get_unix_file_name' function is not available in 'kernel32.dll'.");
        }
    }

    public static void TimingsCheck()
    {
        long tickCount1 = Environment.TickCount;
        Thread.Sleep(500);
        long tickCount2 = Environment.TickCount;

        if (((tickCount2 - tickCount1) < 500L))
        {
            NotPassed("Timings Check", "Emulation is present. Could not validate a timing check.");
        }
        else
        {
            Passed("Timings Check", "Emulation is not present. Timing check validated.");
        }
    }

    public static void ModulesCheck()
    {
        string[] badModules = new string[] { "SbieDll.dll", "cmdvrt32.dll", "cmdvrt64.dll", "SxIn.dll", "cuckoomon.dll" };
        List<string> checkedModules = new List<string>();

        foreach (string badModule in badModules)
        {
            try
            {
                if (GetModuleHandle(badModule).ToInt32() != 0)
                {
                    if (!checkedModules.Contains(badModule.ToLower()))
                    {
                        checkedModules.Add(badModule.ToLower());
                    }
                }
            }
            catch
            {

            }
        }

        try
        {
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                try
                {
                    foreach (string badModule in badModules)
                    {
                        if (module.ModuleName.ToLower().Equals(badModule.ToLower()))
                        {
                            if (!checkedModules.Contains(badModule.ToLower()))
                            {
                                checkedModules.Add(badModule.ToLower());
                            }
                        }
                    }
                }
                catch
                {

                }
            }
        }
        catch
        {

        }

        foreach (Assembly assembly in AppDomain.CurrentDomain.GetAssemblies())
        {
            foreach (string badModule in badModules)
            {
                if (assembly.FullName.ToLower().Contains(badModule.ToLower()) || badModule.ToLower().Contains(assembly.FullName.ToLower()))
                {
                    if (!checkedModules.Contains(badModule.ToLower()))
                    {
                        checkedModules.Add(badModule.ToLower());
                    }
                }
            }
        }

        foreach (Module module in NativeModules.CollectModules(Process.GetCurrentProcess()))
        {
            foreach (string badModule in badModules)
            {
                if (module.ModuleName.ToLower().Equals(badModule.ToLower()))
                {
                    if (!checkedModules.Contains(badModule.ToLower()))
                    {
                        checkedModules.Add(badModule.ToLower());
                    }
                }
            }
        }

        foreach (string badModule in badModules)
        {
            if (checkedModules.Contains(badModule.ToLower()))
            {
                NotPassed("Modules Check", badModule);
            }
            else
            {
                Passed("Modules Check", badModule);
            }
        }
    }

    public static void SystemNamesCheck()
    {
        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
        {
            using (ManagementObjectCollection items = searcher.Get())
            {
                foreach (ManagementBaseObject item in items)
                {
                    string manufacturer = item["Manufacturer"].ToString().ToLower();
                    string model = item["Model"].ToString();

                    if (manufacturer == "microsoft corporation")
                    {
                        NotPassed("System Names Check", "What is checked: {Manufacturer == 'microsoft corporation'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }
                    else
                    {
                        Passed("System Names Check", "What is checked: {Manufacturer == 'microsoft corporation'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }

                    if (manufacturer.ToUpperInvariant().Contains("VIRTUAL"))
                    {
                        NotPassed("System Names Check", "What is checked: {Manufacturer, in upper case invariant, contains 'VIRTUAL'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }
                    else
                    {
                        Passed("System Names Check", "What is checked: {Manufacturer, in upper case invariant, contains 'VIRTUAL'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }

                    if (manufacturer.Contains("vmware"))
                    {
                        NotPassed("System Names Check", "What is checked: {Manufacturer contains 'vmware'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }
                    else
                    {
                        Passed("System Names Check", "What is checked: {Manufacturer contains 'vmware'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }

                    if (model.ToLower().Contains("virtualbox"))
                    {
                        NotPassed("System Names Check", "What is checked: {Model lower case contains 'virtualbox'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }
                    else
                    {
                        Passed("System Names Check", "What is checked: {Model lower case contains 'virtualbox'}, Manufacturer: '" + manufacturer + "', model: '" + model + "'.");
                    }
                }
            }
        }
    }

    public static void RegistryKeysCheck()
    {
        List<string> sandboxStrings = new List<string>() { "vmware", "virtualbox", "vbox", "qemu", "xen" };
        string[] hklmKeys1 = new string[] { @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier", @"SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_VMware_&Prod_VMware_Virtual_S", @"SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\root#vmwvmcihostdev", @"SYSTEM\CurrentControlSet\Control\VirtualDeviceDrivers", @"SOFTWARE\VMWare, Inc.\VMWare Tools", @"SOFTWARE\Oracle\VirtualBox Guest Additions", @"HARDWARE\ACPI\DSDT\VBOX_" };
        string[] hklmKeys2 = new string[] { @"SYSTEM\ControlSet001\Services\Disk\Enum\0", @"HARDWARE\Description\System\SystemBiosInformation", @"HARDWARE\Description\System\VideoBiosVersion", @"HARDWARE\Description\System\SystemManufacturer", @"HARDWARE\Description\System\SystemProductName", @"HARDWARE\Description\System\Logical Unit Id 0" };
       
        foreach (string hklmKey in hklmKeys1)
        {
            RegistryKey openedKey = Registry.LocalMachine.OpenSubKey(hklmKey, false);

            if (openedKey is object)
            {
                NotPassed("Registry Keys Check", "HKEY_LOCAL_MACHINE\\" + hklmKey);
            }
            else
            {
                Passed("Registry Keys Check", "HKEY_LOCAL_MACHINE\\" + hklmKey);
            }
        }

        foreach (string hklmKey in hklmKeys2)
        {
            string valueName = new DirectoryInfo(hklmKey).Name;
            string value = Convert.ToString(Registry.LocalMachine.OpenSubKey(Path.GetDirectoryName(hklmKey), false).GetValue(valueName));
           
            foreach (string sandboxString in sandboxStrings)
            {
                if (!string.IsNullOrEmpty(value) && value.ToLower().Contains(sandboxString.ToLower()))
                {
                    NotPassed("Registry Keys Check (" + sandboxString + ")", hklmKey);
                }
                else
                {
                    Passed("Registry Keys Check (" + sandboxString + ")", hklmKey);
                }
            }
        }
    }

    public static void OwnershipCheck()
    {
        ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_Process");

        foreach (ManagementObject queryObject in searcher.Get())
        {
            if (Path.GetFileNameWithoutExtension(queryObject["Name"].ToString()).ToLower().Equals(Process.GetCurrentProcess().ProcessName.ToLower()))
            {
                ManagementBaseObject outParameters = queryObject.InvokeMethod("GetOwner", null, null);
                string domain = outParameters["Domain"].ToString();
                string user = outParameters["User"].ToString();
                
                if (domain != Environment.MachineName || user != Environment.UserName)
                {
                    NotPassed("Ownership Check", "Domain: '" + domain + "', user: '" + user + "'.");
                }
                else
                {
                    Passed("Ownership Check", "Domain: '" + domain + "', user: '" + user + "'.");
                }
            }
        }
    }

    public static void ProgramTitleCheck()
    {
        try
        {
            string title = Process.GetCurrentProcess().MainWindowTitle;

            if (title.StartsWith("[#]") && title.EndsWith("[#]"))
            {
                NotPassed("Program Title Check", title);
            }
            else
            {
                Passed("Program Title Check", title);
            }
        }
        catch
        {
            Passed("Program Title Check", "No program title available.");
        }
    }
}