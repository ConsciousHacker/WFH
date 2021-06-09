//--------------------------//
// Calling Native Functions //
//--------------------------//

// Native function pointer
var pGetModuleFileNameW = Module.findExportByName("Kernel32.dll","GetModuleFileNameW");

// Function prototype
var fGetModuleFileNameW = new NativeFunction(
    pGetModuleFileNameW,
    "uint32",
    [
        "pointer",
        "pointer", 
        "uint32"
    ]
);

// Array to store LoadLibrary calls
var aModules = new Array();

//-------------------------//
// Load library call chain //
//-------------------------//

// Native function pointers
var pLoadLibraryW = Module.findExportByName('Kernel32.dll', 'LoadLibraryW')
var pLoadLibraryExW = Module.findExportByName('Kernel32.dll', 'LoadLibraryExW')
var pGetProcAddress = Module.findExportByName('Kernel32.dll', 'GetProcAddress')

// Enums
var Dll_dwFlags = {
    NONE: 0x0,
    DONT_RESOLVE_DLL_REFERENCES: 0x1,
    LOAD_IGNORE_CODE_AUTHZ_LEVEL: 0x10,
    LOAD_LIBRARY_AS_DATAFILE: 0x2,
    LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE: 0x40,
    LOAD_LIBRARY_AS_IMAGE_RESOURCE: 0x20,
    LOAD_LIBRARY_SEARCH_APPLICATION_DIR: 0x200,
    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: 0x1000,
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: 0x100,
    LOAD_LIBRARY_SEARCH_SYSTEM32: 0x800,
    LOAD_LIBRARY_SEARCH_USER_DIRS: 0x400,
    LOAD_WITH_ALTERED_SEARCH_PATH: 0x8
}

// Helpers
function ParseDllFlags(FlagVal) {
    var BitMask = [];

    if (FlagVal == Dll_dwFlags.NONE) {
        BitMask.push("NONE");
    } else {
        if ((FlagVal & Dll_dwFlags.DONT_RESOLVE_DLL_REFERENCES) == Dll_dwFlags.DONT_RESOLVE_DLL_REFERENCES) BitMask.push("DONT_RESOLVE_DLL_REFERENCES");
        if ((FlagVal & Dll_dwFlags.LOAD_IGNORE_CODE_AUTHZ_LEVEL) == Dll_dwFlags.LOAD_IGNORE_CODE_AUTHZ_LEVEL) BitMask.push("LOAD_IGNORE_CODE_AUTHZ_LEVEL");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_AS_DATAFILE) == Dll_dwFlags.LOAD_LIBRARY_AS_DATAFILE) BitMask.push("LOAD_LIBRARY_AS_DATAFILE");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE) == Dll_dwFlags.LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE) BitMask.push("LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_AS_IMAGE_RESOURCE) == Dll_dwFlags.LOAD_LIBRARY_AS_IMAGE_RESOURCE) BitMask.push("LOAD_LIBRARY_AS_IMAGE_RESOURCE");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_SEARCH_APPLICATION_DIR) == Dll_dwFlags.LOAD_LIBRARY_SEARCH_APPLICATION_DIR) BitMask.push("LOAD_LIBRARY_SEARCH_APPLICATION_DIR");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) == Dll_dwFlags.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) BitMask.push("LOAD_LIBRARY_SEARCH_DEFAULT_DIRS");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR) == Dll_dwFlags.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR) BitMask.push("LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_SEARCH_SYSTEM32) == Dll_dwFlags.LOAD_LIBRARY_SEARCH_SYSTEM32) BitMask.push("LOAD_LIBRARY_SEARCH_SYSTEM32");
        if ((FlagVal & Dll_dwFlags.LOAD_LIBRARY_SEARCH_USER_DIRS) == Dll_dwFlags.LOAD_LIBRARY_SEARCH_USER_DIRS) BitMask.push("LOAD_LIBRARY_SEARCH_USER_DIRS");
        if ((FlagVal & Dll_dwFlags.LOAD_WITH_ALTERED_SEARCH_PATH) == Dll_dwFlags.LOAD_WITH_ALTERED_SEARCH_PATH) BitMask.push("LOAD_WITH_ALTERED_SEARCH_PATH");
    }

    if (BitMask.length == 0) {
        BitMask.push(FlagVal);
    }

    return BitMask.join("|");
}

Interceptor.attach(pLoadLibraryW, {
    onEnter: function (args) {
        // Make sure var is reset
        this.sideLoad = false;
        var sPath = args[0].readUtf16String();
        // send("LoadLibraryW,LPCWSTR: " + args[0].readUtf16String())
        if (!sPath.toLowerCase().includes("\\windows") && sPath.toLowerCase().includes("dll") && !sPath.toLowerCase().includes("kernel") && !sPath.toLowerCase().includes("ms-win") && !sPath.toLowerCase().includes("advapi") && !sPath.toLowerCase().includes("ntdll") && !sPath.toLowerCase().includes("user32") && !sPath.toLowerCase().includes("gdiplus") && !sPath.toLowerCase().includes("imm32") && !sPath.toLowerCase().includes("gdi32") && !sPath.toLowerCase().includes("ole32") && !sPath.toLowerCase().includes("shell32") && !sPath.toLowerCase().includes("wiatrace") && !sPath.toLowerCase().includes("mscoree") && !sPath.toLowerCase().includes("comctl32") && !sPath.toLowerCase().includes("version") && !sPath.toLowerCase().includes("oleaut32") && !sPath.toLowerCase().includes("wintrust") && !sPath.toLowerCase().includes("crypt32") && !sPath.toLowerCase().includes("sxs") && !sPath.toLowerCase().includes("d3d10warp")) {
            send("LoadLibraryW,LPCWSTR: " + args[0].readUtf16String())
            
            // Store the path to the dll
            this.sPath = args[0].readUtf16String();
            // Set sideload to true to store it in the array of modules
            this.sideLoad = true;
        }
    },
    onLeave: function (retval) {
        if (this.sideLoad){
            // if sideload was true, store it in the array of modules
            var sVal = retval.toString() + " - " + this.sPath;
            if (aModules.indexOf(sVal) == -1) {
                aModules.push(sVal);
            }
        }
    }
});


Interceptor.attach(pLoadLibraryExW, {
    onEnter: function (args) {
        // Make sure var is reset
        this.sideLoad = false;
        var sPath = args[0].readUtf16String();
        // send("1 - LoadLibraryExW,LPCWSTR : " + args[0].readUtf16String())
        if (!sPath.toLowerCase().includes("\\windows") && sPath.toLowerCase().includes("dll") && !sPath.toLowerCase().includes("kernel") && !sPath.toLowerCase().includes("ms-win") && !sPath.toLowerCase().includes("advapi") && !sPath.toLowerCase().includes("ntdll") && !sPath.toLowerCase().includes("user32") && !sPath.toLowerCase().includes("gdiplus") && !sPath.toLowerCase().includes("imm32") && !sPath.toLowerCase().includes("gdi32") && !sPath.toLowerCase().includes("ole32") && !sPath.toLowerCase().includes("shell32") && !sPath.toLowerCase().includes("wiatrace") && !sPath.toLowerCase().includes("mscoree") && !sPath.toLowerCase().includes("comctl32") && !sPath.toLowerCase().includes("version") && !sPath.toLowerCase().includes("oleaut32") && !sPath.toLowerCase().includes("wintrust") && !sPath.toLowerCase().includes("crypt32") && !sPath.toLowerCase().includes("sxs") && !sPath.toLowerCase().includes("d3d10warp")) {
            var FlagVals = ParseDllFlags(args[2])
            // send(FlagVals)
            if (!FlagVals.includes("SYSTEM32") && !FlagVals.includes("DATAFILE")){
                send("LoadLibraryExW,LPCWSTR : " + args[0].readUtf16String() + ", dwFlags : " + FlagVals)

                // Store the path to the dll
                this.sPath = args[0].readUtf16String();
                // Set sideload to true to store it in the array of modules
                this.sideLoad = true;
            }
        }
    },
    onLeave: function (retval) {
        if (this.sideLoad){
            // if sideload was true, store it in the array of modules
            var sVal = retval.toString() + " - " + this.sPath;
            if (aModules.indexOf(sVal) == -1) {
                aModules.push(sVal);
            }
        }
    }
});

Interceptor.attach(pGetProcAddress, {
    onEnter: function (args) { 
        // Call function
        for (var i = 0; i < aModules.length; i++) {
            // send(aModules[i].toString() + " = " + args[0].toString())
            if ((aModules[i].toString()).startsWith(args[0].toString())) {
                // send(aModules[i].toString() + " " + args[0].toString())
                var lpText = Memory.alloc(0x1000)
                var CallResult = fGetModuleFileNameW(args[0], lpText, 0x1000);
                // Print function return value
                send("GetProcAddress,hModule : " + lpText.readUtf16String() + ", LPCSTR: " + args[1].readAnsiString())
            }
        }
    }
});
