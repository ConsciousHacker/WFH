var pRegOpenKeyExW= Module.findExportByName('Kernel32.dll', 'RegOpenKeyExW');
var pRegQueryValueExW = Module.findExportByName('Kernel32.dll', 'RegQueryValueExW');
var pNtQueryKey = Module.findExportByName('Ntdll.dll', 'NtQueryKey');
var pRegCloseKey = Module.findExportByName('Advapi32.dll', 'RegCloseKey');
// Native functions
var fNtQueryKey = new NativeFunction(
    pNtQueryKey,
    "uint",
    [
        "pointer",
        "uint", 
        "pointer", 
        "uint",
        "pointer"
    ]
);

// Globals
var aDict = new Array();

// Helpers
function getKeyPath(hKey)  {
    var pBuff = Memory.alloc(0x1000);
    var pRes = Memory.alloc(0x4);
    var iNTSTATUS = fNtQueryKey(hKey, 3, pBuff, 0x1000, pRes);
    if (iNTSTATUS == 0) { //NTSTATUS_SUCCESS
        return (pBuff.add(4)).readUtf16String();
    } else {
        return;
    }
}

function getHivePreDefKey(hKey) {
    if (hKey == 0x80000000) {
        return "HKEY_CLASSES_ROOT";
    } else if (hKey == 0x80000001) {
        return "HKEY_CURRENT_USER";
    } else if (hKey == 0x80000002) {
        return "HKEY_LOCAL_MACHINE";
    } else if (hKey == 0x80000003) {
        return "HKEY_USERS";
    } else if (hKey == 0x80000004) {
        return "HKEY_PERFORMANCE_DATA";
    } else if (hKey == 0x80000050) {
        return "HKEY_PERFORMANCE_TEXT";
    } else if (hKey == 0x80000060) {
        return "HKEY_PERFORMANCE_NLSTEXT";
    } else if (hKey == 0x80000005) {
        return "HKEY_CURRENT_CONFIG";
    } else if (hKey == 0x80000006) {
        return "HKEY_DYN_DATA";
    } else {
        return;
    }
}

function findInArrayDict(hKey) {
    for (var i = 0; i < aDict.length; i++) {
        if (aDict[i].hKey == hKey.toString()) {
            return aDict[i];
        }
    }
    return;
}

function removeInArrayDict(hKey) {
    for (var i = 0; i < aDict.length; i++) {
        if (aDict[i].hKey == hKey.toString()) {
            aDict.splice(i, 1);
            return true;
        }
    }
    return false;
}

function readRegValue(iType, oData) {
    // Not all type processors are implemented, diy :p
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/25cce700-7fcf-4bb6-a2f3-0f6d08430a55
    if (iType == 0x0) {
        return("Type : REG_NONE");
    } else if (iType == 0x1) {
        return("Type : REG_SZ, Value : " + oData.readUtf16String());
    } else if (iType == 0x2) {
        return("Type : REG_EXPAND_SZ, Value : " + oData.readUtf16String());
    } else if (iType == 0x3) {
        return("Type : REG_BINARY");
    } else if (iType == 0x4) {
        return("Type : REG_DWORD, Value : " + oData.readU32());
    } else if (iType == 0x5) {
        return("Type : REG_DWORD_BIG_ENDIAN, Value : " + oData.readU32()); // Not technically accurate
    } else if (iType == 0x6) {
        return("Type : REG_LINK");
    } else if (iType == 0x7) {
        return("Type : REG_MULTI_SZ");
    } else if (iType == 0x8) {
        return("Type : REG_RESOURCE_LIST");
    } else if (iType == 0xb) {
        return("Type : REG_QWORD, Value : " + oData.readU64());
    } else {
        return("UNDEFINED");
    }
}

// Hooks
Interceptor.attach(pRegOpenKeyExW, {
    onEnter: function (args) {
        var sSubKey = args[1].readUtf16String();
        var sFullPath;
        this.bStoreRes = false;
        if (sSubKey) {
            if (sSubKey.indexOf("\\InProcServer32") >= 0 || sSubKey.indexOf("\\LocalServer32") >= 0 || sSubKey.indexOf("\\TreatAs") >= 0 || sSubKey.indexOf("\\ProgID") >= 0 || sSubKey.indexOf("\\ScriptletURL") >= 0) {
                var sBasePath = getKeyPath(args[0]);
                if (sBasePath == undefined) {
                    var defLookup = getHivePreDefKey(args[0].toUInt32());
                    //send("[+] Fullpath: " + defLookup + "\\" + sSubKey);
                    sFullPath = defLookup + "\\" + sSubKey;

                } else {
                    //send("[+] Fullpath: " + sBasePath + "\\" + sSubKey);
                    sFullPath = sBasePath + "\\" + sSubKey;
                    if (sFullPath.startsWith("\\REGISTRY\\USER\\")) {
                        sFullPath = sFullPath.replace("\\REGISTRY\\USER\\", "HKEY_USERS\\");
                    }
                }

                // We want this entry
                this.bStoreRes = true;
                this.sPath = sFullPath;
                this.pHandle = args[4];
            }
        }
    },
    onLeave: function(retval) {
        if (retval.toInt32() == 0) { //ERROR_SUCCESS
            if (this.bStoreRes) {
                var oReg = {"path": this.sPath, "hKey": ((this.pHandle).readPointer()).toString()};
                aDict.push(oReg);
                //send("I stored a val here..");
            }
        }
    }
});

Interceptor.attach(pRegCloseKey, {
    onEnter: function (args) {
        // Do we need to pop an item out of the array?
        var bRemoved = removeInArrayDict(args[0]);
    }
});

Interceptor.attach(pRegQueryValueExW, {
    onEnter: function (args) {
        this.bPrintRes = false;
        // Is the hKey in out array
        var oReg = findInArrayDict(args[0]);
        if (oReg != undefined) {
            // send("Path : " + oReg.path);
            // send("lpValueName : " + args[1].readUtf16String());

            // We want this data
            this.sPath = "Path : " + oReg.path;
            this.lpValueName = "lpValueName : " + args[1].readUtf16String();
            this.bPrintRes = true;
            this.lpType = args[3];
            this.lpData = args[4];
        }
    },
    onLeave: function(retval) {
        if (this.bPrintRes) {
            if (retval.toInt32() == 0) {
                send(this.sPath + "," + this.lpValueName + "," + readRegValue((this.lpType).readU32(), this.lpData));
            }
        }
    }
});