import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.win32.network as network
import volatility.utils as utils
import volatility.win32 as win32
import volatility.plugins.linux.lsmod as linux_lsmod
import volatility.plugins.modscan as modscan
import struct

PAGE_SIZE = 4096
MAX_SELECTOR = 0x200
SELECTOR_MSB = 0x100
PAGING_TABLE_SIZE = MAX_SELECTOR * 8
PHYSICAL_ADDRESS = 0xffffffffff000
ENTRY_SIZE = 8
# configure volatility
registry.PluginImporter()
config = conf.ConfObject()
registry.register_global_options(config, commands.Command)
filePath = "file:///D:/Research/Linux Kernel Modules/Resources/ubuntu12045latest.dmp"
# default config (note my .volatilityrc is missing some values, 
# so I just used pdb to figure out which values needed setting

base_conf = { 
    'profile': 'LinuxUbuntu12045x64', 
    'use_old_as': None, 
    'kdbg': None, 
    'help': False, 
    'kpcr': None, 
    'tz': None, 
    'pid': None, 
    'output_file': None, 
    'physical_offset': None, 
    'conf_file': None, 
    'dtb': None, 
    'output': None, 
    'info': None, 
    'location': filePath, 
    'plugins': None, 
    'debug': None, 
    'cache_dtb': True, 
    'filename': None, 
    'cache_directory': None, 
    'verbose': None, 'write':False}

# set the default config
for k,v in base_conf.items():
    config.update(k, v)

# configuration complete

# now load up the address space

addressSpace = utils.load_as(config)

'''
    These function requires to pull the latest Volatility version from git, as it uses some new api.
    Note, that some of the functions may pose some untrivial behaviour - but they are all mearly implementation 
    of the x64 virtual memory scheme. Read the Intel / AMD manual to further understand those.
'''

def getPhysicalPageAddress(entry):
    return entry & PHYSICAL_ADDRESS

#returns a list of all physical pages referenced by (some level) paging table construct.
def getPhsyicalPagesForPagingTable(pagingTableAddress):
    # read the full paging table
    pagingTable = addressSpace.base.read(pagingTableAddress & PHYSICAL_ADDRESS, PAGING_TABLE_SIZE)

    if pagingTable is None:
        raise Exception("Bad paging table address")

    # unpack all entries
    entries = struct.unpack('<512Q', pagingTable)

    for entry in range(0, MAX_SELECTOR):
        vaddr = entry << 39
        entry_value = entries[entry]
        if not addressSpace.entry_present(entry_value):
            continue

        physicalPageAddress = (entry_value & PHYSICAL_ADDRESS)
        yield physicalPageAddress

#A generator of start addresses for every paging table construct (all levels) 
def getPagingTables():
    pml4Address = addressSpace.dtb
    
    yield pml4Address
    
    pdptAddresses = list(getPhsyicalPagesForPagingTable(pml4Address))
    
    for pdptAddress in pdptAddresses:
        yield pdptAddress
        pdAddresses = list(getPhsyicalPagesForPagingTable(pdptAddress))
        for pdAddress in pdAddresses:
            yield pdAddress
            ptAddresses = list(getPhsyicalPagesForPagingTable(pdAddress))
            for ptAddress in ptAddresses:
                yield ptAddress

#prints pageing table addresses
def printPagingTables():
    pml4Address = addressSpace.dtb
    
    print "PML4 address is: ", hex(pml4Address)
    
    pdptAddresses = list(getPhsyicalPagesForPagingTable(pml4Address))
    
    for pdptAddress in pdptAddresses:
        print "PDPT address is: ", hex(pdptAddress)
        pdAddresses = list(getPhsyicalPagesForPagingTable(pdptAddress))
        for pdAddress in pdAddresses:
            print "PD address is: ", hex(pdAddress)
            ptAddresses = list(getPhsyicalPagesForPagingTable(pdAddress))
            for ptAddress in ptAddresses:
                print "PT address is: ", hex(ptAddress)


'''
    This method seeks a PML4e that references the original PML4 table, and as such is a self-reference entry.
    For more about self-reference page table management, read https://onedrive.live.com/edit.aspx?cid=31589810d04aaea8&id=documents&resid=31589810D04AAEA8!745&app=OneNote&authkey=!APMjKybJLONKow0&&wd=target%28%2F%2FKernel%20Facilities.one%7C67cfce63-bb27-427e-9a07-0b93738067f0%2FPage%20Table%20Management%7Cb3ba26b7-6481-4632-87aa-369fb29b998f%2F%29
'''
def findSelfReferenceEntry():
    for pml4Selector in range(0,MAX_SELECTOR):
        address = pml4Selector << 39
        
        #Turning into canonical address
        if(pml4Selector & SELECTOR_MSB):
            address = 0xffff000000000000 + address 

        vaddr = long(address)
        pml4e = addressSpace.get_pml4e(vaddr)
        pdptAddress = getPhysicalPageAddress(pml4e) #the physical address that is referenced by the pml4e

        if(pdptAddress == addressSpace.dtb):
            print "Found a Self-Reference selectot at index ", hex(pml4Selector), "!"


#This function aims to find virtual addresses which references onto some portion of the page table constructs.
def findPageTableManagementAddresses():
    pagingTableStartAddresses = list(getPagingTables())
    pagingTableAddresses = {}
    for startAddress  in pagingTableStartAddresses:
        for address in range(startAddress, startAddress + PAGING_TABLE_SIZE, ENTRY_SIZE):
            pagingTableAddresses[address] = True

    for entry,page,size in addressSpace.get_available_pages(True):
        physicalPageAddress = getPhysicalPageAddress(entry)
        if physicalPageAddress in pagingTableAddresses:
            print "The following virtual address: ",hex(page), " references a paging table construct, in physical page: ", hex(physicalPageAddress)


def listModulesLinux():
    modules = set([module for (module, params, sects) in linux_lsmod.linux_lsmod(config).calculate()])
    for mod in modules:
        #print (list(mod.obj_vm.get_available_pages()))[-1]
        print mod.name, hex(mod.module_core), hex(mod.module_core + mod.core_size)
        

#windows specific function
def getAddressKernelModuleMapping():
    scanner = modscan.ModScan(config)
    addressToKernelModule = {}
    for ldr_entry in  scanner.calculate():
        moduleName = str(ldr_entry.BaseDllName or '')
        moduleBaseAddress = ldr_entry.DllBase
        moduleSize = ldr_entry.SizeOfImage
        moduleEndAddress = moduleBaseAddress + moduleSize

        print moduleName, hex(moduleBaseAddress), hex(moduleEndAddress),hex(moduleSize)

        if(moduleBaseAddress & 1 << 48):
            #it is a kernel module
            modulePageStartAddress = moduleBaseAddress - (moduleBaseAddress % PAGE_SIZE)
            modulePageEndAddress  = (moduleEndAddress - (moduleEndAddress % PAGE_SIZE)) + PAGE_SIZE

            for address in range(modulePageStartAddress, modulePageEndAddress, PAGE_SIZE):
                addressToKernelModule[address] = moduleName

    return addressToKernelModule




#A memory range is a continous virtual memory chunk with same attributes (I only check for protection) 
def parseMemoryRanges():
    rangeStartAddress = None
    rangeEndAddress = None
    for currentAddress,size in addressSpace.get_available_pages():
        if(rangeStartAddress is None):
            rangeStartAddress = currentAddress
            rangeEndAddress = currentAddress + size
            continue #start new range
        if(isAddressExecutable(rangeStartAddress) == isAddressExecutable(currentAddress) and \
           isKernelSpaceAddress(rangeStartAddress) == isKernelSpaceAddress(currentAddress) and \
           isAddressWriteable(rangeStartAddress) == isAddressWriteable(currentAddress)):
           rangeEndAddress = currentAddress + size
           continue #with current range
        
        #ended range
        yield (rangeStartAddress, rangeEndAddress)
        rangeStartAddress = currentAddress
        rangeEndAddress = currentAddress + size

def locateKernelExecutableRanges():
    for rangeStartAddress,rangeEndAddress in parseMemoryRanges():
        if(isAddressExecutable(rangeStartAddress) and isKernelSpaceAddress(rangeStartAddress)):
            yield (rangeStartAddress, rangeEndAddress)

def locateKernelWriteableAndExecutableRanges():
    for rangeStartAddress,rangeEndAddress in parseMemoryRanges():
        if(isAddressExecutable(rangeStartAddress) and isKernelSpaceAddress(rangeStartAddress) and isAddressWriteable(rangeStartAddress)):
            yield (rangeStartAddress, rangeEndAddress)


def printKernelExecutableAndWriteableRanges():
    for (rangeStartAddress, rangeEndAddress) in locateKernelWriteableAndExecutableRanges():
        #NOTE: this check may be replaced with a check on all pages in range instead, but i found it good enough for my purpose
        if(isAddressExecutable(rangeStartAddress) and isAddressWriteable(rangeStartAddress) and isKernelSpaceAddress(rangeStartAddress)): 
            print "Found a writeable & executable range, from ",hex(rangeStartAddress)," to ", hex(rangeEndAddress), " sized ", hex(rangeEndAddress-rangeStartAddress)

def printKernelExecutableRanges():
    for (rangeStartAddress, rangeEndAddress) in locateKernelExecutableRanges():
        print "Found a executable range, from ",hex(rangeStartAddress)," to ", hex(rangeEndAddress), " sized ", hex(rangeEndAddress-rangeStartAddress)

def getPageTableEntries(addr):
    vaddr = long(addr)
    
    pml4e = addressSpace.get_pml4e(vaddr)
    entries = [pml4e]

    if not addressSpace.entry_present(pml4e):
        raise Exception("Address not present")

    pdpe = addressSpace.get_pdpi(vaddr, pml4e)
   
    if not addressSpace.entry_present(pdpe):
        raise Exception("Address not present")


    entries += [pdpe]
    if addressSpace.page_size_flag(pdpe):
        return entries

    pdge = addressSpace.get_pgd(vaddr, pdpe)
    if addressSpace.entry_present(pdge):
        entries += [pdge]
        if addressSpace.page_size_flag(pdge):
            return entries
        else:
            pte = addressSpace.get_pte(vaddr, pdge)
            if addressSpace.entry_present(pte):
                entries += [pte]
                return entries
            else:
                raise Exception("Address not present")
    else:
        raise Exception("Address not present")        

def isAddressExecutable(addr):
    return all(map(lambda entry: not addressSpace.is_nx(entry), getPageTableEntries(addr)))

def isAddressWriteable(addr):
    return all(map(lambda entry: addressSpace.is_writeable(entry), getPageTableEntries(addr)))

def isKernelSpaceAddress(addr):
    return any(map(lambda entry: addressSpace.is_supervisor_page(entry), getPageTableEntries(addr)))

def addressToPXE(addr, pte_base):
    return ((addr >> 12) << 2) + pte_base


if __name__ == '__main__':
    print "Virtual Address Space Research Entry Point: J.C. In!"

        
    print "Printing kernel executable ranges"
    printKernelExecutableRanges()
    print "Done printing kernel executable ranges"

    print "Finding Self-Reference entries, if available"
    findSelfReferenceEntry()
    print "Done finding Self-Reference entries"

    print "Printing paging table constructs"
    printPagingTables()
    print "Done printing paging table constructs"

    print "Printing virtual addresses that are used to manage the paging table constructs"
    findPageTableManagementAddresses()
    print "Done printing virtual addresses that are used to manage the paging table constructs"

    print "Printing kernel executable and writeable ranges"
    printKernelExecutableAndWriteableRanges()
    print "Done printing kernel executable and writeable ranges"

    print "Printing kernel executable and writeable pages"
    printKernelExecutableAndWriteablePages()
    print "Done printing kernel executable and writeable pages"


    

    print "Virtual Address Space Research Entry Point: J.C. Out!"

    '''def printKernelExecutableRanges():
    for rangeStartAddress,size in addressSpace.get_available_pages():
        if(isAddressExecutable(rangeStartAddress) and isKernelSpaceAddress(rangeStartAddress)):
            currentAddress =  rangeStartAddress
            while(isAddressExecutable(rangeStartAddress) and isKernelSpaceAddress(rangeStartAddress)):
                
        print "Found a executable range, from ",hex(rangeStartAddress)," to ", hex(rangeStartAddress + size), " sized ", hex(size)
    '''

    
    