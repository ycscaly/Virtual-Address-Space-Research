import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.win32.network as network
import volatility.utils as utils
import volatility.win32 as win32

import struct

MAX_SELECTOR = 0x200
SELECTOR_MSB = 0x100
PAGING_TABLE_SIZE = MAX_SELECTOR * 8
PHYSICAL_ADDRESS = 0xffffffffff000
ENTRY_SIZE = 8
# configure volatility
registry.PluginImporter()
config = conf.ConfObject()
registry.register_global_options(config, commands.Command)
#filePath = "file:///D:/Research/Virtual Address Space Research/ubuntu12045.dmp"
filePath = "file:///D:/Research/Virtual Address Space Research/windows81.dmp"
# default config (note my .volatilityrc is missing some values, 
# so I just used pdb to figure out which values needed setting

base_conf = {
    'profile': 'Win8SP1x64', 
    #'profile': 'LinuxUbuntu12045x64', 
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
    For more about self-reference page table management, read https://www.noteblok.net/wp-content/uploads/sites/3/2015/01/Self-referenced_Page_Tables-Vogel-ASPLOS_SrC.pdf 
    or https://labs.mwrinfosecurity.com/blog/windows-8-kernel-memory-protections-bypass 
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



#These functions iterate over the addresspace seeking for PAGE_READWRITE_EXECUTE kernel pages and ranges.
def printKernelExecutableAndWriteablePages():
    for page,size in addressSpace.get_available_pages():
        if(isAddressExecutable(page) and isAddressWriteable(page) and isKernelSpaceAddress(page)):
            print "Found a writeable & executable kernel page, at: ", hex(page)

def printKernelExecutableAndWriteableRanges():
    for rangeStartAddress,size in addressSpace.get_available_addresses():
        #NOTE: this check may be replaced with a check on all pages in range instead, but i found it good enough for my purpose
        if(isAddressExecutable(rangeStartAddress) and isAddressWriteable(rangeStartAddress) and isKernelSpaceAddress(rangeStartAddress)): 
            print "Found a writeable & executable range, from ",hex(rangeStartAddress)," to ", hex(rangeStartAddress + size), " sized ", hex(size)

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

print "Virtual Address Space Research Entry Point: J.C. In!"


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
