import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.win32.network as network
import volatility.utils as utils
import volatility.win32 as win32
# configure volatility
registry.PluginImporter()
config = conf.ConfObject()
registry.register_global_options(config, commands.Command)
#filePath = "file:///D:/Research/Virtual Address Space Research/ubuntu12045.dmp"
filePath = "file:///D:/Research/Virtual Address Space Research/memory.dmp"
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
'''

def findSelfReferenceEntry():
    for pml4Selector in range(0,0x200):
        address = pml4Selector << 39
        if(pml4Selector & 0x100):
            address = 0xffff000000000000 + address 
        vaddr = long(address)
        pml4e = addressSpace.get_pml4e(vaddr)
        pdptAddress = pml4e & 0xffffffffff000
        if(pdptAddress == addressSpace.dtb):
            print "Found a Self-Reference selectot at index ", hex(pml4Selector), "!"

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

findSelfReferenceEntry()
