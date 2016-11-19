This is a research on the virtual address space of several x64 based OSes. 
I have written some functions to help iterate the paging structures for several purposes.
Currently, two main purposes are covered:
	1. Printing out all kernel RWX pages [DONE].
	2. Finding out how the page tables are being managed, which is done by:
	    a) finding wheter a self-reference entry exists [DONE].
	    b) finding out all entries that refernces back onto one of the paging constructs [DONE].

Current research status: ONGOING.
As for the page table management(2), Windows uses a self-reference index at pml4 selector 0x1ED. Linux does not.

As for the RWX pages: Linux (under Ubuntu 12.04) does not feature any RWX kernel pages! yay :D
Windows however, features many! not-so-yay.

So, I am trying to understand why there are PAGE_READWRITE_EXECUTE pages in a clean installation of Windows 8.1 x64. 
I have yet to find a reasnoble reason for this behaviour.
Windows 10 was also tested out with similiar results.
When attempting to change permissions on all pages:
 8.1 crashed (when changing everything to non-writeable or non-executable)
 10 did not crash when changing everything to non-writeable (it did when changing to non-executable though.)

The research results are attached as txt files.

Any help would be kindly apperciated.