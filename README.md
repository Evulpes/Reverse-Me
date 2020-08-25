# Reverse-Me
# Introduction - Soon™
Simply put, I was bored one day and asked my friend, Maximus Hackerman, to give me something to do. Promptly, he sent through a simple executable called "[ReverseMe.exe](https://github.com/Evulpes/Reverse-Me/blob/master/ReverseMe.exe)" ([VirusTotal Link](https://www.virustotal.com/gui/file-analysis/NTFiZmIzNWE4MmNjYzZiZDBjZjIyNjRlMGYyYzYxOWY6MTU5NTUzNDA5NQ==/detection)) with a simple comment of “print the hidden message in your own application”. Naturally, the cpp header files weren’t provided.
Upon running the executable, it simply opens as a console-based application, prints "Sent all the magic packets, exiting soon, beep boop!" and then almost immediately exits; I guess “soon” is subjective.

<p align="center">
  <img src="https://i.imgur.com/8k8wJJb.png"/>
</p>

Fortunately, there doesn’t appear to be anti-debugging, so I guess Hackerman was feeling nice on the day. 

# Runtime Analysis – Zero Day iDiv
After attaching [windbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) and a disassembler, we can see that the application throws, what initially appears to be, an unhandled `divide by zero` exception. 

<p align="center">
  <img src="https://i.imgur.com/WBDGggw.png"/>
</p>

However, on closer inspection, we find that this exception is thrown just prior to application printing its only visible message. It’s important to note that two VEHs ([Vectored Exception Handlers](https://docs.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)) are registered slightly before this point, so it’s likely that this exception is intentional, and used to mangle the control flow. Cheap trick really to try and throw us off really!

<p align="center">
  <img src="https://i.imgur.com/rXX4kRE.png"/>
</p> 

Forgetting the VEHs for the moment, it’s safe to assume that if the application is “sending” packets, then it’s using the [winsock send function](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send) to do so (although, the application clearly says they’re “magic” packets, so we’ll see). 

As expected, it turns out you can’t send packets by magic, so the winsock `send` function is indeed imported.

<p align="center">
  <img src="https://i.imgur.com/UZpYLaU.png"/>
</p> 

By placing a breakpoint on the send function, we can have a look and see if there’s any relevant data we can abstract at the time of sending. Sadly, by the time the buffer is loaded into the function, the data is already encrypted. However, we can determine that the buffer is always 3 bytes in length, the socket is always bound to a hardcoded value of `0x69` (*nice*), and that the send function breakpoint is hit 14 times in total.

<p align="center">
  <img src="https://i.imgur.com/YJ8XGp8.png"/>
</p> 

There are a few ways to go about getting around said encryption. One is to entirely reverse it, which could turn out to be a lot of effort, another is to locate the desired data prior to encryption and abstract it before It becomes encrypted. The latter is significantly easier than the former, so we’re going with that; feel free to reverse the encryption though, I’ve had a brief look and it’s not horrendous. Alternatively, if you’re feeling fancy you could always overwrite the socket handle value and have a receiving application deal with it.

## Handling Handled Handlers
Sadly, there are no useful strings in the read-only data segment, apart from the initial message, so no helpful pointers from that aspect!

<p align="center">
  <img src="https://i.imgur.com/29qMiWH.png"/>
</p> 

Going back to the VEHs, we can see that both registered handlers are used to copy a few unknown objects into an allocated memory buffer. This appears to be done by using [memcpy](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/memcpy-wmemcpy?view=vs-2019), using a function as the second parameter, which in turn uses a hardcoded integer as its second parameter. It’s worth noting that these hardcoded values do not exceed 14 at any point. I’ve only included one of the VEHs in the screenshot, as they are basically identical code-wise except for the hardcoded values.

<p align="center">
  <img src="https://i.imgur.com/Gncmt93.png"/>
</p> 

By breakpointing at one of the memcpy functions and inspecting the subfunction in the second parameter, we can see that the hardcoded integer (13 / 0Dh in the below example) is set to first byte of the a1 parameter, and a1+1 contains a character, just after the pointer is dereferenced.

<p align="center">
  <img src="https://i.imgur.com/bmYAtMc.png"/>
</p> 

If we check the some of the other 14 calls to this function, we can find the same behaviour repeating; arranging the characters from 1 to 14, using the corresponding number as an indicator of order, we can see that they start to spell out some legible words. Now, we could be super lazy and just make a console app to print the message out, once we know what it is, but that really feels like cheating. Plus, the message may change at some point. So, let’s write a code cave to intercept the values before they’re encrypted.

## That’s A Big 0x90 From Me
Sorry, but we’re using C++ for this! If you prefer using C#, feel free to go through the whole [Platform Invoke](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke) process for 9.7 million functions and come back here when you’re done. Anyway, first we need to decide where to code cave. Luckily, we already know! By analysing the above function, however briefly, we know that by the highlighted point `RDX` contains the index, and `RDX+1` contains the corresponding character. Below is the assembly code for the discussed function. 

<p align="center">
  <img src="https://i.imgur.com/dUwMmzs.png"/>
</p> 

Now, logically speaking, the best place to take the jump from would be at `mov [rsp+arg_8], rdx`, as we don’t really care about the third parameter, but do want to intercept `RDX` register and `RDX+1`. To do this kids, we’re going to need a few bytes: 10 bytes for the `MOV` instruction, to move the address of our code cave to a register (we’ll use `RAX`, more on this later during the 10 o’clock news), and 2 bytes for the `JMP` instruction, to jump to the register. For those of you who have PTSD from further maths, that totals at 12 bytes. Now, before we go all Aunt Bessie and spaghettify that code with [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory), we need to consider that there is no ideal place to replace 12 bytes in the above assembly. If we want to jump from offset `0x2905` (`mov [rsp+arg_8], rdx`), and we need 12 bytes to do so, then that takes us to offset `0x2917`, which is smack bang in between two `MOV` instructions. Unfortunately, if we were to just simply write our bytes to there, it would completely mangle the assembly, and likely cause some, uh, “interesting” side effects. As a result, it’s going to be easier (maybe a bit more hacky, sorry not sorry) to add some one-byte instructions for padding and round off to the end of an instruction. Welcome aboard, [0x90](https://en.wikipedia.org/wiki/NOP_(code)).  

<p align="center">
  <img src="https://i.imgur.com/NujXHza.png"/>
</p> 

# Washing Machines Live Longer With Code Caves
Anyway, so now that we know what our plan is, so let’s write some code: [*cue intense hacker man music*](https://youtu.be/fQGbXmkSArs?t=18)! 
## Documentation? What’s that?
Below is what the initial jump to our code cave will look like once the bytes are written into the assembly of the application, complete with its very own NOP slide. 

<p align="center">
  <img src="https://i.imgur.com/eaWiSl8.png"/>
</p> 

However, before we actually write and replace any assembly, we need to start the application in a suspended state; this will stop the application runtime at an early stage, so that memory changes can be made before the application gets to the instruction we’re interested in. The below code extract shows this process, and I won’t go over it too much as you can view it in the source files of this repo, and it mostly speaks for itself.

<p align="center">
  <img src="https://i.imgur.com/lHLrRjO.png"/>
</p> 

Now that the process is spawned, we’ll need to acquire the base address of the process. Normally you can use [EnumProcessModules](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules) for this, but as we immediately suspended the main process thread, the [PEB](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb) does not contain a fully populated [PEB_LDR_DATA](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data) structure, specifically the `InMemoryOrderModuleList`, so we cannot currently get the base address. By the way, this doesn’t appear to be documented anywhere on MSDN. Luckily, this is relatively easy to circumvent; by very quickly resuming the process, querying the modules, and then resuspending the process we can get the information we need without the process progressing too much. 
As with most things in Windows, Microsoft likes to reiterate that it’s operating system is the superior one by again not documenting the functions we need: `NtSuspendProcess` and `NtResumeProcess`. Conveniently, my Dad is friends with Bill Gates, and he tells me that these functions live coupled in `ntdll.dll`, so we can fetch them by using the below class that I made earlier:

<p align="center">
  <img src="https://i.imgur.com/tBpyUSq.png"/>
</p> 

Now that we have the two functions we need, we can resume the process, query the modules, and resuspend the process:

<p align="center">
  <img src="https://i.imgur.com/nudhzXR.png"/>
</p> 

You may be wondering, why is the while loop waiting for two module discoveries as opposed to one? Well, Microsoft is looking to score a hattrick with a meatball in the back of the undocumented spaghetti net by also not mentioning that the first module found by `EnumProcessModules` will be ntdll.dll, and the second will be the executable. While this sounds reasonable, once the executable is found, it will swap indexes with ntdll.dll. Here’s an example:

The result after querying only the first module:

<p align="center">
  <img src="https://i.imgur.com/GIkUPSC.png"/>
</p> 

The result after querying two modules: 

<p align="center">
  <img src="https://i.imgur.com/3hAsmYS.png"/>
</p> 

## The Numbers Mason, What Do They Mean?
Before we go any further, we need to write the assembly code that does the initial jump to the code cave, and the code cave itself. Essentially, we’ll overwrite some memory starting at the offset `0x2905`, take a jump, do our code caving spying, and then jump back to `0x2911` to continue the normal program flow. Initially, we declare the moving of the address to the `RAX` register as `MOV RAX, 0x0`, as the address we’ll jump to is dynamic and we don’t know what it is yet. `RAX` is a safe register to use, as it’s [volatile register](https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions?view=vs-2019) and is overwritten shortly after anyway. Fun fact, this is how Nintendo programmed the original Mario Bros platformer, with lots of jumps (tell me I’m funny)! 
Below is how the code looks in the compiler; it can be created in other ways, but I’ve chosen to dissemble the required assembly instructions into bytecode. If you’re looking to do this at home, use [this website](https://defuse.ca/online-x86-assembler.htm).

<p align="center">
  <img src="https://i.imgur.com/HCfumIG.png"/>
</p> 

The code for the actual code cave is a bit more complex, and the logic for it is also commented in this file, but here’s the rough process:
1.	Move the address of memory we’ve reserved in our application to `R10`	
2.	Set the first byte of our memory to non-signalled
3.	Move the lower part of `RDX`, which contains the packet index, into `R11B`
4.	Move R11B to the second byte of our memory
5.	Move the second byte of `RDX`, which contains the character, into `R11B`
6.	Move R11B to the third byte of our memory
7.	Set the first byte of our memory to signalled
8.	Wait for our application to finish reading the memory, at which point it set the byte to non-signalled
9.	While the byte is signalled, jump to the previous step
10.	Move the address that we jumped from initially (`+12`) to `R10` (which is `0x2911`)
11.	Jump to `R10`
We also need to rewrite the assembly code we overwrote (with the NOP slide) into our code cave to preserve the stack etc.; this code is referenced in the “`Predetermined Assembly`” region, excluding the NOPs. Below is the code cave in its ugly glory:

<p align="center">
  <img src="https://i.imgur.com/J20oTEp.png"/>
</p> 

Hard part over, mostly.
## Oh, yeah. It’s all coming together.
At this point, we essentially have everything we need to siphon the hidden message out of memory, we just need to implement it. To recap, we have a handle to a suspended process that we spawned, 2 byte arrays that represent assembly logic, the base address of the suspended process, stored in `modules[0]`, and the offset of where we need to write the jump logic. The below code snippet creates the address to jump from, the address of the code cave (to jump to), the address of our 3-byte memory storage, writes the addresses into the assembly code, and then writes the assembly code the suspended process, before resuming it:

<p align="center">
  <img src="https://i.imgur.com/AMOm0Mb.png"/>
</p> 

The magical Harry Potter style casting for the `codeCaveStorageAddr` is to convert the address into bytes, and the hardcoded values in the loops are for the dynamic address placements in the assembly arrays. Of course, this can be done in a much cleaner manner (don’t write magic numbers kids), I’m just lazy after having to manually write out all those bytes.
The last few bits to write are the loops to read, using [ReadProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory), the memory, store the characters and indexes into an ordered byte array, signal the byte, using `WriteProcessMemory`, when the reading of the current memory is finished, and print the hidden message. We know that the send function only occurs 14 times, so we exit the while loop once the byte array is filled; this could be altered with more memory edits to signal to our application that the process is “exiting” and our loop can be stopped, rather than using a hardcoded value of 14, but this works for this example.

<p align="center">
  <img src="https://i.imgur.com/K4xV8x7.png"/>
</p> 

The result? Our hidden message is printed in our very own console application! If anyone is curious, NPT is a reference to another piece of software Maximums Hacker-whatever-I-called-him wrote.


<p align="center">
  <img src="https://i.imgur.com/Ghlo5Cs.png"/>
</p> 
