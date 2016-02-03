# FirewallExtension-Linux-Kernel-Module-
A kernel module that allows programs to operate on specified ports

This was created for an assignment for my operating systems module in my third year of study.

The files include a userspace program firewallSetup.c and a kernel module firewallExtension.c (.ko when MakeFile executed). 

When the MakeFile is executed, firewallExtension.ko needs to be inserted using ```insmod```.

firewallSetup.c
---------------
---------------

This allows the user to either print the current firewall rules or specify new rules.

```
Usage: L | W <filename>
```
Filename contains the firewall rules, each rule with the format ```<portno> <program name>``` 
The program name must be the full path of the program, and cannot include sym-links.

The method ```parseRules``` opens this file and iterates through each lines, using a regular expression to check each rule is well formed. The rule is parsed using ```strtok``` to extract the path of the program name and check it exists (using stat command).

If the rule is well formed and the program exists, then it is added to a singly linked list; this is then passed to ```writeToProc```.

```writeToProc``` writes each node in the linked list to the proc file, or just the flag (if L is used). The proc file is how the kernel communicates with userspace (and vice versa).

firewallExtension.c
-------------------
-------------------

```kernelRead``` acts as the interface between kernel space and userspace. The data from the proc file is read into the buffer and a switch statement is used on the first character, to either print the rules or update them. 

```updateRules``` takes in a flag 'W' to mark the start of the rules and parses the rules until 'EOF' is read. The port no and program name is extracted and added to a linked list. The old linked list is then swapped out for the new one using a temporary variable. 

The method ```FirewallExtensionHook``` was given as a template; it has been modified to check if an incoming connection can be allowed to proceed. 

```C
     path = findExecutable(); //get exectuable for each process

	   if (isProgramAllowed(ntohs(tcp->dest), path)!=0) { //if not allowed
	       tcp_done (sk); /* terminate connection immediately */
	       printk (KERN_INFO "Program not allowed on this port: connection shut down\n");
         kfree(path);
	       return NF_DROP;
	   }
     kfree(path);
     
```
I inserted the above code. It shows the char pointer ```path``` being assigned to the full path name of the program making a connection (e.g. telent). ```isProgramAllowed``` checks whether this program allowed on the port number (```ntohs(tcp->dest)```).

```findExectutable``` gets the path of the executable of the currently connecting program. It combines the pid and ```kern_path``` method to get the dentry. This is then iterated through (backwards) to get the full path.

```isProgramAllowed``` takes in a port number and the path of the program. It iterates through the linked list and checks if the port number is present. If it isn't then the program is allowed to connect; if it is, then list it iterated though again to check if the specified program is also present. 

```printRules()``` is run if the 'L' flag is specified in the userspace program. It simply iterates through the linked list and prints each rule to the kernel log (/var/log/kern.log). 
