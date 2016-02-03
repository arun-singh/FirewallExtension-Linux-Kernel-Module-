# FirewallExtension-Linux-Kernel-Module-
A kernel module that allows  programs on specified ports

This was created for my operating systems module in my third year of study.

The files include a userspace program firewallSetup.c and a kernel module firewallExtension.c (.ko when MakeFile executed). 

firewallSetup.c
---------------
---------------

This allows the user to either print the current firewall rules or specify new rules.

```
Usage: L | W <filename>
```

Filename contains the firewall rules, each rule with the format ```<portno> <program name>``` 
The program name must be the full path of the program, and not include sym-links.

The method ```parseRules()``` opens this file and iterates through each lines, using a regular expression to check each rule is well formed. The rule is parsed using ```strtok``` to check the program name exists (using stat command).

If the rule is well formed, then it is added to a singly linked-list; this is then passed to ```writeToProc()```.

