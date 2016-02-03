#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include <linux/namei.h>
#include <linux/proc_fs.h> 
#include "firewallExtension.h"
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/rwsem.h>

MODULE_AUTHOR ("Arun Bahra");
MODULE_DESCRIPTION ("Extensions to the firewall") ;
MODULE_LICENSE("GPL");

static DECLARE_RWSEM(sem);

struct proc_dir_entry * procKernelRead; 
static List * firewall_rule_list;
static List * tmp_list;

/* make IP4-addresses readable */

#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

#define PROC_ENTRY_FILENAME "firewallExtension"
#define PRINT_RULES 'L'
#define UPDATE_RULES 'W'
#define BUFFERLENGTH 256        


struct nf_hook_ops *reg;

unsigned int FirewallExtensionHook (const struct nf_hook_ops *ops,
				    struct sk_buff *skb,
				    const struct net_device *in,
				    const struct net_device *out,
				    int (*okfn)(struct sk_buff *)) {

    struct tcphdr *tcp;
    struct tcphdr _tcph;
    struct sock *sk;
    char * path;


  sk = skb->sk;
  if (!sk) {
    printk (KERN_INFO "firewall: netfilter called with empty socket!\n");;
    return NF_ACCEPT;
  }

  if (sk->sk_protocol != IPPROTO_TCP) {
    printk (KERN_INFO "firewall: netfilter called with non-TCP-packet.\n");
    return NF_ACCEPT;
  }

  /* get the tcp-header for the packet */
  tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
  if (!tcp) {
	   printk (KERN_INFO "Could not get tcp-header!\n");
     return NF_ACCEPT;
  }
  
  if (tcp->syn) {
	   struct iphdr *ip;
	   printk (KERN_INFO "firewall: Starting connection \n");
	   ip = ip_hdr (skb);
	   if (!ip) {
	       printk (KERN_INFO "firewall: Cannot get IP header!\n!");
	   }
	   else {
	       printk (KERN_INFO "firewall: Destination address = %u.%u.%u.%u\n", NIPQUAD(ip->daddr));
	   }
	   
     printk (KERN_INFO "firewall: destination port = %d\n", ntohs(tcp->dest)); 
		
	   if (in_irq() || in_softirq()) {
		     printk (KERN_INFO "Not in user context - retry packet\n");
		     return NF_ACCEPT;
	   }

     path = findExecutable(); //get exectuable for each process

	   if (isProgramAllowed(ntohs(tcp->dest), path)!=0) { //if not allowed
	       tcp_done (sk); /* terminate connection immediately */
	       printk (KERN_INFO "Program not allowed on this port: connection shut down\n");
               kfree(path);
	       return NF_DROP;
	   }
     kfree(path);
  }
  return NF_ACCEPT;	
}

EXPORT_SYMBOL (FirewallExtensionHook);

static struct nf_hook_ops firewallExtension_ops = {
	.hook    = FirewallExtensionHook,
	.owner   = THIS_MODULE,
	.pf      = PF_INET,
	.priority = NF_IP_PRI_FIRST,
	.hooknum = NF_INET_LOCAL_OUT
};

int updateRules(char * buffer){
  char * spaceDelim;
  int diff;
  char dest[BUFFERLENGTH];
  char filename[BUFFERLENGTH];
  long port;

  if(strcmp(buffer, "W")==0){ //start of file
    tmp_list = create_list();
    return 0;
  }else if(strcmp(buffer, "EOF")==0){ //end of file
    //swap out old rules for new
    free_list(firewall_rule_list);
    firewall_rule_list = tmp_list;
  }else{
    if(buffer[strlen(buffer)-1]=='\n')
        buffer[strlen(buffer)-1]='\0';

    //split on space
    spaceDelim = strstr(buffer, " ");
    diff = spaceDelim-buffer;
    //Assign port
    strncpy(dest, buffer, diff);
    dest[diff]='\0';
    //Convert port to long
    kstrtol(dest, 10, &port);
    //Assign filename
    strncpy(filename, buffer+diff+1, (strlen(buffer)-diff));
    filename[BUFFERLENGTH-1]='\0';
    
    append_list(tmp_list, filename, (int)port);
  }

  return 0;
}

int isProgramAllowed(int dest, char * p_name){
  ListItem * curr; 
  int portPresent = 0;

  down_read(&sem);
  curr = firewall_rule_list->p_head;
  //check if port is present
  while(curr!=NULL){
    if(curr->dest==dest)
      portPresent=1;
    curr = curr->p_next;
  }

  if(portPresent==1){ //if port present, check for matching program name
    curr = firewall_rule_list->p_head;
    while(curr!=NULL){
      if(curr->dest==dest && strcmp(curr->p_data, p_name)==0){
        up_read(&sem);
        return 0; //connection allowed
      }
      curr = curr->p_next;
    }  
  }else{
    up_read(&sem);
    return 0;
  }
  up_read(&sem);
  return 1;
}

void printRules(){
  ListItem * curr;

  if(is_empty(firewall_rule_list)==0){
    printk(KERN_INFO "No rules to print\n");
    return;
  }

  curr = firewall_rule_list->p_head;
  while(curr!=NULL){
    printk(KERN_INFO "Firewall rule: %d %s\n", curr->dest, curr->p_data);
    curr = curr->p_next;
  }
}

static ssize_t kernelRead (struct file *file, const char *buffer, unsigned long count, loff_t *data) { 
  char * kernelBuffer = kmalloc(BUFFERLENGTH, GFP_KERNEL);
  if (!kernelBuffer) {
    if(tmp_list!= NULL) free_list(tmp_list);
    return -ENOMEM;
  }

  if(count > BUFFERLENGTH){
    printk(KERN_INFO "Count is greater than buffer - make larger!\n");
    kfree (kernelBuffer);
    if(tmp_list!= NULL) free_list(tmp_list);
    return -EFAULT;
  }

  if (copy_from_user (kernelBuffer, buffer, count)) { 
    kfree (kernelBuffer);
    if(tmp_list!= NULL) free_list(tmp_list);
    return -EFAULT;
  }

  kernelBuffer[BUFFERLENGTH-1]='\0';
  //switch on flag
  switch(*kernelBuffer){
    case UPDATE_RULES:
      updateRules(kernelBuffer);
      break;
    case PRINT_RULES:
      printRules();
      break;
    default:
      updateRules(kernelBuffer);
  }

  kfree (kernelBuffer);
  return count;
}
/* 
 * The file is opened - we don't really care about
 * that, but it does mean we need to increment the
 * module's reference count. 
 */
int procfs_open(struct inode *inode, struct file *file){
  if(down_write_trylock(&sem)==0){
    printk (KERN_INFO "Proc file in use\n");
    return -EAGAIN;
  }
  try_module_get(THIS_MODULE);
  return 0;
}

/* 
 * The file is closed - again, interesting only because
 * of the reference count. 
 */
int procfs_close(struct inode *inode, struct file *file){
  up_write(&sem);
  module_put(THIS_MODULE);
  return 0;   /* success */
}

const struct file_operations File_Ops_4_Our_Proc_File = {
    .owner = THIS_MODULE,
    .write = kernelRead,
    .open = procfs_open,
    .release = procfs_close,
};

int init_module(void){

  int errno;
  /* create the proc-file */
  procKernelRead = proc_create_data (PROC_ENTRY_FILENAME, 0644, NULL, &File_Ops_4_Our_Proc_File, NULL);

  if (!procKernelRead) {
     return -ENOMEM;
  }else{
    printk(KERN_INFO "Proc file created\n");
  }
 
  errno = nf_register_hook (&firewallExtension_ops); /* register the hook */
  if (errno) {
    printk (KERN_INFO "Firewall extension could not be registered!\n");
  } 
  else {
    printk(KERN_INFO "Firewall extensions module loaded\n");
  }

  if(errno==0)
    firewall_rule_list = create_list();

  // A non 0 return means init_module failed; module can't be loaded.
  return errno;
}


void cleanup_module(void){

    nf_unregister_hook (&firewallExtension_ops); /* restore everything to normal */
    printk(KERN_INFO "Firewall extensions module unloaded\n");

    remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
    printk(KERN_INFO "Proc file unloaded\n");

    if(firewall_rule_list!=NULL)
      free_list(firewall_rule_list);
}  

char * findExecutable(){
    struct path path;
    pid_t mod_pid;
    struct dentry * curr;

    int lengthCopied = 0; 
    int count = 0;
    
    char * pathToReturn = kmalloc(BUFFERLENGTH*2, GFP_KERNEL);
    char cmdlineFile[BUFFERLENGTH];
    
    int res;
    
    /* current is pre-defined pointer to task structure of currently running task */
    mod_pid = current->pid;
    snprintf (cmdlineFile, BUFFERLENGTH, "/proc/%d/exe", mod_pid); 
    res = kern_path (cmdlineFile, LOOKUP_FOLLOW, &path);
    if (res) {
      printk (KERN_INFO "Could not get dentry for %s!\n", cmdlineFile);
      return "ERROR";
    }
    
    curr = path.dentry;

    //while we havent hit root
    while(strcmp(curr->d_name.name, "/")!=0){
      //first dentry
      if(count==0){
        strncpy(pathToReturn, curr->d_name.name, strlen(curr->d_name.name));
        lengthCopied+=strlen(curr->d_name.name);
        pathToReturn[lengthCopied]='\0';
        prepString(pathToReturn, "/");
        lengthCopied++;
      }else{
        prepString(pathToReturn, curr->d_name.name);
        prepString(pathToReturn, "/");
        lengthCopied+=strlen(curr->d_name.name)+1;
      }

      curr = curr->d_parent;
      count++;
    }

    pathToReturn[lengthCopied]='\0';
    return pathToReturn;
}

//Prepend one string to another (used to build path)
void prepString(char * dest, const char* src){
    int length = strlen(src);
    int i;
    memmove(dest + length, dest, strlen(dest));

    for (i = 0; i < length; ++i){
        dest[i] = src[i];
    }
}


















/* Linked list handling */
List * create_list(void){
  List * p_list = kmalloc(sizeof(List), GFP_KERNEL);
  p_list->p_head = NULL;
  p_list->p_tail = NULL;
  return p_list;
}

void append_list(List *p_list, char * p_data, int dest) {
  
  // Allocate some memory for the size of our structure. -- note: edited so struct created out of func
  ListItem *p_new_item = kmalloc(sizeof(ListItem), GFP_KERNEL);
  p_new_item->p_previous = p_list->p_tail; // Link backwards.
  p_new_item->p_next = NULL;       // We are the new tail -> no p_next.
 
  p_new_item->p_data = kmalloc(strlen(p_data)+1, GFP_KERNEL);     
  strncpy(p_new_item->p_data, p_data, strlen(p_data));
  p_new_item->p_data[strlen(p_data)]='\0';

  p_new_item->dest = dest;
     
  // If there is a tail, link it to us; else we must also be the head.
  if (p_list->p_tail) {
    p_list->p_tail->p_next = p_new_item;
  } else {
    p_list->p_head = p_new_item;
  }                    

  // Now we are the new tail.
  p_list->p_tail = p_new_item;
}

int is_empty(List * p_list){
  if(p_list->p_head==NULL && p_list->p_tail==NULL){
        return 0;
    }
    return 1;
}

char * pop_data(List * p_list){
    return p_list->p_head->p_data;
}

void free_head(List * p_list){
  ListItem * head = p_list->p_head;
  //list one node long
  if(head == p_list->p_tail){
    p_list->p_head = NULL;
    p_list->p_tail = NULL;
  }else{
    ListItem *next = head->p_next;
    p_list->p_head = next;
  }
  kfree(head->p_data);
  kfree(head);
}

int total_list_size(List * list){
  int sum = 0;
  ListItem * curr = list->p_head;
  while(curr!=NULL){
    sum++;
    curr = curr->p_next;
  }
  return sum;
}

void free_list(List* p_list) {
  
  ListItem * head = p_list->p_head;
  ListItem * tmp; 

  if(is_empty(p_list)==0){
    p_list=NULL;
    return;
  } 

  while((tmp=head)!=NULL){
       head = head->p_next;
       //kfree(tmp->dest);
       kfree(tmp->p_data);
       kfree(tmp);
  }
  kfree(p_list);
  p_list=NULL;
}
