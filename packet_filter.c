#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/skbuff.h>
#include<linux/ip.h>
#include<linux/netdevice.h>
#include<linux/time.h>
#include<linux/string.h>
#include<linux/moduleparam.h>
#include<linux/inet.h>

#define MAX_HISTORY_SIZE 1024


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Siddharth/Sandeep");

//Version with design modifications

static char *port="test";
static char *sourceip="192.162.1.2";
static long time=0;
module_param(port, charp, 0000);
module_param(sourceip, charp, 0000);
module_param(time, long, 0);

static struct nf_hook_ops pf_hook;					//structure declared for hook, malloc requires header so not used
struct sk_buff *socket_buffer;						//for holding the socket buffer
struct iphdr *ip_header;						//ip header structure
struct timespec kernel_time_now;
struct timespec kernel_time_end;
char s[6] = "";
int i=0;
bool done = false;
__be32 srcip=0;

void module_done(void);
void ip_history_init(void);
void packet_counter(__be32 dest);
void packet_history_print(void);
static unsigned int packet_interceptor_hook( unsigned int hook, 
                                             struct sk_buff *pskb,			//** changed to * after seeing header 
                                             const struct net_device *indev, 
                                             const struct net_device *outdev, 
                                             int (*okfn) (struct sk_buff *)
                                             );


struct ip_info{
	__be32 ip;
	unsigned long count_to;
};

static struct ip_info ip_history[MAX_HISTORY_SIZE];


/*init_pf initializes the required data structures*/
int init_module(void)
{
	printk(KERN_INFO "Initializing packet filter module...\n");
	printk(KERN_INFO "The port to monitor is %s\n",port);
	printk(KERN_INFO "IP Address to be tracked is %s\n", sourceip);
	printk(KERN_INFO "The time for monitoring is %ld ms\n", time);
	
	strcat(sourceip,"\0");
	srcip = in_aton(sourceip);
	
	pf_hook.hook = packet_interceptor_hook;					//not sure if it is correct
	pf_hook.hooknum = 0;//NF_IP_PRE_ROUTING;	//called immediately after packet is recieved, first hook for Netfilter
	pf_hook.pf = PF_INET;								//The field is so as its an IPV4 packet
	pf_hook.priority = NF_IP_PRI_FIRST;						//highest priority hook function	
	nf_register_hook(&pf_hook);							//register the hook with kernel
	ip_history_init();
	strcat(port,"\0");
	printk(KERN_INFO "Module deployed...\n");

	kernel_time_end = current_kernel_time();	
	kernel_time_end.tv_sec += time/1000;	
	kernel_time_end.tv_nsec += time%1000*1000000;

	return 0;
}

/*Does the main processing for packet capturing*/
static unsigned int packet_interceptor_hook( unsigned int hook, 
                                             struct sk_buff *pskb,			//** changed to * after seeing header file
                                             const struct net_device *indev, 
                                             const struct net_device *outdev, 
                                             int (*okfn) (struct sk_buff *)
                                             )
{
	socket_buffer = pskb;
	ip_header = (struct iphdr *)skb_network_header(socket_buffer);		//get the network header using accessor function.
	kernel_time_now = current_kernel_time();
	
	i = timespec_compare(&kernel_time_end, &kernel_time_now);
	
	
	if(i < 0)
	{
		if(done)		//has been added to handle bugs and would never be reached as the function has been unregistered.
		{
			return NF_ACCEPT;
		}
		else
		{
			module_done();
			done = true;
			return NF_ACCEPT;	
		}
	}
	
	if(!socket_buffer)
	{
		return NF_ACCEPT;
	}

	if(indev->name)
	{
		strncpy(s,indev->name, 6);
	}
	strcat(s,"\0");
	i =strcmp(s,port);
	if(!(i)&&(srcip == *&ip_header->saddr))
	{
		packet_counter(*&ip_header->daddr);				//packet counter called
	}
	return NF_ACCEPT;							//Just forward all packets
}

/*official cleanup module*/
void cleanup_module(void)
{
	printk(KERN_INFO "Module removed from mod list...\n");
	nf_unregister_hook(&pf_hook);
}

/*unregisters hook and frees memory. module just tends to sit in the mod list after its execution.*/
void module_done(void)
{
	printk(KERN_INFO "Module cleanup initiated...\n");
	packet_history_print();
	printk(KERN_INFO "\n\n Kindly remove the module...\n\n");
}

void ip_history_init (void){
	for(i=0; i<MAX_HISTORY_SIZE; i++)
	{
		ip_history[i].ip=0;
		ip_history[i].count_to = 0;
	}
}

/*maintains the history of packets*/
void packet_counter(__be32 dest){
	bool dest_exist = false;
	for(i=0; i<MAX_HISTORY_SIZE; i++)
	{
		if(ip_history[i].count_to != 0)
		{
			if(dest == ip_history[i].ip)
			{
					ip_history[i].count_to++;
					dest_exist = true;
					break;
			}
		}
	}
	if(!dest_exist)
	{
		for(i=0; i<MAX_HISTORY_SIZE; i++)
		{
			if(ip_history[i].count_to == 0)
			{
				ip_history[i].ip = dest;
				ip_history[i].count_to++;
				dest_exist = true;						//not required, adding for safety
				break;
			}
		}
	}
}

/*Packet history print function called at the end of module to dispaly all counted addresses */
void packet_history_print(void)
{
	printk(KERN_INFO "The module has monitored the mac port %s for source IP address %s for %ld ms...\n\n", port, sourceip, time);
	printk(KERN_INFO "Count for the packets monitored in this duration:\n\n");
	for(i=0; i<MAX_HISTORY_SIZE; i++)
	{
		if(ip_history[i].count_to != 0)
		{
			printk(KERN_INFO "Destination IP Address: %15pI4 Count: %10ld\n", &ip_history[i].ip, ip_history[i].count_to);
		}
	}
}
