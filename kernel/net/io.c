/** NexusOS: kernel core networking code */

#include <nexus/defs.h>
#include <nexus/queue.h>
#include <nexus/synch.h>
#include <nexus/machineprimitives.h>
#include <nexus/device.h>
#include <nexus/net.h>
#include <nexus/thread.h>
#include <nexus/clock.h>
#include <nexus/util.h> // for atoi
#include <nexus/queue.h> // for atoi
#include <nexus/syscalls.h>
#include <nexus/clock.h>
#include <asm/param.h> // for HZ
#ifdef __NEXUSXEN__
#include <nexus/xen-defs.h>
#endif

// XXX both of these should go: 
// - only switch needs to know about default NIC
// - default switch IPC port is now hardcoded default_switch_port
Port_Num default_ip_nic;

/// default source for all userspace packets. is overwritten
//  with true MAC of default address in the vswitch.
char default_mac_address[6];		///< who to send outgoing packets as
int default_nic_port;			///< where to send packets out on

char myip[4]; 				///< network byte order
unsigned int my_ipaddress;
unsigned int my_gateway;
unsigned int my_netmask = 0x00ffffff; 	///< 255.255.255.0
unsigned int switch_packetcount;

unsigned char serverip[4];
unsigned char server_mac[6];

//////// support routines

static int is_zero(char *ip) 
{
	return (* (uint32_t *) ip) == 0 ? 1 : 0;
}

static int __nexus_isdigit(char value)
{
	return (value >= '0' && value <= '9') ? 1 : 0;
}

/** return true if the given address matches mine */
static int 
ethdst_me(const char *addr) 
{
	return memcmp(addr, default_mac_address, 6) ? 0 : 1;
}

/** parse a string holding an IPv4 address ("x.x.x.x") 
    and return it in big endian format

    @param in holds a string, does not have to be \0 terminated.
    @return 0 on success; -1 on failure.			
 */
static int
__nexus_parse_ipv4(const char *in, unsigned int *out)
{
        int field, field_off, tmp;
        short fieldval;

	tmp = 0;

        field_off = 0;
        for (field = 0; field < 4; field++) {
                char c_off = 0;

                // first character must be a digit
                if (!__nexus_isdigit(in[field_off])) {
			printk("WARNING character %d of [%s] is not a digit\n", field_off, in);
                        return 1;
		}
                fieldval = in[field_off] - '0';

                // 2nd and 3rd are optional.
                if (__nexus_isdigit(in[field_off + 1])) {
                        c_off++;
                        fieldval *= 10;
                        fieldval += in[field_off + 1] - '0';
                        if (__nexus_isdigit(in[field_off + 2])) {
                                c_off++;
                                fieldval *= 10;
                                fieldval += in[field_off + 2] - '0';
                        }
                }

                // dot connector required
                if (field < 3 && in[field_off + c_off + 1] != '.') 
                        return 1;

                // done. go to next field
		tmp += fieldval;
		if (field < 3)
			tmp <<= 8;
                field_off += c_off + 2;
        }
	
	*out = tmp;
	return 0;
}


//////// networking shell commands

/** Shell command to initialize network devices */
int shell_netopen(int ac, char **av) {
	static int initialized;
	int i, kernel_ok, user_ok;

	if (ac > 2) 
		return BAD_USAGE;
	
	kernel_ok = (ac == 1 || !strcmp(av[1], "kernel"));
	user_ok = (ac == 1 || !strcmp(av[1], "user"));

	if (kernel_ok && !initialized) {
		initialized = 1;
		vortex_init();
		tg3_init();
	}

	return 0;
}

DECLARE_SHELL_COMMAND(netopen, shell_netopen, "[user|kernel] -- pick and initialize one of the network drivers\n"
	   "	with kernel option, only uses in-kernel drivers; with user only userspace drivers");


//////// state get and set

int
getmyip_int(void)
{
	return *(uint32_t *) myip;
}

char *
getmyip(void) 
{
	int i;

	if (default_ip_nic <= 0) {
	      printkx(PK_NET, PK_INFO, "no default address\n");
	      return NULL;
	}
	
	return is_zero(myip) ? NULL : myip;
}

/* Return string containing server address if 
   both networking and server configured; NULL otherwise.

   Server is set in one of three ways:
     1) at the kernel command line (alongside vga=... add server=X.X.X.X)
     2) through nexusbootd
     3) by defining SERVER_IP
 */
char *
getserverip(void) 
{

#ifdef SERVER_IP
	if (is_zero(serverip)) {
		memcpy(serverip, SERVER_IP, 4);
		memcpy(server_mac, SERVER_MAC, 6);
	}
#endif

	return is_zero(serverip) ? NULL : serverip;
}

void set_server(char *server) {
	unsigned int uiaddr;

	if (__nexus_parse_ipv4(server, &uiaddr)) {
		printk("Failed to parse boot option server=%s\n", server);
		return;
	}
		
	uiaddr = htonl(uiaddr);
	memcpy(serverip, (char *) &uiaddr, 4);
}


