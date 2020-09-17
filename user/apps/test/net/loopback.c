/** NexusOS: Lowest level testing of userlevel network stack: loopback.
    The lwIP stack does not have to communicate with the Nexus kernel for
    this task, which makes it an ideal unittest. 

    We run the test at the lwip/RawAPI level
  */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/udp.h>
#include <lwip/tcp.h>
#include <lwip/tcpip.h>
#include <lwip/netifapi.h>
#include <lwip/sockets.h>

#include <nexus/sema.h>
#include <nexus/Thread.interface.h>

#define ReturnError(stmt) do { fprintf(stderr, "%s.%d: %s\n", __FUNCTION__, __LINE__, stmt); return 1; } while (0)
#define SRVPORT 8000
#define UDPPORT 9000

#define PAYLOAD "helloworld"
#define PLEN strlen(PAYLOAD)

int udpdone, tcpdone, threadsdone;

static struct netif loopif;
static struct ip_addr ipaddr;
static struct tcp_pcb *tcp_server;
static Sema sema = SEMA_INIT;

err_t loopif_init(struct netif *netif);

static void
tcpipthread_ready(void *_sem)
{
	sys_sem_t sem = _sem;
	sys_sem_signal(sem);
printf("signal\n");
}

static void *
fasttimer_thread(void *arg)
{
	while (!tcpdone) {
		Thread_USleep(TCP_FAST_INTERVAL * 1000);
		tcp_fasttmr();
	};
	printf("T1 done\n");
}

static void *
slowtimer_thread(void *arg)
{
	while (!tcpdone) {
		Thread_USleep(TCP_SLOW_INTERVAL * 1000);
		tcp_slowtmr();
	};
	printf("T2 done\n");
}

/** initialize the loopback device */
static int
lwip_loopback_init(void)
{
	struct ip_addr netmask, gw;
	sys_sem_t sem;
#ifdef MULTITHREADED
#else
	pthread_t thread;
#endif
	
	netif_init();
	sem = sys_sem_new(0);

#ifdef MULTITHREADED
	tcpip_init(tcpipthread_ready, sem);
printf("about to wait\n");
	sys_sem_wait(sem);
	sys_sem_free(sem);
printf("TCP thread up\n");
#else
	lwip_init();
	// BUG: thread allocation delays could case first wakeups to be too late
	pthread_create(&thread, NULL, &fasttimer_thread, NULL);
	pthread_create(&thread, NULL, &slowtimer_thread, NULL);
#endif
    	IP4_ADDR(&gw, 0, 0, 0, 0);
   	IP4_ADDR(&ipaddr, 127, 0, 0, 1);
    	IP4_ADDR(&netmask, 255, 0, 0, 0);
	
#ifdef MULTITHREADED
	netifapi_netif_add(&loopif, &ipaddr, &netmask, &gw, NULL, loopif_init,
		           ip_input);	// XXX should this be tcpip_input?
	netifapi_netif_set_default(&loopif);
	netifapi_netif_set_up(&loopif);
#else
	netif_add(&loopif, &ipaddr, &netmask, &gw, NULL, loopif_init,
	          ip_input);
	netif_set_default(&loopif);
	netif_set_up(&loopif);
#endif

	return 0;
}

static void
lwip_udp_recv(void *arg, struct udp_pcb *conn, struct pbuf *p,
	      struct ip_addr *addr, u16_t port)
{
	if (p->len == PLEN && !memcmp(p->payload, PAYLOAD, PLEN))
		udpdone = 1;
}

static int
lwip_loopback_udp_test(void)
{
	struct udp_pcb *server, *client;
	struct ip_addr dstaddr;
	struct pbuf *p;
    	
	IP4_ADDR(&dstaddr, 127, 0, 0, 1);

	// setup server
	server = udp_new();
	if (!server)
		ReturnError("udp new");

	if (udp_bind(server, IP_ADDR_ANY, UDPPORT) != ERR_OK)
		ReturnError("udp bind");

	udp_recv(server, lwip_udp_recv, NULL);

	// client
	client = udp_new();
	if (!client)
		ReturnError("udp new #2");

	if (udp_connect(client, &dstaddr, UDPPORT) != ERR_OK)
		ReturnError("udp connect");

	p = pbuf_alloc(PBUF_TRANSPORT, PLEN, PBUF_RAM);
	memcpy(p->payload, PAYLOAD, PLEN); 
	if (udp_send(client, p) != ERR_OK)
		ReturnError("udp send");
	
	while (!udpdone) {
		netif_poll(&loopif);
		Thread_Yield();
	}
	pbuf_free(p);

	return 0;
}

static err_t
__server_recv(void *arg, struct tcp_pcb *conn, struct pbuf *buf, err_t err)
{
	int ret = ERR_IF;

	// validate state
	if (err != ERR_OK) {
		fprintf(stderr, "%s init failed\n", __FUNCTION__);
		return ERR_IF;
	}

	// ack
	tcp_recved(conn, buf->tot_len);
	
	// validate contents
	if (buf->len == PLEN && !memcmp(buf->payload, PAYLOAD, PLEN)) {
		printf("DEBUG: loopback received correct data\n");
		tcpdone = 1;
		ret = ERR_OK;
	}

// closing here causes crash. why?
#if 0
	// close
	if (tcp_close(conn) != ERR_OK) {
		fprintf(stderr, "close failed\n");
		return ERR_IF;
	}
#endif

	return ret;
}

static err_t
__server_accept(void *arg, struct tcp_pcb *conn, err_t err)
{
	static int connport = SRVPORT + 1;

	// validate state
	if (err != ERR_OK) {
		fprintf(stderr, "%s init failed\n", __FUNCTION__);
		return ERR_IF;
	}

	tcp_recv(conn, __server_recv);
	tcp_accepted(tcp_server);
	return ERR_OK;
}

static err_t
__client_connect(void *arg, struct tcp_pcb *conn, err_t err)
{
	// validate state
	if (err != ERR_OK) {
		fprintf(stderr, "%s init failed\n", __FUNCTION__);
		return ERR_IF;
	}

	// write reply
	if (tcp_write(conn, PAYLOAD, PLEN, TCP_WRITE_FLAG_COPY) != ERR_OK) {
		fprintf(stderr, "write failed\n");
		return ERR_IF;
	}

	if (tcp_output(conn) != ERR_OK) {
		fprintf(stderr, "output failed\n");
		return ERR_IF;
	}

#if 0
	if (tcp_close(conn) != ERR_OK) {
		fprintf(stderr, "close failed in client\n");
		return ERR_IF;
	}
#endif

	return ERR_OK;
}

/** test the loopback device at low level */
static int
lwip_loopback_tcp_test(void)
{
	struct tcp_pcb *client;
	struct ip_addr srvaddr, dstaddr;

    	IP4_ADDR(&srvaddr, 0, 0, 0, 0);
    	IP4_ADDR(&dstaddr, 127, 0, 0, 1);

	// setup server
	tcp_server = tcp_new();
	if (!tcp_server)
		ReturnError("new");

	if (tcp_bind(tcp_server, &srvaddr, SRVPORT) != ERR_OK)
		ReturnError("bind");

	tcp_server = tcp_listen(tcp_server);
	if (!tcp_server)
		ReturnError("listen");

	tcp_accept(tcp_server, __server_accept);

	// connect with client
	client = tcp_new();
	if (!client)
		ReturnError("new #2");

	if (tcp_connect(client, &dstaddr, SRVPORT, __client_connect) != ERR_OK)
		ReturnError("connect");

	while (!tcpdone) {
		netif_poll(&loopif);
		Thread_Yield();
	}
	printf("TCP: done\n");

	return 0;

}

int 
main(int argc, char **argv)
{
	if (lwip_loopback_init())
		ReturnError("init");

	if (lwip_loopback_udp_test())
		return 1;

	if (lwip_loopback_tcp_test())
		return 1;

	printf("OK. loopback tests succeeded\n");
	return 0;
}

