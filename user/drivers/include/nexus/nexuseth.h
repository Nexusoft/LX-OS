#ifndef _NEXUS_ETH_H_
#define _NEXUS_ETH_H_

/*XXX all of this should move into nexuscompat.h and devicecompat.h
  (both of which should be renamed) */

struct sk_buff;
struct hh_cache;
struct neighbour;
struct net_device;

int eth_header(struct sk_buff *skb, struct net_device *dev, unsigned short type,
	   void *daddr, void *saddr, unsigned len);
int eth_rebuild_header(struct sk_buff *skb);
unsigned short eth_type_trans(struct sk_buff *skb, struct net_device *dev);
int eth_header_parse(struct sk_buff *skb, unsigned char *haddr);
int eth_header_cache(struct neighbour *neigh, struct hh_cache *hh);
void eth_header_cache_update(struct hh_cache *hh, struct net_device *dev, unsigned char * haddr);


#endif // _NEXUS_ETH_H_
