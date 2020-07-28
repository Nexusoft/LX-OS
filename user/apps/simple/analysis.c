#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <nexus/kshmem.h>
#include <nexus/util.h>
#include <nexus/stringbuffer.h>
#include <nexus/vector.h>
#include <nexus/ipc.h>
#include <nexus/hashtable.h>
#include <nexus/debug.h>
#include <nexus/tpmcompat.h>

StringBuffer *all_opens;

#if 0
#define log_open(TYPE,STR)						\
  do { SB_cat(all_opens, TYPE "(");					\
    SB_cat(all_opens, STR); SB_cat(all_opens, ")");			\
    /* writefile("all_o", SB_c_str(all_opens), strlen(SB_c_str(all_opens))); */	\
  } while(0)

#define opendir(STR) ({ log_open("opendir", STR); opendir(STR); })
#define open(STR, FLAGS) ({ log_open("open", STR); open(STR, FLAGS); })
#endif

static void waitforinput(void) {
  char ignored[128];
  fgets(ignored, sizeof(ignored), stdin);
}

int read_int_value(char *path, int *error) {
  int fd = open(path, O_RDONLY);
  if(fd < 0) {
    printf("could not open %s!\n", path);
    *error = 1;
    return -1;
  }
  char buf[32];
  int read_amount = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if(read_amount <= 0) {
    printf("could not read from %s\n", path);
    *error = 1;
    return -1;
  }
  buf[read_amount] = '\0';
  *error = 0;
  return atoi(buf);
}

unsigned read_uint_value(char *path, int *error) {
  int fd = open(path, O_RDONLY);
  if(fd < 0) {
    printf("could not open %s!\n", path);
    *error = 1;
    return -1;
  }
  char buf[32];
  int read_amount = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if(read_amount <= 0) {
    printf("could not read from %s\n", path);
    *error = 1;
    return -1;
  }
  buf[read_amount] = '\0';
  *error = 0;

  unsigned rv;
  sscanf(buf, "%u", &rv);
  return rv;
}

struct IPCGraphIPD;
struct IPCGraphChannel;
typedef struct IPCGraph {
  PointerVector ipds; // IPCGraphIPD
  PointerVector channels;
} IPCGraph;

IPCGraph *IPCGraph_new(void) {
  IPCGraph *rv = malloc(sizeof(*rv));
  PointerVector_init(&rv->ipds, 100, 0);
  PointerVector_init(&rv->channels, 100, 0);
  return rv;
}

int IPCGraph_numIPDs(IPCGraph *graph) {
  return PointerVector_len(&graph->ipds);
}

struct IPCGraphIPD *IPCGraph_nthIPD(IPCGraph *graph, int n) {
  return (struct IPCGraphIPD *)PointerVector_nth(&graph->ipds, n);
}

typedef struct IPCGraphEdge {
  struct IPCGraphChannel *target_channel;
} IPCGraphEdge;

enum IPDAnnotation {
  SOURCE,
  DESTINATION,
  NONE,
};

typedef struct IPCGraphIPD {
  IPD_ID id;
  char *ipd_name;
  PointerVector edges; // IPCGraphEdge
  enum IPDAnnotation annotation;
} IPCGraphIPD;

typedef struct IPCGraphChannel {
  int channel_num;
  int ignore_permissions;
  IPCGraphIPD *owner;
} IPCGraphChannel;

IPCGraphEdge *IPCGraphEdge_new(IPCGraphChannel *target_channel);

struct IPCGraphIPD *IPCGraph_findIPD(IPCGraph *graph, IPD_ID ipd_id);
int IPCGraphIPD_numEdges(IPCGraphIPD *ipd) {
  return PointerVector_len(&ipd->edges);
}
IPCGraphEdge *IPCGraphIPD_nthEdge(IPCGraphIPD *ipd, int n) {
  return (IPCGraphEdge *)PointerVector_nth(&ipd->edges, n);
}

struct IPCGraphChannel *IPCGraph_findChannel(IPCGraph *graph, int channel_num);

void IPCGraph_addIPD(IPCGraph *graph, struct IPCGraphIPD *node) {
  if(IPCGraph_findIPD(graph, node->id) != NULL) {
    printf("IPCGraph_addNode: node already added\n");
  } else {
    PointerVector_append(&graph->ipds, node);
  }
}

void IPCGraph_addChannel(IPCGraph *graph, struct IPCGraphChannel *target_channel) {
  if(IPCGraph_findChannel(graph, target_channel->channel_num) != NULL) {
    printf("add channel: channel %d already exists\n",
	   target_channel->channel_num);
  } else {
    PointerVector_append(&graph->channels, target_channel);
  }
}

void IPCGraph_addEdge(IPCGraph *graph, IPCGraphIPD *src_ipd, IPCGraphChannel *target_channel) {
  // why have edge when we can just target the channel?
  IPCGraphEdge *edge = IPCGraphEdge_new(target_channel);
  PointerVector_append(&src_ipd->edges, edge);
}

struct IPCGraphIPD *IPCGraph_findIPD(IPCGraph *graph, IPD_ID ipd_id) {
  int i;
  int found = 0;
  IPCGraphIPD *cand = NULL;

  for(i=0; i < PointerVector_len(&graph->ipds); i++) {
    cand = (IPCGraphIPD *)PointerVector_nth(&graph->ipds, i);
    if(cand->id == ipd_id) {
      found = 1;
      break;
    }
  }
  if(found) {
    return cand;
  } else {
    return NULL;
  }
}

struct IPCGraphChannel *IPCGraph_findChannel(IPCGraph *graph, int channel_num) {
  int i;
  IPCGraphChannel *cand = NULL;
  int found = 0;
  for(i=0; i < PointerVector_len(&graph->channels); i++) {
    cand = (IPCGraphChannel *)PointerVector_nth(&graph->channels, i);
    if(cand->channel_num == channel_num) {
      found = 1;
      break;
    }
  }
  if(found) {
    return cand;
  } else {
    return NULL;
  }
}

  ///// Edge
IPCGraphEdge *IPCGraphEdge_new(struct IPCGraphChannel *channel) {
  IPCGraphEdge *rv = malloc(sizeof(*rv));
  rv->target_channel = channel;
  return rv;
}

IPCGraphIPD *IPCGraphIPD_new(IPD_ID ipd_id, char *ipd_name) {
  IPCGraphIPD *rv = malloc(sizeof(*rv));
  rv->id = ipd_id;
  rv->ipd_name = strdup(ipd_name);
  PointerVector_init(&rv->edges, 100, 0);
  rv->annotation = NONE;
  return rv;
}

IPCGraphChannel *IPCGraphChannel_new(int channel_num, int ignore_permissions, IPCGraphIPD *owner) {
  IPCGraphChannel *rv = malloc(sizeof(*rv));
  rv->channel_num = channel_num;
  rv->ignore_permissions = ignore_permissions;
  rv->owner = owner;
  return rv;
}

IPCGraph *buildIPCGraph(int *error_count) {
  // First, find all the IPDs in existence
  const char *ipds_dir_name = "/ipds";
  const char *channels_dir_name = "/channels";
  DIR *ipds_dir = opendir(ipds_dir_name);
  DIR *channels_dir = opendir(channels_dir_name);
  IPCGraph *graph = IPCGraph_new();
  *error_count = 0;

  if(ipds_dir == NULL) {
    printf("ipc graph build error: could not open ipds directory\n");
    return NULL;
  }
  if(channels_dir == NULL) {
    closedir(ipds_dir);
    printf("ipc graph build error: could not open channels directory\n");
    return NULL;
  }

  // read in all ipd nodes
  while(1) {
    struct dirent *d = readdir(ipds_dir);
    if(d == NULL) break;
    char path[512];
    // read the id
    char *node_name = d->d_name;
    sprintf(path, "%s/%s/id", ipds_dir_name, node_name);
    int error;
    int id = read_int_value(path, &error);
    if(error != 0) {
      printf("could not read from %s\n", path);
      *error_count += 1;
      continue;
    }
    printf("%s => %d\n", node_name, id);

    IPCGraphIPD *node = IPCGraphIPD_new(id, node_name);
    IPCGraph_addIPD(graph, node);
    printf("added ipd %d\n", id);
  }
  closedir(ipds_dir);

  // read in all channels
  printf("begin channel scan\n");
  while(1) {
    struct dirent *d = readdir(channels_dir);
    if(d == NULL) {
      printf("readdir of channels_dir == NULL\n");
      if(readdir(channels_dir) != NULL) {
	printf("readdir failed\n");
      }
      break;
    }
    char path[512];
    // read the id
    char channel_name[512];
    strcpy(channel_name, d->d_name);
    sprintf(path, "%s/%s/channel_num", channels_dir_name, channel_name);

    int error;
    int channel_num = read_uint_value(path, &error);
    if(error) {
      printf("error reading channel_num\n");
      *error_count += 1;
      continue;
    }
    printf("%s => %u ;; ", channel_name, channel_num);

    sprintf(path, "%s/%s/owner_ipd", channels_dir_name, channel_name);
    int owner_ipd = read_int_value(path, &error);
    if(error) {
      printf("error reading owner_ipd\n");
      *error_count += 1;
      continue;
    }
    sprintf(path, "%s/%s/ignore_permissions", channels_dir_name, channel_name);
    int ignore_permissions = read_int_value(path, &error);
    if(error) {
      printf("error reading ignore_permissions\n");
      *error_count += 1;
      continue;
    }

    printf("%s owned by %d, ignore_permissions = %d\n",
	   channel_name, owner_ipd, ignore_permissions);

    IPCGraphIPD *owner = IPCGraph_findIPD(graph, owner_ipd);
    if(owner == NULL) {
      printf("Could not find owner from %d!\n", owner_ipd);
      *error_count += 1;
      continue;
    }

    IPCGraphChannel *channel = IPCGraphChannel_new(channel_num, ignore_permissions, owner);
    // Now, scan the permission table
    sprintf(path, "%s/%s/permtable", channels_dir_name, channel_name);
    DIR *permtable = opendir(path);
    if(permtable == NULL) {
      printf("could not open the permission table for %s\n", path);
      *error_count += 1;
      continue;
    }
    // printf(";; permission scan of %s ", path);
    while(1) {
      struct dirent *d = readdir(permtable);
      if(d == NULL) break;
#if 0
      printf("%p = ", d);
      printf("\"%s\"\n", d->d_name);
#endif
      int src_ipd_num = atoi(d->d_name);
      IPCGraphIPD *src_ipd = IPCGraph_findIPD(graph, src_ipd_num);
      if(src_ipd == NULL) {
	printf("%s: could not find ipd %d\n", path, src_ipd_num);
	*error_count += 1;
	continue;
      }
      IPCGraph_addEdge(graph, src_ipd, channel);
    }
    closedir(permtable);

    IPCGraph_addChannel(graph, channel);
  }
  closedir(channels_dir);
  return graph;
}

void IPCGraph_toDot(IPCGraph *graph, StringBuffer *sb) {
#define PING() printf("(%d)", __LINE__)
  SB_cat(sb, "graph CommGraph {\n");
  int i;
  char dest_buf[512];
  printf("dest_buf = %p\n", dest_buf);
  for(i=0; i < PointerVector_len(&graph->ipds); i++) {
    IPCGraphIPD *ipd = (IPCGraphIPD *) PointerVector_nth(&graph->ipds, i);

    sprintf(dest_buf, "subgraph cluster%d {\n", ipd->id);
    SB_cat(sb, dest_buf);

    char stylebuf[80] = "";
    switch(ipd->annotation) {
    case SOURCE:
      strcpy(stylebuf, " fillcolor=\"red\" style=filled ");
      break;
    case DESTINATION:
      strcpy(stylebuf, " fillcolor=\"blue\" style=filled ");
      break;
    case NONE:
      break;
    default:
      printf("todot: unsupported annotation\n");
    }
    sprintf(dest_buf, "ipd%d [label=\"%s\" %s];\n", ipd->id, ipd->ipd_name, stylebuf);
    SB_cat(sb, dest_buf);
    int j;
    for(j=0; j < PointerVector_len(&graph->channels); j++) {
      IPCGraphChannel *channel = (IPCGraphChannel *) PointerVector_nth(&graph->channels, j);
      if(channel->owner != ipd) continue;
      char *color;
      sprintf(dest_buf, " ");
      if(channel->ignore_permissions) {
	color = "fillcolor=\"yellow\" style=filled";
      } else {
	color = "";
      }
      char channel_label[80];

      if(channel->channel_num >= MAX_IPD_ID) {
	sprintf(channel_label, "%d", channel->channel_num - MAX_IPD_ID);
      } else {
	sprintf(channel_label, "r(%d)", channel->channel_num);
      }

      sprintf(dest_buf, "node [shape=diamond label=\"%s\" %s] channel%u;\n", channel_label, color, channel->channel_num);
      SB_cat(sb, dest_buf);
    }
    SB_cat(sb, "}\n\n");
  }

  // output channels
  for(i=0; i < PointerVector_len(&graph->channels); i++) {
    IPCGraphChannel *channel = (IPCGraphChannel *) PointerVector_nth(&graph->channels, i);
    sprintf(dest_buf, "	channel%u -- ipd%d [color=\"blue\"];\n", channel->channel_num,
	    channel->owner->id);
    SB_cat(sb, dest_buf);
    SB_cat(sb, "\n");
  }

  SB_cat(sb, "\n\n");
  // output edges
  SB_cat(sb, "// IPC edges\n");
  int j;
  for(i=0; i < PointerVector_len(&graph->ipds); i++) {
    IPCGraphIPD *ipd = (IPCGraphIPD *) PointerVector_nth(&graph->ipds, i);
    for(j=0; j < PointerVector_len(&ipd->edges); j++) {
      IPCGraphEdge *edge = PointerVector_nth(&ipd->edges, j);
      sprintf(dest_buf, "ipd%d -- channel%d [color=\"grey\"];\n",
	      ipd->id, edge->target_channel->channel_num);
      SB_cat(sb, dest_buf);
    }
  }
  SB_cat(sb, "}\n");
}


///////////////////
// Abstract communications flow graph

typedef struct InfoGraph {
  PointerVector ipds;
} InfoGraph;

typedef struct InfoGraphIPD {
  IPD_ID id;
  char *ipd_name;
  PointerVector edges;
  int marks;
  enum IPDAnnotation annotation;
} InfoGraphIPD;

typedef struct InfoGraphEdge {
  InfoGraphIPD *target;
} InfoGraphEdge;

InfoGraph *InfoGraph_new(void);

void InfoGraph_addIPD(InfoGraph *graph, InfoGraphIPD *ipd);
int InfoGraph_numIPDs(InfoGraph *graph);
InfoGraphIPD *InfoGraph_findIPD(InfoGraph *graph, int ipd_id);
InfoGraphIPD *InfoGraph_nthIPD(InfoGraph *graph, int n);
void InfoGraph_clearMarks(InfoGraph *graph);

InfoGraphIPD *InfoGraphIPD_new(IPD_ID ipd_id, char *ipd_name);
int InfoGraphIPD_numEdges(InfoGraphIPD *ipd);
InfoGraphEdge *InfoGraphIPD_nthEdge(InfoGraphIPD *ipd, int n);

void InfoGraphIPD_addEdge(InfoGraphIPD *source, InfoGraphIPD *dest);

InfoGraphEdge *InfoGraphEdge_new(InfoGraphIPD *target);

InfoGraph *InfoGraph_new(void) {
  InfoGraph *ig = malloc(sizeof(*ig));
  PointerVector_init(&ig->ipds, 100, 0);
  return ig;
}

void InfoGraph_addIPD(InfoGraph *graph, InfoGraphIPD *ipd) {
  if(InfoGraph_findIPD(graph, ipd->id) != NULL) {
    printf("InfoGraph_addIPD: node already added\n");
  } else {
    PointerVector_append(&graph->ipds, ipd);
  }
}

int InfoGraph_numIPDs(InfoGraph *graph) {
  return PointerVector_len(&graph->ipds);
}

InfoGraphIPD *InfoGraph_findIPD(InfoGraph *graph, int ipd_id) {
  int i;
  int found = 0;
  InfoGraphIPD *cand = NULL;

  for(i=0; i < PointerVector_len(&graph->ipds); i++) {
    cand = (InfoGraphIPD *)PointerVector_nth(&graph->ipds, i);
    if(cand->id == ipd_id) {
      found = 1;
      break;
    }
  }
  if(found) {
    return cand;
  } else {
    return NULL;
  }
}

InfoGraphIPD *InfoGraph_nthIPD(InfoGraph *graph, int n) {
  return (InfoGraphIPD *)PointerVector_nth(&graph->ipds, n);
}

void InfoGraph_clearMarks(InfoGraph *graph) {
  int i;
  for(i=0; i < InfoGraph_numIPDs(graph); i++) {
    InfoGraphIPD *ipd = InfoGraph_nthIPD(graph, i);
    ipd->marks = 0;
  }
}

InfoGraphIPD *InfoGraphIPD_new(IPD_ID ipd_id, char *ipd_name) {
  InfoGraphIPD *rv = malloc(sizeof(*rv));
  rv->id = ipd_id;
  rv->ipd_name = strdup(ipd_name);
  rv->annotation = NONE;
  rv->marks = 0;
  PointerVector_init(&rv->edges, 100, 0);
  return rv;
}

int InfoGraphIPD_numEdges(InfoGraphIPD *ipd) {
  return PointerVector_len(&ipd->edges);
}

InfoGraphEdge *InfoGraphIPD_nthEdge(InfoGraphIPD *ipd, int n) {
  return (InfoGraphEdge *)PointerVector_nth(&ipd->edges, n);
}

void InfoGraphIPD_addEdge(InfoGraphIPD *source, InfoGraphIPD *dest) {
  int i;
  for(i=0; i < InfoGraphIPD_numEdges(source); i++) {
    InfoGraphEdge *edge = InfoGraphIPD_nthEdge(source, i);
    if(edge->target == dest) {
      printf("addedge: target already in edge list\n");
      return;
    }
  }
  PointerVector_append(&source->edges, InfoGraphEdge_new(dest));
}

InfoGraphEdge *InfoGraphEdge_new(InfoGraphIPD *target) {
  InfoGraphEdge *rv = malloc(sizeof(*rv));
  rv->target = target;
  return rv;
}

int Check_Access(int channel_num, IPD_ID ipd) {
  return 1;
}

void InfoGraph_toDot(InfoGraph *graph, StringBuffer *sb) {
  SB_cat(sb, "graph AbstractInfoGraph {\n");
  char dest_buf[512];
  int i;
  for(i=0; i < InfoGraph_numIPDs(graph); i++) {
    InfoGraphIPD *ipd = InfoGraph_nthIPD(graph, i);

    char stylebuf[80] = "";
    switch(ipd->annotation) {
    case SOURCE:
      strcpy(stylebuf, " fillcolor=\"red\" style=filled ");
      break;
    case DESTINATION:
      strcpy(stylebuf, " fillcolor=\"blue\" style=filled ");
      break;
    case NONE:
      break;
    default:
      printf("todot: unsupported annotation\n");
    }

    sprintf(dest_buf, " ipd%d [label=\"%s\" %s];\n", ipd->id, ipd->ipd_name, stylebuf);
    SB_cat(sb, dest_buf);
  }
  SB_cat(sb, "\n");

  struct Pair {
    IPD_ID src, dst;
  };
  struct HashTable *dups = hash_new(100, sizeof(struct Pair));

  for(i=0; i < InfoGraph_numIPDs(graph); i++) {
    InfoGraphIPD *ipd = InfoGraph_nthIPD(graph, i);
    int j;
    for(j=0; j < InfoGraphIPD_numEdges(ipd); j++) {
      int src_ipd = ipd->id;
      int target_ipd = InfoGraphIPD_nthEdge(ipd, j)->target->id;
      struct Pair pair0 = {
	.src = src_ipd,
	.dst = target_ipd,
      };
      struct Pair pair1 = {
	.src = target_ipd,
	.dst = src_ipd,
      };
      if(hash_findItem(dups, &pair0) != NULL ||
	 hash_findItem(dups, &pair1) != NULL) {
	// printf("Dup!");
	continue;
      }
      hash_insert(dups, &pair0, (void *)1);
      hash_insert(dups, &pair1, (void *)1);
      sprintf(dest_buf, "ipd%d -- ipd%d;\n", src_ipd, target_ipd);
      SB_cat(sb, dest_buf);
    }
  }
  hash_destroy(dups);

  SB_cat(sb, "\n");
  SB_cat(sb, "}\n");
}

int InfoGraph_searchHelper(InfoGraphIPD *ipd, int dst_id) {
  int i;
  if(ipd->id == dst_id) return 1; // found
  if(ipd->marks) { // stop recursion
    return 0;
  }
  ipd->marks = 1;

  for(i=0; i < InfoGraphIPD_numEdges(ipd); i++) {
    InfoGraphIPD *target = InfoGraphIPD_nthEdge(ipd, i)->target;
    if(InfoGraph_searchHelper(target, dst_id)) {
      return 1;
    }
  }
  // nothing found
  return 0;
}

int InfoGraph_canReach(InfoGraph *graph, int src_id, int dst_id) {
  InfoGraph_clearMarks(graph);
  InfoGraphIPD *ipd = InfoGraph_findIPD(graph, src_id);
  if(ipd == NULL) {
    printf("Could not find source id!\n");
    return 0;
  }
  assert(ipd->id == src_id);
  return InfoGraph_searchHelper(ipd, dst_id);
}

InfoGraph *simulateInfoGraph(IPCGraph *graph) {
  InfoGraph *info_graph =  InfoGraph_new();
  int i;
  for(i=0; i < IPCGraph_numIPDs(graph); i++) {
    IPCGraphIPD *ipd = IPCGraph_nthIPD(graph, i);
    InfoGraphIPD *info_ipd = InfoGraphIPD_new(ipd->id, ipd->ipd_name);
    InfoGraph_addIPD(info_graph, info_ipd);
  }
  for(i=0; i < IPCGraph_numIPDs(graph); i++) {
    IPCGraphIPD *ipd = IPCGraph_nthIPD(graph, i);
    InfoGraphIPD *info_ipd = InfoGraph_nthIPD(info_graph, i);
    assert(ipd->id == info_ipd->id);
    int j;
    for(j=0; j < IPCGraphIPD_numEdges(ipd); j++) {
      IPCGraphEdge *edge = IPCGraphIPD_nthEdge(ipd, j);
      if(Check_Access(edge->target_channel->channel_num, ipd->id)) {
	// printf("!");
	// generate forward and back edge
	InfoGraphIPD *target_owner_ipd =
	  InfoGraph_findIPD(info_graph, edge->target_channel->owner->id);

	InfoGraphIPD_addEdge(info_ipd, target_owner_ipd);
	InfoGraphIPD_addEdge(target_owner_ipd, info_ipd);
      }
    }
  }
  return info_graph;
}

int main(int argc, char **argv) {
  all_opens = StringBuffer_new(1024);
  if(argc < 2) {
  arg_error:
    printf("cantalk: <sourceipd_num>,<destipd_num>\n");
    return -1;
  }
  printf("Warning: CanTalk is vulnerable at least to the following race conditions:\n"
	 "Permtable changing during scan\n"
	 "Permtable changing after scan\n");

  char *src_name = argv[1];
  char *finger;
  int found_dest = 0;
  char *dest_name = NULL;
  for(finger = argv[1]; *finger != '\0'; finger++) {
    if(*finger == ',') {
      *finger = '\0';
      dest_name = finger + 1;
      found_dest = 1;
      break;
    }
  }
  if(!found_dest) {
    goto arg_error;
  }
  printf("CanTalk %s=>%s\n", src_name, dest_name);
  int num_errors;
  IPCGraph *graph = buildIPCGraph(&num_errors);
  printf("built graph\n");
  if(num_errors > 0) {
    printf("%d errors, not generating output!\n", num_errors);
    return -1;
  }

  int src_id = atoi(src_name);
  int dst_id = atoi(dest_name);
  printf("src_id = %d, dst_id = %d\n", src_id, dst_id);

#if 1
  StringBuffer *output = StringBuffer_new(1024);
  printf("simulating info graph\n");
  InfoGraph *info_graph = simulateInfoGraph(graph);
  printf("info graph => dot\n");

  {
    InfoGraphIPD *src_ipd = InfoGraph_findIPD(info_graph, src_id);
    if(src_ipd != NULL) {
      src_ipd->annotation = SOURCE;
    } else {
      printf("could not find src ipd %d\n", src_id);
    }
    PING();
    InfoGraphIPD *dst_ipd = InfoGraph_findIPD(info_graph, dst_id);
    if(dst_ipd != NULL) {
      dst_ipd->annotation = DESTINATION;
    } else {
      printf("could not find dst ipd %d\n", dst_id);
    }
  }

  InfoGraph_toDot(info_graph, output);
  writefile("cantalk-info.dot", SB_c_str(output), strlen(SB_c_str(output)));

  printf("CanReach(%d,%d) = %d\n", src_id, dst_id,
	 InfoGraph_canReach(info_graph, src_id, dst_id));
#endif


#if 1
  // code to write output
  IPCGraphIPD *src_ipd = IPCGraph_findIPD(graph, src_id);
  if(src_ipd != NULL) {
    src_ipd->annotation = SOURCE;
  } else {
    printf("could not find src ipd %d\n", src_id);
  }
PING();
  IPCGraphIPD *dst_ipd = IPCGraph_findIPD(graph, dst_id);
  if(dst_ipd != NULL) {
    dst_ipd->annotation = DESTINATION;
  } else {
    printf("could not find dst ipd %d\n", dst_id);
  }

    StringBuffer *output1 = StringBuffer_new(1024);
PING();
  IPCGraph_toDot(graph, output1);
PING();
// printf("output (%d): \n%s\n", strlen(SB_c_str(output)), SB_c_str(output));
 writefile("cantalk.dot", SB_c_str(output1), strlen(SB_c_str(output1)));
PING();
#endif
  return 0;
}
