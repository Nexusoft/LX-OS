/** NexusOS: link in common structures whose implementations live in common */

#include <nexus/defs.h>
#include <asm/types.h>

#include <nexus/util.h>
#include <nexus/debug.h>
#include <nexus/queue.h>
#include <nexus/hashtable.h>                                                    
#include <nexus/bitmap.h>                                                       
#include <nexus/vector.h>                                                       
#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#include <nexus/ipd.h>
#include <nexus/user_compat.h>

#include <common/code/util-code.c>                                                  
#include <common/code/queue-code.c>                                                  
#include <common/code/hashtable-code.c>                                             
#include <common/code/bitmap-code.c>                                                
#include <common/code/vector-code.c>                                                
