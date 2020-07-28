#ifndef __DJWILLDBG_H__
#define __DJWILLDBG_H__

#if defined __NEXUSKERNEL__ || defined NEXUS_UDRIVER
#define printk_info(X...) printk(X)
#else 
#define printk_info(X...) printf(X)
#endif


#define printk_djwill(X...)				\
  if(dbg){						\
    printk_info("%s:%d:", __FILE__, __LINE__);		\
    printk_info(X);					\
  }

#define printk_err(X...)				\
  if(1){						\
    printk_info("%s:%d:", __FILE__, __LINE__);		\
    printk_info(X);					\
  }

#define printf_djwill(X...) printk_djwill(X)
#define printf_err(X...) printk_err(X)

#endif
