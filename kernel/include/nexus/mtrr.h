#ifndef _NEXUS_MTRR_H_
#define _NEXUS_MTRR_H_

#ifdef MTRR_NEED_STRINGS
static char *mtrr_strings[MTRR_NUM_TYPES] =
{
    "uncachable",               /* 0 */
    "write-combining",          /* 1 */
    "?",                        /* 2 */
    "?",                        /* 3 */
    "write-through",            /* 4 */
    "write-protect",            /* 5 */
    "write-back",               /* 6 */
};
#endif

void mtrr_dump(void);
int mtrr_add (unsigned long base, unsigned long size,
	      unsigned int type, char increment);

#endif // _NEXUS_MTRR_H_
