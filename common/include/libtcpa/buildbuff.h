/****************************************************************************/
/*                                                                          */
/*  buildbuff.h  03 Apr 2003                                                */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/
#ifndef TCPAUTIL_H
#define TCPAUTIL_H

int buildbuff(const char *format, unsigned char *buffer, ...);
int readbuff(const char *format, unsigned char *buffer, ...);

#endif
