/****************************************************************************/
/*                                                                          */
/*                           buildbuff utility                              */
/*                                                                          */
/* This file is copyright 2003 IBM. See "License" for details               */
/****************************************************************************/

/****************************************************************************/
/*                                                                          */
/*  This routine takes a format string, sort of analogous to sprintf,       */
/*  a buffer, and a variable number of arguments, and copies the arguments  */
/*  and data from the format string into the buffer, based on the characters*/
/*  in the format string.                                                   */
/*                                                                          */
/*  The routine returns a negative value if it detects an error in the      */
/*  format string, or a positive value containing the total length          */
/*  of the data copied to the buffer.                                       */
/*                                                                          */
/*  The legal characters in the format string are...                        */
/*                                                                          */
/*  0123456789abcdefABCDEF                                                  */
/*     These are used to insert bytes directly into the buffer, represented */
/*     in the format string as hex ascii.  These MUST be in pairs,          */
/*     representing the two hex nibbles in a byte. e.g. C3 would insert     */
/*     a byte containing the hex value 0xC3 next position in the buffer.    */
/*     There is no argument associated with these format characters.        */
/*                                                                          */
/*  L                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     long (32 bit) unsigned word, in NETWORK byte order (big endian)      */
/*                                                                          */
/*  S                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     short (16 bit) unsigned word, in NETWORK byte order (big endian)     */
/*                                                                          */
/*                                                                          */
/*  l                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     long (32 bit) unsigned word, in NATIVE byte order.                   */
/*                                                                          */
/*  s                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     short (16 bit) unsigned word, in NATIVE byte order.                  */
/*                                                                          */
/*  o                                                                       */
/*     This is used to insert the next argument into the buffer as a        */
/*     byte or character                                                    */
/*                                                                          */
/*  @                                                                       */
/*     This is used to insert a sequence of bytes into the buffer, based    */
/*     on the next two arguments. The first is the length of the sequence.  */
/*     The second is a pointer to the array of bytes to be inserted.        */
/*     The length is inserted into the buffer as a 32 bit big-endian        */
/*     word, preceding the array.  If the length is 0, no array is          */
/*     copied, but the length word containing zero is inserted.             */
/*                                                                          */
/*  %                                                                       */
/*     This is used to insert a sequence of bytes into the buffer, based    */
/*     on the next two arguments. The first is the length of the sequence.  */
/*     The second is a pointer to the array of bytes to be inserted.        */
/*     The length is NOT inserted into the buffer.                          */
/*                                                                          */
/*  T                                                                       */
/*     This is used to insert a 4 byte long value (32 bits, big endian)     */
/*     containing the total length of the data inserted into the buffer.    */
/*     There is no argument associated with this format character.          */
/*                                                                          */
/*                                                                          */
/*  Example                                                                 */
/*                                                                          */
/*   buildbuff("03Ts@99%",buf,10,6,"ABCDEF",3,"123");                       */
/*                                                                          */
/*   would produce a buffer containing...                                   */
/*                                                                          */
/*                                                                          */
/*   03 00 00 00 15 00 0A 00 00 00 06 41 42 43 44 45 46 99 31 32 33         */
/*                                                                          */
/*                                                                          */
/****************************************************************************/
int buildbuff(const char *format, unsigned char *buffer, ...)
{
    unsigned char *totpos;
    va_list argp;
    const char *p;
    unsigned int totlen;
    unsigned char *o;
    unsigned long l;
    unsigned short s;
    unsigned char c;
    unsigned long len;
    unsigned char byte = 0;
    unsigned char hexflag;
    unsigned char *ptr;
    int i;

    va_start(argp, buffer);
    i = 0;
    o = buffer;
    totpos = 0;
    totlen = 0;
    hexflag = 0;
    p = format;
    while (*p != '\0') {
        switch (*p) {
        case ' ':
            break;
        case 'L':
            if (hexflag)
                return -1;
            byte = 0;
            l = (unsigned long) va_arg(argp, unsigned long);
            *(uint32_t *) (o + 0) = htonl(l);
            o += 4;
            totlen += 4;
            break;
        case 'S':
            if (hexflag)
                return -1;
            byte = 0;
            s = (unsigned short) va_arg(argp, int);
            *(uint16_t *) (o + 0) = htons(s);
            o += 2;
            totlen += 2;
            break;
        case 'l':
            if (hexflag)
                return -1;
            byte = 0;
            l = (unsigned long) va_arg(argp, unsigned long);
            *(uint32_t *) (o + 0) = l;
            o += 4;
            totlen += 4;
            break;
        case 's':
            if (hexflag)
                return -1;
            byte = 0;
            s = (unsigned short) va_arg(argp, int);
            *(uint16_t *) (o + 0) = s;
            o += 2;
            totlen += 2;
            break;
        case 'o':
            if (hexflag)
                return -1;
            byte = 0;
            c = (unsigned char) va_arg(argp, int);
            *(o) = c;
            o += 1;
            totlen += 1;
            break;
        case '@':
            if (hexflag)
                return -1;
            byte = 0;
            len = (int) va_arg(argp, int);
            ptr = (unsigned char *) va_arg(argp, unsigned char *);
            if (len > 0 && ptr == NULL)
                return -3;
            *(uint32_t *) (o + 0) = htonl(len);
            o += 4;
            if (len > 0)
                memcpy(o, ptr, len);
            o += len;
            totlen += len + 4;
            break;
        case '%':
            if (hexflag)
                return -1;
            byte = 0;
            len = (int) va_arg(argp, int);
            ptr = (unsigned char *) va_arg(argp, unsigned char *);
            if (len > 0 && ptr == NULL)
                return -3;
            if (len > 0)
                memcpy(o, ptr, len);
            o += len;
            totlen += len;
            break;
        case 'T':
            if (hexflag)
                return -1;
            byte = 0;
            totpos = o;
            o += 4;
            totlen += 4;
            break;
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            byte = byte << 4;
            byte = byte | ((*p - '0') & 0x0F);
            if (hexflag) {
                *o = byte;
                ++o;
                hexflag = 0;
                totlen += 1;
            } else
                ++hexflag;
            break;
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            byte = byte << 4;
            byte = byte | (((*p - 'A') & 0x0F) + 0x0A);
            if (hexflag) {
                *o = byte;
                ++o;
                hexflag = 0;
                totlen += 1;
            } else
                ++hexflag;
            break;
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            byte = byte << 4;
            byte = byte | (((*p - 'a') & 0x0F) + 0x0A);
            if (hexflag) {
                *o = byte;
                ++o;
                hexflag = 0;
                totlen += 1;
            } else
                ++hexflag;
            break;
        default:
            return -2;
        }
        ++p;
    }
    if (totpos != 0)
        *(uint32_t *) (totpos + 0) = htonl(totlen);
    va_end(argp);
    return totlen;
}


int readbuff(const char *format, unsigned char *buffer, ...)
{
    unsigned char *totpos;
    va_list argp;
    const char *p;
    unsigned int totlen;
    unsigned char *o;
    unsigned long *l;
    unsigned short *s;
    unsigned char *c;
    unsigned long *len;
    unsigned char byte = 0;
    unsigned char hexflag;
    unsigned char *ptr;
    int i;

    va_start(argp, buffer);
    i = 0;
    o = buffer;
    totpos = 0;
    totlen = 0;
    hexflag = 0;
    p = format;

    while (*p != '\0') {
        switch (*p) {
        case ' ':
            break;
        case 'L':
            if (hexflag)
                return -1;
            byte = 0;
	    
            l = (unsigned long *) va_arg(argp, unsigned long*);
            *l = ntohl(*(uint32_t *) (o + 0));
            o += 4;
            totlen += 4;
            break;
        case 'S':
            if (hexflag)
                return -1;
            byte = 0;
            s = (unsigned short *) va_arg(argp, unsigned short*);
            *s = ntohs(*(uint16_t *) (o + 0));
            o += 2;
            totlen += 2;
            break;
        case 'l':
            if (hexflag)
                return -1;
            byte = 0;
            l = (unsigned long *) va_arg(argp, unsigned long*);
            *l = *(uint32_t *) (o + 0);
            o += 4;
            totlen += 4;
            break;
        case 's':
            if (hexflag)
                return -1;
            byte = 0;
            s = (unsigned short *) va_arg(argp, unsigned short *);
            *s = *(uint16_t *) (o + 0);
            o += 2;
            totlen += 2;
            break;
        case 'o':
            if (hexflag)
                return -1;
            byte = 0;
            c = (unsigned char*) va_arg(argp, unsigned char*);
            *c = *(o);
            o += 1;
            totlen += 1;
            break;
        case '@':
            if (hexflag)
                return -1;
            byte = 0;
            len = (unsigned long *) va_arg(argp, unsigned long *);
            ptr = (unsigned char *) va_arg(argp, unsigned char *);
            *len = ntohl(*(uint32_t *) (o + 0));
            o += 4;
            if ((*len > 0) && (ptr != NULL))
	      memcpy(ptr, o, *len);
            o += *len;
            totlen += *len + 4;
            break;
        case '%':
            if (hexflag)
                return -1;
            byte = 0;
            len = (unsigned long *) va_arg(argp, unsigned long *);
            ptr = (unsigned char *) va_arg(argp, unsigned char *);
            if ((*len > 0) && (ptr != NULL))
	      memcpy(ptr, o, *len);
            o += *len;
            totlen += *len;
            break;
        case 'T':
            if (hexflag)
                return -1;
            byte = 0;
            totpos = o;
            o += 4;
            totlen += 4;
            break;
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            byte = byte << 4;
            byte = byte | ((*p - '0') & 0x0F);
            if (hexflag) {
                *o = byte;
                ++o;
                hexflag = 0;
                totlen += 1;
            } else
                ++hexflag;
            break;
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            byte = byte << 4;
            byte = byte | (((*p - 'A') & 0x0F) + 0x0A);
            if (hexflag) {
                *o = byte;
                ++o;
                hexflag = 0;
                totlen += 1;
            } else
                ++hexflag;
            break;
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            byte = byte << 4;
            byte = byte | (((*p - 'a') & 0x0F) + 0x0A);
            if (hexflag) {
                *o = byte;
                ++o;
                hexflag = 0;
                totlen += 1;
            } else
                ++hexflag;
            break;
        default:
            return -2;
        }
        ++p;
    }
    /* total is always ingored on read */
    //if (totpos != 0)
    //  *(uint32_t *) (totpos + 0) = htonl(totlen);
    va_end(argp);
    return totlen;
}
