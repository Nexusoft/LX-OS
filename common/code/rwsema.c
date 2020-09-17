/** NexusOS: reader/writer locks. Shared by kernel and user  */

#ifdef __NEXUSKERNEL__
#define V_nexus(x) V(x)
#endif

/*  Reader for reader/writer lock: allow parallel readers,  not writers
    
    @param sw must be a mutex
    @param s is the lock that readers can use as normal
    @param parallel must be the number of allowed parallel users 
           (s's initial value)

    see http://doc.trolltech.com/qq/qq11-mutex.html for an explanation */
void 
P_writer(RWSema *s)
{
	int i;

	P(&s->writer_mutex);
	for (i = 0; i < s->max_readers; i++)
		P(&s->sema);
	V_nexus(&s->writer_mutex);
}

void 
V_writer(RWSema *s)
{
	int i;

	for (i = 0; i < s->max_readers; i++)
		V_nexus(&s->sema);
}

void 
P_reader(RWSema *s)
{
	P(&s->sema);
}

void 
V_reader(RWSema *s)
{
	V_nexus(&s->sema);
}

void 
rwsema_set(RWSema *s, int value)
{
	s->sema = SEMA_INIT;
	s->writer_mutex = SEMA_MUTEX_INIT;

	s->sema.value = value;
	s->max_readers = value;
}

RWSema * 
rwsema_new(int value)
{
	RWSema *s;

	s = nxcompat_calloc(1, sizeof(*s));
	rwsema_set(s, value);
	return s;
}

void    
rwsema_del(RWSema *s)
{
	nxcompat_free(s);
}

