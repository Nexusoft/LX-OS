#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "containers.h"
#include "mainloop.h"
#include "timeval.h"

typedef struct _Input Input;
struct _Input {
	int handle, fd;
	IOCondition condition;
	IOCallback *cb;
	void *data;
	gboolean removed;
};

typedef struct _Timer Timer;
struct _Timer {
	int handle, ms;
	struct timeval next;
	TimerCallback *cb;
	void *data;
	gboolean removed;
};

static GArray *inputs = NULL, *timers = NULL;

static void mainloop_iter(void);
static gboolean timers_need_cleanup = FALSE, inputs_need_cleanup = FALSE;
static void timers_cleanup(void);
static void inputs_cleanup(void);

int mainloop_add_input(int fd, IOCondition condition, IOCallback *cb,
		void *data) {
	static int handle = 1;
	Input inp;
	g_return_val_if_fail(condition & (IO_READ|IO_WRITE|IO_EXCEPTION), -1);
	g_return_val_if_fail((condition & ~(IO_READ|IO_WRITE|IO_EXCEPTION))==0, -1);
	g_return_val_if_fail(fd >= 0, -1);
	g_return_val_if_fail(cb != NULL, -1);
	if (!inputs)
		inputs = g_array_new(FALSE, FALSE, sizeof(Input));

	inp.handle = handle;
	inp.fd = fd;
	inp.condition = condition;
	inp.cb = cb;
	inp.data = data;
	inp.removed = FALSE;
	g_array_append_val(inputs, inp);

	return handle++;
}

void mainloop_remove_input(int handle) {
	unsigned int i;
	g_return_if_fail(inputs);
	for (i=0; i<inputs->len; i++)
		if (g_array_index(inputs, Input, i).handle == handle) {
			g_array_index(inputs, Input, i).removed = TRUE;
			inputs_need_cleanup = TRUE;
			return;
		}
	g_warning("Attempted to remove nonexistent input %d", handle);
}

void mainloop_change_input(int handle, IOCondition condition) {
	unsigned int i;
	g_return_if_fail(inputs);
	for (i=0; i<inputs->len; i++)
		if (g_array_index(inputs, Input, i).handle == handle) {
			g_array_index(inputs, Input, i).condition = condition;
			return;
		}
	g_warning("Attempted to change nonexistent input %d", handle);
}

int mainloop_add_timer(int ms, TimerCallback *cb, void *data) {
	static int handle = 1;
	Timer tim;

	g_return_val_if_fail(ms >= 0, -1);
	g_return_val_if_fail(cb != NULL, -1);

	gettimeofday(&tim.next, NULL);

	if (!timers)
		timers = g_array_new(FALSE, FALSE, sizeof(Timer));

	tim.handle = handle;
	tim.ms = ms;
	timeval_add_usec(&tim.next, ms*1000);
	tim.cb = cb;
	tim.data = data;
	tim.removed = FALSE;
	g_array_append_val(timers, tim);

	return handle++;
}

void mainloop_remove_timer(int handle) {
	unsigned int i;
	g_return_if_fail(timers);
	for (i=0; i<timers->len; i++)
		if (g_array_index(timers, Timer, i).handle == handle) {
			g_array_index(timers, Timer, i).removed = TRUE;
			timers_need_cleanup = TRUE;
			return;
		}
	g_warning("Attempted to remove nonexistent timer %d", handle);
}

static gboolean quit = FALSE;

void mainloop_run() {
	while (!quit)
		mainloop_iter();
	quit = FALSE;
}

void mainloop_quit() {
	quit = TRUE;
}

static void mainloop_iter() {
	struct timeval delay;
	fd_set rfds, wfds, efds;
	int maxfd=-1, res, timer_id = -1;
	unsigned int i, inputs_len;
	gboolean r_flag = FALSE, w_flag = FALSE, e_flag = FALSE, t_flag = FALSE;

	/* timers come first, in case the timer callbacks mess with the inputs
	 * list */
	timers_cleanup();
	if (timers && timers->len > 0) {
		struct timeval now;
		int soonest = 0x7FFFFFFF;
		gettimeofday(&now, NULL);
		for (i=0; i<timers->len; i++) {
			int diff;
			Timer *tim = &g_array_index(timers, Timer, i);
			diff = timeval_diff(&tim->next, &now);
			while (diff <= 0 && !tim->removed) {
				tim->cb(tim->data);
				timeval_add_usec(&tim->next, tim->ms*1000);
				diff += 1000*tim->ms;
			}
			if (!tim->removed && diff < soonest) {
				soonest = diff;
				timer_id = i;
			}
		}
		timers_cleanup();
		if (timers->len > 0) {
			timeval_set(&delay, soonest);
			t_flag = TRUE;
		}
	}

	inputs_cleanup();
	if (inputs && inputs->len > 0) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&efds);
		for (i=0; i<inputs->len; i++) {
			gboolean handled = FALSE;
			Input *inp = &g_array_index(inputs, Input, i);
			if (inp->fd > maxfd) maxfd = inp->fd;
			if (inp->condition & IO_READ) {
				FD_SET(inp->fd, &rfds);
				handled = r_flag = TRUE;
			}
			if (inp->condition & IO_WRITE) {
				FD_SET(inp->fd, &wfds);
				handled = w_flag = TRUE;
			}
			if (inp->condition & IO_EXCEPTION) {
				FD_SET(inp->fd, &efds);
				handled = e_flag = TRUE;
			}
			g_assert(handled);
		}
	}

	res = select(maxfd+1, r_flag?&rfds:NULL, w_flag?&wfds:NULL,
		e_flag?&efds:NULL, t_flag?&delay:NULL);
	if (res == -1) {
		if (errno != EINTR) {
			perror("select");
			abort();
		}
		return;
	}
	if (res == 0) {
		Timer *tim;
		g_assert(timers);
		g_assert(t_flag);
		g_assert(timers->len > 0);
		g_assert(timer_id != -1);
		tim = &g_array_index(timers, Timer, timer_id);
		tim->cb(tim->data);
		timeval_add_usec(&tim->next, tim->ms*1000);
		return;
	}

	g_assert(inputs);
	/* Grab a static copy of this.  If new inputs are added, it will change,
	 * and we won't want to look at the new inputs during this pass. */
	inputs_len = inputs->len;
	for (i=0; i<inputs_len; i++) {
		Input *inp;
		inp = &g_array_index(inputs, Input, i);
		if ((inp->condition & IO_READ) && FD_ISSET(inp->fd, &rfds)) {
			inp->cb(inp->fd, IO_READ, inp->data);
			/* set 'inp' again in case array has changed */
			inp = &g_array_index(inputs, Input, i);
			res--;
		}
		if ((inp->condition & IO_WRITE) && FD_ISSET(inp->fd, &wfds)) {
			res--;
			if (!inp->removed) {
				inp->cb(inp->fd, IO_WRITE, inp->data);
				/* set 'inp' again in case array has changed */
				inp = &g_array_index(inputs, Input, i);
			}
		}
		if ((inp->condition & IO_EXCEPTION) && FD_ISSET(inp->fd, &efds)) {
			res--;
			if (!inp->removed)
				inp->cb(inp->fd, IO_EXCEPTION, inp->data);
		}
	}
	if (res != 0) fprintf(stderr, "res=%d\n", res);
	g_assert(res == 0);
}

static void timers_cleanup(void) {
	unsigned int i;
	if (!timers_need_cleanup) return;
	for (i=0; i<timers->len; )
		if (g_array_index(timers, Timer, i).removed)
			g_array_remove_index_fast(timers, i);
		else
			i++;
	timers_need_cleanup = FALSE;
}

static void inputs_cleanup(void) {
	unsigned int i;
	if (!inputs_need_cleanup) return;
	for (i=0; i<inputs->len; )
		if (g_array_index(inputs, Input, i).removed)
			g_array_remove_index_fast(inputs, i);
		else
			i++;
	inputs_need_cleanup = FALSE;
}
