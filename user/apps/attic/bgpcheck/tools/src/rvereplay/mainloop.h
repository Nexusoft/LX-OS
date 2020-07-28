#ifndef MAINLOOP_H
#define MAINLOOP_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { IO_READ=1, IO_WRITE=2, IO_EXCEPTION=4 } IOCondition;
typedef void IOCallback(int fd, IOCondition condition, void *data);
typedef void TimerCallback(void *data);

int mainloop_add_input(int fd, IOCondition condition, IOCallback *cb,
		void *data);
void mainloop_remove_input(int handle);
void mainloop_change_input(int handle, IOCondition condition);
int mainloop_add_timer(int ms, TimerCallback *cb, void *data);
void mainloop_remove_timer(int handle);
void mainloop_run();
void mainloop_quit();

#ifdef __cplusplus
}
#endif

#endif
