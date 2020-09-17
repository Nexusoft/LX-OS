syscall Console {
	decls {
		includefiles { "<nexus/keyboard.h>" }
		includefiles { "<nexus/fb.h>" }
		includefiles { "<nexus/mouse.h>" }
	}
	decls __callee__ {
		includefiles { "<nexus/defs.h>" }
		includefiles { "<nexus/ipd.h>" }
		includefiles { "<nexus/device.h>" }
		includefiles { "<nexus/screen.h>" }
		includefiles { "<nexus/kbd.h>" }
		includefiles { "<nexus/handle.h>" }
		includefiles { "<nexus/screen.h>" }
		includefiles { "<nexus/thread-inline.h>" }
	}

	/** Open a new console. 
	    @return 0 on success or an errorcode */
	interface int 
	Init(void) 
	{
		// skip for quiet processes
		if (curt->ipd->quiet)
			return INVALID_HANDLE;

		curt->ipd->console = console_new_foreground(curt->ipd->name, curt->ipd->sha1, 1, 1);
		console_set(curt->ipd->console);
		return 0;
	}

	interface void
	Switch(int to_left)
	{
		if (to_left)
			console_left(NULL);
		else 
			console_right(NULL);
	}

	interface int 
	PrintString(const char *data, int dlen) 
	{
		if (curt->ipd->console)
			curt->ipd->console->out(curt->ipd->console, data, dlen);
		else	
			printk_red("[process %d] %s", curt->ipd->id, data);
		return dlen;
	}

	// 24 bit blit frame
	interface int 
	Blit_Frame(void *data, unsigned int width, unsigned int height) 
	{
		return screen_blit(curt->ipd->console, width, height, data);
	}

	/** Data available? */
	interface int 
	HasLine(void) 
	{
		return curt->ipd->console->poll(curt->ipd->console);
	}

	/** Read data */
	interface int 
	GetData(__output__ struct VarLen data, int max_size) 
	{
		// verify arguments
		if (max_size <= 0 || max_size > PAGE_SIZE) 
			return -SC_INVALID;

		return curt->ipd->console->in(curt->ipd->console, data.data, max_size);
	}

	/** Set keyboard input mode (if console has a keyboard) */
	interface int 
	SetInputMode(enum KbdMode new_mode) 
	{
		if (!curt->ipd->console->keyboard)
			return -SC_NOTFOUND;

		if (consolebuf_setmode(curt->ipd->console->keyboard, new_mode))
			return -SC_INVALID;
		
		return 0;
	}

	/** returns the number of events in nonblocking fashion */
	interface int
	Mouse_Read(struct MouseEvent *event) 
	{
		return curt->ipd->console->mouse_read(curt->ipd->console, event);
	}
}

