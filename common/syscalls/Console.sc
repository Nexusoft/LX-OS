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
		includefiles { "<nexus/mousedev.h>" }
		includefiles { "<nexus/thread-inline.h>" }
		
	}

	interface int Blit_Init(void) {
		NexusDevice *nd;
		NexusOpenDevice *nod;
		IPD *ipd;
		int first_screen, handle;
		
		ipd = nexusthread_current_ipd();
		if (ipd->quiet) // no output
			return INVALID_HANDLE;

		first_screen = !ipd_get_open_device(ipd, DEVICE_VIDEO, -1);
		nd = find_device(DEVICE_VIDEO, NULL);
		if (!nd) 
			return INVALID_HANDLE;

		nod = screen_init(nd, ipd);
		handle = ipd_add_open_device(ipd, nod);

		if (first_screen) {
			add_focus(ipd);
			if (!ipd->background)
				focus(ipd);
		}
		return handle;
	}

	interface void PrintChar(int handle, char c) {
		IPD *ipd = nexusthread_current_ipd();

		// special case: log quiet processes to kernel log
		if (ipd->quiet) {
			nxcompat_printf("[process %d] %c\n", ipd->id, c);
			return;
		}

		if (!Handle_Valid(handle))
			return;


		NexusOpenDevice *nod = ipd_get_open_device(ipd, DEVICE_VIDEO, handle);
		if (!nod)
			return;

		if (c == '\b')
		  print_backspace(ipd);
		else
		  screen_putc(nod, c, WHITE);
	}
	
	interface int PrintString(int handle, const char *data, int dlen) {
		IPD *ipd = nexusthread_current_ipd();

		// special case: log quiet processes to kernel log
		if (ipd->quiet) {
			nxcompat_printf("[process %d] %s", ipd->id, data);
			return dlen;
		}

		if (!Handle_Valid(handle))
			return -SC_ACCESSERROR;

		NexusOpenDevice *nod = ipd_get_open_device(ipd, DEVICE_VIDEO, handle);
		if (!nod)
			return -SC_NOTFOUND;
	

		screen_print(nod, data, dlen);
		return dlen;
	}

	// 24 bit blit frame
	interface int Blit_Frame(int handle, void *blt_source, unsigned int width, unsigned int height) {
		IPD *ipd = nexusthread_current_ipd();
		
		if (!Handle_Valid(handle))
			return -SC_INVALID;

		unsigned int size = width*3 * height;
		NexusOpenDevice *nod = ipd_get_open_device(ipd, DEVICE_VIDEO, handle);
		if (!nod) return -1; // XXX better error needed
		unsigned char *data = galloc(size);
		if (!data) return -SC_NOMEM;

		if (peek_user(nexusthread_current_map(), (__u32)blt_source, data, size) != 0) {
			gfree(data);
			printk_red("blit_frame: access error\n");
			return -SC_ACCESSERROR;
		}

		//screen_notext(nod); // disable all text
		int ret = screen_blit(nod, width, height, data);
		gfree(data);
		return ret;
	}

	// Blit frame in the native bit depth. Length is for benefit
	// of Linux kernel's page locking before invoking the Nexus
	// hypercall
	interface int Blit_Frame_Native(int handle, void *blt_source, unsigned int width, unsigned int height, int len) {
		IPD *ipd = nexusthread_current_ipd();
		
		if (!Handle_Valid(handle))
			return -SC_INVALID;

		NexusOpenDevice *nod = ipd_get_open_device(ipd, DEVICE_VIDEO, handle);
		if (!nod) return -1; // XXX better error needed
		struct FB_Info info;
		int bdepth;
		if(screen_get_geometry(nod, &info) != 0) {
			// This is supposed to succeed
			printk_red("Could not get screen geometry for Blit_Frame_Native\n");
			return -SC_INVALID;
		}
		if(info.bpp % 8 != 0) {
			printk_red("BPP is not an even multiple of 8!\n");
			return -SC_INVALID;
		}
		bdepth = info.bpp / 8;
		unsigned int size = width * height * bdepth;
		if(size != len) {
			printk_red("blit native length mismatch!\n");
			return -SC_INVALID;
		}
		unsigned char *data = galloc(size);
		if (!data) return -SC_NOMEM;

		if (peek_user(nexusthread_current_map(), (__u32)blt_source, data, size) != 0) {
			gfree(data);
			printk_red("blit_frame: access error\n");
			return -SC_ACCESSERROR;
		}
		// printk_red("Blit (%d,%d)=%d [%d]\n", width, height, size, bdepth);

		//screen_notext(nod); // disable all text
		int ret = screen_blit_native(nod, width, height, data);
		gfree(data);
		return ret;
	}

	interface int SetPrintState(int handle, int new_state) {
		IPD *ipd = nexusthread_current_ipd();
		
		if (!Handle_Valid(handle))
			return -SC_ACCESSERROR;

		NexusOpenDevice *nod = ipd_get_open_device(ipd, DEVICE_VIDEO, handle);
		if (!nod) return -1; // XXX better error needed
		screen_set_print_state(nod, new_state);
		return 0;
	}


	interface int GetKeymapEntry(int table, int entry) {
		return kbd_drv_keymap_get_entry(table, entry);
	}

	interface int Kbd_Init(void) {
		IPD *ipd = nexusthread_current_ipd();
		
		if (ipd->quiet)
			return INVALID_HANDLE;

		NexusDevice *nd = find_device(DEVICE_KEYBOARD, NULL);
		if (!nd) return 0;
		NexusOpenDevice *nod = kbd_new(nd, ipd);
		return ipd_add_open_device(ipd, nod);
	}

	interface int GetData(int handle, __output__ struct VarLen data, int max_size) {
		NexusOpenDevice *nod;
		IPD *ipd;
		char *buf;
		int linesize;
		int rv = -1;

		ipd = nexusthread_current_ipd();
		
		if (!Handle_Valid(handle))
			return -SC_INVALID;

		if (max_size <= 0) // sanity check arguments
			return -SC_INVALID;

		nod = ipd_get_open_device(nexusthread_current_ipd(), 
					  DEVICE_KEYBOARD, handle);
		if (!nod)
			return -SC_NOPERM;

		buf = galloc(max_size);
		linesize = max_size;
		kbd_getdata(nod, &linesize, buf);

		if(IPC_TransferTo(call_handle, data.desc_num, 
				  (unsigned int) data.data, buf, linesize) != 0) {
		  	printk("Error: Console GetData transfer error\n");
			rv = -SC_ACCESSERROR;
			goto out;
		}
		rv = linesize;
	out:
		gfree(buf);
		return rv;
	}

	interface int HasLine(int handle) {
		NexusOpenDevice *nod;
		IPD *ipd;

		ipd = nexusthread_current_ipd();
		
		if (!Handle_Valid(handle))
			return -SC_INVALID;

		nod = ipd_get_open_device(nexusthread_current_ipd(), 
					  DEVICE_KEYBOARD, handle);
		if (!nod)
			return -SC_NOPERM;

		return kbd_hasline(nod);
	}

	interface int SetInputMode(int handle, enum KbdMode new_mode) {
		NexusOpenDevice *nod;
		IPD *ipd;

		ipd = nexusthread_current_ipd();
		
		if (!Handle_Valid(handle))
			return -SC_INVALID;
	       
		nod = ipd_get_open_device(nexusthread_current_ipd(), 
					  DEVICE_KEYBOARD, handle);
		if (!nod)
			return -SC_NOPERM;

		if (kbd_setmode(nod, new_mode))
			return -SC_INVALID;
		
		return 0;
	}

	// Map in a frame buffer, excluding the Nexus-specific parts
	// Currently, this only returns the screen geometry and color weight
	// If hint is NULL, don't map in the frame buffer
	interface int MapFrameBuffer(int handle, void *hint /* in, must be 4 MB aligned */, 
				     struct FB_Info *info_ptr /* out */ ) {
		IPD *ipd = nexusthread_current_ipd();
		
		if (!Handle_Valid(handle))
			return -SC_INVALID;

		int is_xen = ipd_isXen(ipd);
		NexusOpenDevice *nod = 
			ipd_get_open_device(ipd, DEVICE_VIDEO, handle);
		if (!nod) {
			printk_red("could not look up frame buffer\n");
			return -SC_INVALID;
		}
		if(PTAB_OFFSET((__u32)hint) != 0) {
			printk_red("Hint is not 4MB aligned!\n");
			return -SC_INVALID;
		}

		Map *m = nexusthread_current_map();
		struct FB_Info info;
		screen_get_geometry(nod, &info);
		char *dev_data = info.fb;
		info.fb = NULL;

		if(hint == NULL) {
			// Don't map in the frame buffer
		} else {
			// Compute the length of the area to map in
			assert( (((__u32) info.fb) & PAGE_OFFSET_MASK) == 0);
			assert(info.bpp % 8 == 0);
			int fb_length = info.yres * info.line_length;
			int real_skip = 
				(info.skip_ylength * info.line_length + PAGE_SIZE - 1) /
				PAGE_SIZE * PAGE_SIZE;
			int y_adj = (real_skip + info.line_length - 1) /
				info.line_length;
			int fb_offset = y_adj * info.line_length - real_skip; // amount to add to mapped frame buffer to reach beginning of first line
			int map_length = fb_length - real_skip;
			printk_red("Orig fb length %d, map length %d, adjusted "
				   "y-geometry by %d,"
				   "real skip %d,%d\n",
				   fb_length, map_length, y_adj,
				   real_skip, info.skip_ylength);

			// Allocate virtual memory area & shadow pages for IPD
			// to write into when it doesn't have focus
			int i;
			int num_map_pages = (map_length + PAGE_SIZE - 1) / 
				PAGE_SIZE;
			printk_red("%d pages to map\n", num_map_pages);
			assert(num_map_pages <= FB_MAX_LEN);

			if(is_xen) {
				// Guest needs to have mapped in the
				// page tables

				// Need to do this Xen-specific check
				// for every new address space that
				// maps in FB.

				for(i=0; i < num_map_pages; i++) {
					// XXX this code could be slightly faster
					Page *ptab = Map_getPagetable(m, (__u32)hint + i * PAGE_SIZE);
					if(ptab == NULL) {
						printk_red("Xen guest is responsible for making sure page tables are present!\n");
						return -SC_INVALID;
					}
					// is_mapped is used to catch MMU updates
					ptab->u.fb.is_mapped = 1;
				}
			}

			if(!ipd_hasMappedFB(ipd)) {
				// XXX The error handling here might leak memory
				__u32 vaddr = map_page(m, ipd, num_map_pages, 1, 1, 0, 0,
						       (__u32)hint, 1);
				if((void *)vaddr != hint) {
					printk_red("fb mapped region does not match hint!\n");
					unmap_pages(m, vaddr, num_map_pages);
					return -SC_INVALID;
				}

				ipd->fb.shadow = galloc(num_map_pages * sizeof(__u32));
				ipd->fb.data = dev_data + real_skip;
				assert( ((__u32)ipd->fb.data & PAGE_OFFSET_MASK) == 0 );
				ipd->fb.length = map_length;
				for(i=0; i < num_map_pages; i++) {
					ipd->fb.shadow[i] = 
						fast_virtToPhys_nocheck(m, vaddr + i * PAGE_SIZE);
				}
			} else {
				printk_red("Second frame buffer mapping\n");
				assert(ipd->fb.data == dev_data + real_skip);
				assert(ipd->fb.length == map_length);
				// This is not the first time a frame buffer
				// has been mapped into this IPD

				// Make sure address range is not present. Map_activate()
				// will handle mapping in these pages
				for(i=0; i < num_map_pages; i++) {
					__u32 v = (__u32)hint + i * PAGE_SIZE;
					Mem_mutex_lock();
					PageTableEntry *pte = Map_getPTE(m, v);
					if(pte != NULL) {
						if(!PageTableEntry_checkAvailable(pte)) {
							printk_red("pte at %p already present\n", (void *)v);
							return -SC_INVALID;
						}
						PageTableEntry_makeUnpresentButProtected(pte);
						pte->pagebase = 0;
						Mem_mutex_unlock();
					} else {
						// Xen page table should already be present
						assert(!is_xen);
						// Allocate a PageTable
						Mem_mutex_unlock();
						__u32 v1 = map_page(m, ipd, 1, 0, 0, 0, 0, v, 0);
						if(v != v1) {
							printk_red("Error allocating PageTable\n");
							Mem_mutex_lock();
							unmap_pages(m, v1, 1);
							Mem_mutex_unlock();
							return -SC_INVALID;
						}

						Mem_mutex_lock();
						unmap_pages(m, v, 1);
						pte = Map_getPTE(m, v);
						PageTableEntry_makeUnpresentButProtected(pte);
						assert(pte != NULL);
						Mem_mutex_unlock();
					}
				}
			}

			info.fb = (char *)hint + fb_offset;
			printk_red(" hint=%p, adj_vaddr=%p ", hint, info.fb);
			info.skip_ylength = y_adj;
			info.yres -= y_adj;

			Page *root = Map_getRoot(m);
			root->u.fb.pdoffset = PDIR_OFFSET((__u32)hint);
			root->u.fb.is_mapped = 0;

			// Initialize user framebuffer
			int intlevel = disable_intr(); // prevent context / map switch
			int focused = is_focused(ipd);

			ipd_fb_remap(ipd, root, 
				     focused ? FB_MAP_VIDEO : FB_MAP_MEM);

			printk_red("remap0 done of root %p (focused = %d)", 
				   root, focused);
			restore_intr(intlevel);
		}

		int rv = poke_user(m, (__u32) info_ptr, &info, sizeof(info));
		if(rv != 0) {
			printk_red("error writing fb info to target, rolling back\n");
			return -SC_ACCESSERROR;
		}

		return 0;
	}

	// Unmap the frame buffer from the:
	// 	current (!Xen, or pdbr_mfn == 0)
	// 	or specified PDBR
	// The IPD resources, shared between different PDBRs, are not freed
	interface int UnmapFrameBuffer(int handle, unsigned int pdbr_mfn) {
		Page *pdbr;
		IPD *ipd = nexusthread_current_ipd();
		
		if (!Handle_Valid(handle))
			return -SC_INVALID;

		// Default: use current
		pdbr = Map_getRoot(nexusthread_current_map());

		if(ipd_isXen(ipd) && pdbr_mfn != 0) {
			pdbr = Page_Xen_fromMFN_checked(pdbr_mfn);
			if(pdbr == NULL) {
				printk_red("unmap frame buffer bad pdbr mfn\n");
				return -SC_INVALID;
			}
#ifdef __NEXUSXEN__
			if(pdbr->type == FT_RDWR) {
				// Guest OS has already unpinned this
				// type from FT_DIRECTORY
				return 0;
			}
			if( pdbr->type != FT_PDIRECTORY ) {
				printk_red("pdbr type of %p is not page directory (%d)!\n", pdbr, pdbr->type);
				return -SC_INVALID;
			}
#endif
			if(PDBR_hasFramebuffer(pdbr)) {
				printk_red("unmap called on pdbr without "
					   "fb map\n");
				return -SC_INVALID;
			}
		}

		return ipd_fb_unmap(ipd, pdbr);
	}

	interface int Mouse_Init(void) {
		IPD *ipd = nexusthread_current_ipd();
		
		if (ipd->quiet)
			return INVALID_HANDLE;

		NexusDevice *nd = find_device(DEVICE_MOUSE, NULL);
		if (!nd) return 0;
		NexusOpenDevice *nod = mouse_new(nd, ipd);
		return ipd_add_open_device(ipd, nod);
	}
	interface int Mouse_SetProtocol(int handle, enum MouseProto protocol) {
		printk_red("Mouse_SetProtocol() could break synchronization; context switch between different protocols in different IPDs is not implemented!\n");
#define LOOKUP_MOUSE()							\
		IPD *ipd = nexusthread_current_ipd();			\
		if (!Handle_Valid(handle))				\
			return -SC_INVALID;				\
		NexusOpenDevice *nod =					\
			ipd_get_open_device(ipd, DEVICE_MOUSE, handle);	\
		if (!nod) {						\
			printk_red("%s: could not look up mouse\n",	\
				   __FUNCTION__);			\
			return -SC_INVALID;				\
		}

		LOOKUP_MOUSE();
		return mouse_setProtocol(nod, protocol);
	}
	interface int Mouse_Poll(int handle) {
		LOOKUP_MOUSE();
		return mouse_poll(nod);
	}
	// returns the number of events. Nonblocking
	interface int Mouse_Read(int handle,
			 struct MouseEvent *dest, int max_num_events) {
		LOOKUP_MOUSE();
		return mouse_read(nod, dest, max_num_events);
	}
}

