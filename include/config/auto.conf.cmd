deps_config := \
	/home/viz/Nexus/LLL-OS/tools/common/Kconfig \
	tools/elfloader/Kconfig \
	/home/viz/Nexus/LLL-OS/apps/nethack/Kconfig \
	/home/viz/Nexus/LLL-OS/apps/snake/Kconfig \
	/home/viz/Nexus/LLL-OS/apps/tetris/Kconfig \
	/home/viz/Nexus/LLL-OS/apps/test_user/Kconfig \
	/home/viz/Nexus/LLL-OS/apps/test_os/Kconfig \
	/home/viz/Nexus/LLL-OS/apps/terminal/Kconfig \
	/home/viz/Nexus/LLL-OS/apps/timer_server/Kconfig \
	/home/viz/Nexus/LLL-OS/apps/console_server/Kconfig \
	/home/viz/Nexus/LLL-OS/apps/file_server/Kconfig \
	/home/viz/Nexus/LLL-OS/apps/selfloader/Kconfig \
	/home/viz/Nexus/LLL-OS/apps/process_server/Kconfig \
	apps/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libplatsupport/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libvterm/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libutils/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/librefos/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/librefossys/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libsel4utils/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libsel4vka/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libsel4vspace/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libsel4utils/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libsel4simple-default/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libsel4simple/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libsel4platsupport/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libsel4muslcsys/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libsel4debug/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libsel4allocman/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libmuslc/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libelf/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libdatastruct/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libcpio/Kconfig \
	/home/viz/Nexus/LLL-OS/libs/libsel4/Kconfig \
	libs/Kconfig \
	/home/viz/Nexus/LLL-OS/kernel/src/plat/pc99/Kconfig \
	/home/viz/Nexus/LLL-OS/kernel/src/arch/arm/Kconfig \
	kernel/Kconfig \
	Kconfig

include/config/auto.conf: \
	$(deps_config)

ifneq "$(SEL4_APPS_PATH)" "/home/viz/Nexus/LLL-OS/apps"
include/config/auto.conf: FORCE
endif
ifneq "$(SEL4_LIBS_PATH)" "/home/viz/Nexus/LLL-OS/libs"
include/config/auto.conf: FORCE
endif
ifneq "$(COMMON_PATH)" "/home/viz/Nexus/LLL-OS/tools/common"
include/config/auto.conf: FORCE
endif
ifneq "$(KERNEL_ROOT_PATH)" "/home/viz/Nexus/LLL-OS/kernel"
include/config/auto.conf: FORCE
endif

$(deps_config): ;
