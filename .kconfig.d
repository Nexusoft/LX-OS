deps_config := \
	Config.in

.config include/autoconf.h: $(deps_config)

include/autoconf.h: .config

$(deps_config):
