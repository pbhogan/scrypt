require "mkmf"
dir_config("scrypt_ext")
CONFIG['CC'] << " -Wall -msse -msse2 "
CONFIG['CC'] << " -D_GNU_SOURCE=1 " if CONFIG["target_os"]["mingw"]
create_makefile("scrypt_ext")