require "mkmf"
dir_config("scrypt_ext")
CONFIG['CC'] << " -Wall "
create_makefile("scrypt_ext")