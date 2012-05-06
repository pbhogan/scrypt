#include "ruby.h"
#include "scrypt_calibrate.h"
#include "crypto_scrypt.h"


static VALUE mSCrypt;
static VALUE cSCryptEngine;


#ifndef RSTRING_PTR
	#define RSTRING_PTR(s) (RSTRING(s)->ptr)
#endif


static VALUE sc_calibrate( VALUE self, VALUE maxmem, VALUE maxmemfrac, VALUE maxtime )
{
	uint64_t n = 0;
	uint32_t r = 0;
	uint32_t p = 0;

	size_t mm = NUM2UINT( maxmem );
	double mf = rb_num2dbl( maxmemfrac );
	double mt = rb_num2dbl( maxtime );

	if (calibrate( mm, mf, mt, & n, & r, & p ) == 0)
	{
		return rb_ary_new3( 3, UINT2NUM( n ), UINT2NUM( r ), UINT2NUM( p ));
	}

	return Qnil;
}


static VALUE sc_crypt( VALUE self, VALUE key, VALUE salt, VALUE n, VALUE r, VALUE p, VALUE keylen )
{
	int result;

	const char * safe_key = RSTRING_PTR(key) ? RSTRING_PTR(key) : "";
	const char * safe_salt = RSTRING_PTR(salt) ? RSTRING_PTR(salt) : "";

	const size_t buffer_size = NUM2UINT( keylen );
	char buffer[buffer_size];
	memset( buffer, '\0', buffer_size );

	result = crypto_scrypt(
		(uint8_t *) safe_key, strlen(safe_key),
		(uint8_t *) safe_salt, strlen(safe_salt),
		NUM2UINT( n ), NUM2UINT( r ), NUM2UINT( p ),
		(uint8_t *) buffer, buffer_size
	);

	if (result == 0)
	{
		return rb_str_new( buffer, buffer_size );
	}

	printf( "error %d \n", result );

	return Qnil;
}


void Init_scrypt_ext()
{
	mSCrypt = rb_define_module( "SCrypt" );
	cSCryptEngine = rb_define_class_under( mSCrypt, "Engine", rb_cObject );

	rb_define_singleton_method( cSCryptEngine, "__sc_calibrate", sc_calibrate, 3 );
	rb_define_singleton_method( cSCryptEngine, "__sc_crypt", sc_crypt, 6 );
}
