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
		char cost_str[33];
		memset( cost_str, '\0', 33 );
		#ifdef __MINGW32__
		sprintf( cost_str, "%lx$%x$%x$", (long unsigned int)n, (unsigned int)r, (unsigned int)p );
		#else
		sprintf( cost_str, "%Lx$%x$%x$", n, r, p );
		#endif
		return rb_str_new2( cost_str );
	}

	return Qnil;
}


static VALUE sc_crypt( VALUE self, VALUE key, VALUE salt, VALUE cost )
{
	uint64_t n = 0;
	uint32_t r = 0;
	uint32_t p = 0;
	int result;

	const char * safe_key = RSTRING_PTR(key) ? RSTRING_PTR(key) : "";
	const char * safe_salt = RSTRING_PTR(salt) ? RSTRING_PTR(salt) : "";

	const size_t buffer_size = 256;
	char buffer[buffer_size];
	memset( buffer, '\0', buffer_size );

	if (!RSTRING_PTR( cost ))
	{
		return Qnil;
	}

	#ifdef __MINGW32__
	sscanf( RSTRING_PTR( cost ), "%lx$%x$%x$", (long unsigned int*)& n, (unsigned int*)& r, (unsigned int*)& p );
	#else
	sscanf( RSTRING_PTR( cost ), "%Lx$%x$%x$", & n, & r, & p );
	#endif

	result = crypto_scrypt(
		(uint8_t *) safe_key, strlen(safe_key),
		(uint8_t *) safe_salt, strlen(safe_salt),
		n, r, p,
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
	rb_define_singleton_method( cSCryptEngine, "__sc_crypt", sc_crypt, 3 );
}


/*
#include <stdio.h>
#include <string.h>
#include "scrypt_calibrate.h"
#include "crypto_scrypt.h"

int main (int argc, const char * argv[])
{
	uint64_t n;
	uint32_t r;
	uint32_t p;

	int result = calibrate( 0, 0.001, 0.25, & n, & r, & p );

	printf( "%Ld %d %d \n", n, r, p );

	char header[33];
	sprintf( header, "%.16Lx%.8x%.8x", n, r, p );
	printf( "%s \n", header );

	uint64_t a = 0;
	uint32_t b = 0;
	uint32_t c = 0;
	sscanf( header, "%16Lx%8x%8x", & a, & b, & c );
	printf( "%Ld %d %d \n", a, b, c );

	char password[] = "helloworld!";
	char salt[] = "qwerty";
	const size_t buffer_size = 32;
	char buffer[buffer_size];
	memset(buffer, '\0', buffer_size);

	result = crypto_scrypt( (uint8_t *) password, strlen(password), (uint8_t *) salt, strlen(salt), n, r, p, (uint8_t *) buffer, buffer_size );

	for (size_t i=0; i<buffer_size; i++)
	{
		printf( "%.2x", buffer[i] );
	}
	printf( "\n" );

    return 0;
}
*/
