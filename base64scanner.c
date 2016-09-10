#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

// octothorpe
#define OCTOTHORPE_DEBUG
#include <stuff.h>
#include <logging.h>
#include <fmt_utils.h>
#include <dmalloc.h>
#include <strbuf.h>
#include <files.h>
#include <memutils.h>
#include <entropy.h>
#include <oassert.h>
#include <ostrings.h>
#include <rbtree.h>
#include <base64.h>

// defaults (in bytes):
int min_block=16;
//int min_block=10;
//int max_block=20;
int max_block=102400;

int ascii_only=0;
int _2n_size_only=0;
int skip_padding_checks=0;

rbtree *tree;

struct key
{
	uint64_t hash;
	size_t size;
	char* base64;
	byte* buf;
};

void dfree_key(void *vk)
{
	struct key *k=(struct key*)vk;

	DFREE (k->base64);
	DFREE (k->buf);
	DFREE (k);
};

int compare_key(void* vl, void* vr)
{
	struct key *l = (struct key*)vl;
	struct key *r = (struct key*)vr;
	
	if (r->hash < l->hash)
		return -1;
	if (r->hash > l->hash)
		return 1;
	
	if (r->size < l->size)
		return -1;
	if (r->size > l->size)
		return 1;

	oassert(l->hash==r->hash);
	oassert(l->size==r->size);
	return 0;
}

struct val
{
	char *fname;
	size_t pos;
	struct val *next;
};

void dfree_val(void *vv)
{
	struct val *v=(struct val*)vv;
	if (v->next)
		dfree_val(v->next); // recurisvely, first free deepest structure
	DFREE(v->fname);
	DFREE(v);
};

void visitor(void* k, void* v)
{
	struct key *key=k;
	struct val *val=v;
		
	printf ("\n");
	printf ("*** CRC64=0x%" PRIx64 " size=%zu\n", key->hash, key->size);

	printf ("base64=\"");
	fprint_shrinked_string (key->base64, 100, stdout);
	printf ("\"\n");
	printf ("entropy=%.2lf\n", entropy(key->buf, key->size));

	L_print_buf (key->buf, key->size);
	
	char *fname=dmalloc_and_snprintf("buf_%" PRIx64 ".dat", key->hash);
	save_file_or_die (fname, key->buf, key->size);
	printf ("binary file saved to %s\n", fname);
	DFREE(fname);

	printf ("found at:\n");

	do
	{
		printf ("fname=%s pos=%zu (0x%zx)\n", val->fname, val->pos, val->pos);
		val=val->next;
	}
	while (val);
};

void try_to_decode (char* fname, size_t pos, char *s, size_t size /* of base64 string */)
{
	//printf ("%s(pos=0x%zx size=%zu)\n", __FUNCTION__, pos, size);

	if (skip_padding_checks==0 && size&3) // base64 string size should be multiple of 4 (incl. padding, if present)
		return;

	char *tmp=DSTRNDUP(s, size, "base64");
	byte *outbuf=NULL;

	if (likely_base64_string (tmp)==false)
		goto exit;
	
	outbuf=DMALLOC(byte, size, "byte");
	int realbufsize=Base64decode(outbuf, s);

	if (realbufsize<min_block)
		goto exit;
	if (realbufsize>max_block)
		goto exit;
	if (_2n_size_only && popcnt64(realbufsize)!=1)
		goto exit;
	
	if (ascii_only==1 && is_buf_printable(outbuf, realbufsize)==false)
		goto exit;

	struct key *k=DMALLOC(struct key, 1, "key");
	k->hash=CRC64(0, outbuf, size);
	k->size=realbufsize;
	k->buf=outbuf; outbuf=NULL; // transfer ownership
	k->base64=tmp; tmp=NULL; // transfer ownership
		
	struct val *new_v=DMALLOC(struct val, 1, "value");
	new_v->fname=DSTRDUP(fname, "fname");
	new_v->pos=pos;
	new_v->next=NULL;
	
	if (rbtree_is_key_present(tree, k))
	{
		struct val *v=rbtree_lookup(tree, k);
		// find the last
		for (; v->next; v=v->next);
		oassert(v->next==NULL);
		// insert to v->next
		v->next=new_v;

		// free all structures related to key, we don't need it anymore
		DFREE(k->base64);
		DFREE(k->buf);
		DFREE(k);
	}
	else
		rbtree_insert(tree, (void*)k, (void*)new_v);

exit:
	DFREE(tmp);
	DFREE(outbuf);
};

void scan_for_base64_strings(char* fname, byte *buf, size_t len)
{
#define LAST_IS_NOT_BASE64 0
#define LAST_IS_BASE64 1
#define LAST_IS_BASE64_PADDING 2

	int state=LAST_IS_NOT_BASE64;
	byte* c=buf;
	byte* ptr=NULL;

	while (c-buf<len)
	{
		bool f_is_base64_char=is_base64_char(*c);
		bool f_is_padding=*c=='=';
		if (state!=LAST_IS_BASE64_PADDING && f_is_base64_char && state!=LAST_IS_BASE64)
		{
			// we're getting there if padding hasn't seen yet, and this is first (or subsequent) base64 character
			// start reading new base64 string:
			state=LAST_IS_BASE64;
			ptr=c;
		}
		else if (f_is_base64_char && state==LAST_IS_BASE64)
		{
			// do nothing
		}
		else if (f_is_padding && state==LAST_IS_BASE64_PADDING)
		{
			// do nothing
		}
		else if (state==LAST_IS_BASE64 && f_is_padding)
			state=LAST_IS_BASE64_PADDING;
		else if (state==LAST_IS_BASE64_PADDING && f_is_base64_char)
		{
			// this is a case for "... aaaaa=aaaaaaa= ..." (i.e., several base64 strings are joined together)
			// this part must be processed before the next one
			// dump current string:
			try_to_decode(fname, /* pos */ ptr-buf, /* s */ ptr, /* size */ c-ptr);

			// start reading new base64 string:
			state=LAST_IS_BASE64;
			ptr=c;
		}
		else if (state==LAST_IS_BASE64 || state==LAST_IS_BASE64_PADDING)
		{
			// we're getting there if *c is not base64 character, nor padding symbol
			try_to_decode(fname, /* pos */ ptr-buf, /* s */ ptr, /* size */ c-ptr);
			// reset state
			state=LAST_IS_NOT_BASE64;
		};
		c++;
		//printf ("state=%d buf=%p ptr=%p\n", state, buf, ptr);
	};
	// all bytes are processed
	// dump if anything left
	if (state==LAST_IS_BASE64 || state==LAST_IS_BASE64_PADDING)
		try_to_decode(fname, /* pos */ ptr-buf, /* s */ ptr, /* size */ c-ptr);
};

void process_file (char *fname)
{
	int fd=open_or_die(fname, O_RDONLY);

	size_t fsize=get_file_size_or_die(fname);

	byte* mapped = (byte*)mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mapped==MAP_FAILED)
		die ("mmap failed on %s\n", fname);

	scan_for_base64_strings(fname, mapped, fsize);	

	munmap(mapped, fsize);
};

int main(int argc, char* argv[])
{
	int c;
	int digit_optind = 0;

	printf ("base64scanner <dennis(a)yurichev.com> (2015-2016; compiled at %s)\n", __DATE__);

	L_init_stdout_only();

	while (1)
	{
		int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		static struct option long_options[] =
		{
			{"max-block",		required_argument,	0,			0 },
			{"min-block",		required_argument,	0,			0 },
			{"limit-to-ascii",	no_argument,		&ascii_only,		1 },
			{"2n-size-only",	no_argument,		&_2n_size_only,		1 },
			{"skip-padding-checks",	no_argument,		&skip_padding_checks,	1 },
			{0,			0,			0,			0 }
		};

		c = getopt_long(argc, argv, "",	long_options, &option_index);
		if (c == -1)
			break;

		switch (c)
		{
			case 0:
				if (option_index==0) // max
				{
					if (optarg==NULL)
						die ("--max-block value also should be supplied\n");
					max_block=atoi(optarg);
					printf ("Setting max block to %d\n", max_block);
				}
				else if (option_index==1) // min
				{
					if (optarg==NULL)
						die ("--min-block value also should be supplied\n");
					min_block=atoi(optarg);
					printf ("Setting min block to %d\n", min_block);
				}
				break;

			case '?':
				// unrecognized option!
				exit(0);
				break;

			default:
				printf("?? getopt returned character code 0%o ??\n", c);
		}
	}

	tree=rbtree_create(true, "tree", compare_key);

	if (optind < argc)
	{
		while (optind < argc)
			process_file (argv[optind++]);
	}
	else
	{
		printf ("Usage: base64scanner [options] file1 [file2] [file3] ...\n");
		printf ("\n");
		printf ("Options:\n");
		printf ("\t--min-block <number>  : skip short blocks. size in bytes (decoded).\n");
		printf ("\t--max-block <number>  : limit length of block. size is also in bytes (decoded).\n");
		printf ("\t--limit-to-ascii      : suppress binary blocks, dump only those containing ASCII strings.\n");
		printf ("\t--2n-size-only        : all blocks must have 2^n size (i.e., 2, 4, 8, 16, ...).\n");
		printf ("\t--skip-padding-checks : padding symbols are not checked.\n");
		printf ("\n");
		printf ("Filemask instead of filename is OK, it can be '*' or '*.exe', etc\n");
		printf ("\n");
	};

	// dump all info
	rbtree_foreach(tree, visitor, NULL, NULL);

	rbtree_foreach(tree, NULL, dfree_key, dfree_val);
	rbtree_deinit(tree);

	dump_unfreed_blocks();
	dmalloc_deinit();

	return 0;
};

