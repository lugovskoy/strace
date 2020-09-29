/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993-1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Copyright (c) 2007 Roland McGrath <roland@redhat.com>
 * Copyright (c) 2011-2012 Denys Vlasenko <vda.linux@googlemail.com>
 * Copyright (c) 2010-2015 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2014-2019 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"

static void
printargv(struct tcb *const tcp, kernel_ulong_t addr, char **file)
{
	if (!addr || !verbose(tcp)) {
		printaddr(addr);
		return;
	}

	const char *const start_sep = "[";
	const char *sep = start_sep;
	const unsigned int wordsize = current_wordsize;
	unsigned int n;

	for (n = 0; addr; sep = ", ", addr += wordsize, ++n) {
		union {
			unsigned int p32;
			kernel_ulong_t p64;
			char data[sizeof(kernel_ulong_t)];
		} cp;

		if (umoven(tcp, addr, wordsize, cp.data)) {
			if (sep == start_sep)
				printaddr(addr);
			else {
				tprints(", ...");
				printaddr_comment(addr);
				tprints("]");
			}
			return;
		}
		if (!(wordsize < sizeof(cp.p64) ? cp.p32 : cp.p64)) {
			if (sep == start_sep)
				tprints(start_sep);
			break;
		}
		if (abbrev(tcp) && n >= max_strlen) {
			tprintf("%s...", sep);
			break;
		}
		tprints(sep);
    char *cmd_arg = printstr_exec(tcp, wordsize < sizeof(cp.p64) ? cp.p32 : cp.p64);
    if (cmd_arg == NULL)
      continue;
    if (file && cmd_arg[0] == '"' && cmd_arg[1] == '@') {
      *file = xstrdup(cmd_arg+2);
      (*file)[strlen(*file)-1] = 0;
    }
		tprints(cmd_arg);
    free(cmd_arg);
	}
	tprints("]");
}

static void
printargc(struct tcb *const tcp, kernel_ulong_t addr)
{
	printaddr(addr);

	if (!addr || !verbose(tcp))
		return;

	bool unterminated = false;
	unsigned int count = 0;
	char *cp = NULL;

	for (; addr; addr += current_wordsize, ++count) {
		if (umoven(tcp, addr, current_wordsize, &cp)) {
			if (!count)
				return;

			unterminated = true;
			break;
		}
		if (!cp)
			break;
	}
	tprintf_comment("%u var%s%s",
		count, count == 1 ? "" : "s",
		unterminated ? ", unterminated" : "");
}

static char *read_file(char *filename)
{
  char *buf = NULL;
  FILE *fp = fopen(filename, "r");

  if (fp) {
    fseek(fp, 0, SEEK_END);

    size_t buf_size = ftell(fp);
		rewind(fp);

    buf = (char*)xmalloc(sizeof(char) * (buf_size + 1) );
    size_t read_size = fread(buf, sizeof(char), buf_size, fp);
    buf[buf_size] = '\0';

    fclose(fp);

    if (buf_size != read_size) {
      free(buf);
      buf = NULL;
    }
  }
  return buf;
}

static void
decode_execve(struct tcb *tcp, const unsigned int index)
{
  char *file = NULL;

	printpath(tcp, tcp->u_arg[index + 0]);
	tprints(", ");

	printargv(tcp, tcp->u_arg[index + 1], &file);
	tprints(", ");

  tprints("[\"");
  if (file != NULL) {
    char *content = read_file(file);
    for (int i = 0; content[i] != '\0'; ++i) {
      if (content[i] == '\n' || content[i] == '\r')
        content[i] = ' ';
    }
    tprints(content);
    free(content);
    free(file);
  }
  tprints("\"]");
  tprints(", ");

  if (abbrev(tcp))
    printargc(tcp, tcp->u_arg[index + 2]);
  else
    printargv(tcp, tcp->u_arg[index + 2], NULL);
}

SYS_FUNC(execve)
{
	decode_execve(tcp, 0);

	return RVAL_DECODED;
}

SYS_FUNC(execveat)
{
	print_dirfd(tcp, tcp->u_arg[0]);
	tprints(", ");
	decode_execve(tcp, 1);
	tprints(", ");
	printflags(at_flags, tcp->u_arg[4], "AT_???");

	return RVAL_DECODED;
}

#if defined(SPARC) || defined(SPARC64)
SYS_FUNC(execv)
{
	printpath(tcp, tcp->u_arg[0]);
	tprints(", ");
	printargv(tcp, tcp->u_arg[1]);

	return RVAL_DECODED;
}
#endif /* SPARC || SPARC64 */
