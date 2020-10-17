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

struct FileQueue {
  char *filename;
  struct FileQueue *next;
};


static void fileq_free(struct FileQueue *fq) {
  if (fq) {
    if (fq->filename)
      free(fq->filename);
    free(fq);
  }
}

static void
printargv(struct tcb *const tcp, kernel_ulong_t addr, struct FileQueue **fileq)
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
    if (fileq && cmd_arg[0] == '"' && cmd_arg[1] == '@') {
      char *filename = xstrdup(cmd_arg+2);
      filename[strlen(filename)-1] = 0;

      struct FileQueue *new_fileq = (struct FileQueue *)xmalloc(sizeof(struct FileQueue));
      new_fileq->filename = filename;
      new_fileq->next = *fileq;
      *fileq = new_fileq;
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
  char *outbuf = NULL, *inbuf = NULL;
  FILE *fp = fopen(filename, "r");

  if (fp) {
    fseek(fp, 0, SEEK_END);

    size_t buf_size = ftell(fp);
		rewind(fp);

    inbuf = (char *)xcalloc(sizeof(char), buf_size + 1);
    outbuf = (char *)xcalloc(sizeof(char), buf_size * 2 + 1);
    size_t read_size = fread(inbuf, sizeof(char), buf_size, fp);

    fclose(fp);

    if (buf_size != read_size) {
      free(outbuf);
      outbuf = NULL;
    }
    else
      for (int i = 0, j = 0; inbuf[i] != '\0'; ++i, ++j) {
        if (inbuf[i] == '\n' || inbuf[i] == '\r') {
          outbuf[j] = '\\';
          outbuf[++j] = 'n';
        }
        else if (inbuf[i] == '\\') {
          outbuf[j] = '\\';
          outbuf[++j] = '\\';
        }
        else if (inbuf[i] == '"') {
          outbuf[j] = '\\';
          outbuf[++j] = '"';
        }
        else
          outbuf[j] = inbuf[i];
      }
    free(inbuf);
  }
  return outbuf;
}

static void
decode_execve(struct tcb *tcp, const unsigned int index)
{
  struct FileQueue *fileq = NULL, *fileq_tmp = NULL;

	printpath(tcp, tcp->u_arg[index + 0]);
	tprints(", ");

	printargv(tcp, tcp->u_arg[index + 1], &fileq);
	tprints(", ");

  tprints("{");
  while (fileq != NULL) {
    char *content = read_file(fileq->filename);
    if (content != NULL) {
      if (fileq_tmp != NULL)
        tprints(",");
      tprints("\"");tprints(fileq->filename);tprints("\":");
      tprints("\"");tprints(content);tprints("\"");
      free(content);
    }
    fileq_tmp = fileq;
    fileq = fileq->next;
    fileq_free(fileq_tmp);
  }
  tprints("}");
  tprints(", ");
  tprints("\"");
  {
    char buf[PATH_MAX + 1] = {0};
    char proc_cwd[32];
    snprintf(proc_cwd, sizeof(proc_cwd), "/proc/%d/cwd", tcp->pid);
    if (readlink(proc_cwd, buf, sizeof(buf) - 1) > 0)
      tprints(buf);
  }
  tprints("\"");
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
