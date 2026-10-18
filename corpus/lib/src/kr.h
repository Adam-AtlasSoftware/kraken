/* libkr: a tiny C library built as every kind of library and object file (corpus/lib). */
#ifndef KR_H
#define KR_H

extern int kr_calls;

int kr_classify(int c);
int kr_report(const char *s);
const char *kr_kind_name(int kind);
unsigned kr_checksum(const char *s);
char *kr_dup_upper(const char *s);

#endif
