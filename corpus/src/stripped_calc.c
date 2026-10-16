/* stripped_calc: small expression evaluator, meant to be analysed without symbols. */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

struct parser {
    const char *p;
    int err;
};

static long parse_expr(struct parser *ps);

static void skip_ws(struct parser *ps)
{
    while (isspace((unsigned char)*ps->p))
        ps->p++;
}

static long parse_number(struct parser *ps)
{
    long v = 0;
    int any = 0;
    skip_ws(ps);
    while (isdigit((unsigned char)*ps->p)) {
        v = v * 10 + (*ps->p - '0');
        ps->p++;
        any = 1;
    }
    if (!any)
        ps->err = 1;
    return v;
}

static long parse_atom(struct parser *ps)
{
    skip_ws(ps);
    if (*ps->p == '(') {
        ps->p++;
        long v = parse_expr(ps);
        skip_ws(ps);
        if (*ps->p != ')')
            ps->err = 1;
        else
            ps->p++;
        return v;
    }
    if (*ps->p == '-') {
        ps->p++;
        return -parse_atom(ps);
    }
    return parse_number(ps);
}

static long parse_term(struct parser *ps)
{
    long v = parse_atom(ps);
    for (;;) {
        skip_ws(ps);
        char op = *ps->p;
        if (op != '*' && op != '/' && op != '%')
            return v;
        ps->p++;
        long r = parse_atom(ps);
        if (op == '*') {
            v *= r;
        } else if (r == 0) {
            ps->err = 1;
        } else {
            v = (op == '/') ? v / r : v % r;
        }
    }
}

static long parse_expr(struct parser *ps)
{
    long v = parse_term(ps);
    for (;;) {
        skip_ws(ps);
        char op = *ps->p;
        if (op != '+' && op != '-')
            return v;
        ps->p++;
        long r = parse_term(ps);
        v = (op == '+') ? v + r : v - r;
    }
}

static int evaluate(const char *text, long *out)
{
    struct parser ps = { text, 0 };
    long v = parse_expr(&ps);
    skip_ws(&ps);
    if (ps.err || *ps.p != '\0')
        return -1;
    *out = v;
    return 0;
}

int main(void)
{
    static const char *const cases[] = {
        "1 + 2 * 3", "(1 + 2) * 3", "100 / (5 - 5)", "-(4 + 6) % 7",
        "2 * (3 + 4) * 5", "12 +", "((7))",
    };
    int bad = 0;
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        long v;
        if (evaluate(cases[i], &v) == 0) {
            printf("%-18s = %ld\n", cases[i], v);
        } else {
            printf("%-18s : error\n", cases[i]);
            bad++;
        }
    }
    printf("errors: %d\n", bad);
    return 0;
}
