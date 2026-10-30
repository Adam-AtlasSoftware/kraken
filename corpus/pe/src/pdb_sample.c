/* A freestanding Windows program built with clang and lld-link, which write a PDB: structs, a
   union, an enum, pointers, arrays and function pointers for the native engine's PDB reader. */

typedef unsigned int u32;
typedef unsigned long long u64;

enum shape_kind { SHAPE_POINT = 0, SHAPE_BOX = 1, SHAPE_RING = 7 };

struct vec2 {
    int x;
    int y;
};

struct shape {
    enum shape_kind kind;
    struct vec2 origin;
    struct vec2 extent;
    const char *label;
    int tags[4];
};

union number {
    u32 word;
    float real;
};

struct node {
    struct node *next;
    int value;
};

typedef struct {
    u32 lo : 4;
    u32 hi : 12;
    u32 rest;
} packed_word;

typedef int (*scorer_fn)(const struct shape *);

volatile int pdb_sample_counter;

__attribute__((noinline)) int shape_area(const struct shape *s)
{
    pdb_sample_counter++;
    return s->extent.x * s->extent.y;
}

__attribute__((noinline)) int shape_tag_sum(const struct shape *s, int limit)
{
    int total = 0;
    for (int i = 0; i < 4 && i < limit; i++)
        total += s->tags[i];
    return total;
}

__attribute__((noinline)) int apply_scorer(scorer_fn fn, const struct shape *s)
{
    return fn(s) + 1;
}

__attribute__((noinline)) u32 number_bits(union number n)
{
    return n.word ^ 0x5a5a5a5au;
}

__attribute__((noinline)) void shape_move(struct shape *s, int dx, int dy)
{
    s->origin.x += dx;
    s->origin.y += dy;
}

__attribute__((noinline)) int list_sum(struct node *head, packed_word w)
{
    int total = (int)(w.lo + w.hi + w.rest);
    for (; head; head = head->next)
        total += head->value;
    return total;
}

int main(void)
{
    struct shape s = {SHAPE_BOX, {1, 2}, {3, 4}, "box", {1, 2, 3, 4}};
    union number n;
    n.real = 1.5f;
    shape_move(&s, 2, 3);
    struct node tail = {0, 5};
    struct node head = {&tail, 6};
    packed_word w = {3, 9, 100};
    return apply_scorer(shape_area, &s) + shape_tag_sum(&s, 3) + (int)number_bits(n) +
           list_sum(&head, w);
}
