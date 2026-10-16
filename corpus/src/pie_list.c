/* pie_list: PIE C program with function pointers and a struct-heavy linked list. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct point {
    int x, y;
};

struct record {
    int id;
    char name[16];
    struct point pos;
    double weight;
};

struct node {
    struct record rec;
    struct node *next;
};

struct list {
    struct node *head;
    int count;
};

typedef int (*cmp_fn)(const struct record *, const struct record *);
typedef void (*visit_fn)(const struct record *, void *);

static struct node *node_new(int id, const char *name, int x, int y, double w)
{
    struct node *n = calloc(1, sizeof *n);
    if (!n)
        exit(3);
    n->rec.id = id;
    strncpy(n->rec.name, name, sizeof n->rec.name - 1);
    n->rec.pos.x = x;
    n->rec.pos.y = y;
    n->rec.weight = w;
    return n;
}

void list_push(struct list *l, struct node *n)
{
    n->next = l->head;
    l->head = n;
    l->count++;
}

static int cmp_id(const struct record *a, const struct record *b)
{
    return a->id - b->id;
}

static int cmp_name(const struct record *a, const struct record *b)
{
    return strcmp(a->name, b->name);
}

static int cmp_dist(const struct record *a, const struct record *b)
{
    int da = a->pos.x * a->pos.x + a->pos.y * a->pos.y;
    int db = b->pos.x * b->pos.x + b->pos.y * b->pos.y;
    return da - db;
}

void list_sort(struct list *l, cmp_fn cmp)
{
    int swapped;
    do {
        swapped = 0;
        for (struct node **pp = &l->head; *pp && (*pp)->next; pp = &(*pp)->next) {
            struct node *a = *pp, *b = a->next;
            if (cmp(&a->rec, &b->rec) > 0) {
                a->next = b->next;
                b->next = a;
                *pp = b;
                swapped = 1;
            }
        }
    } while (swapped);
}

void list_each(const struct list *l, visit_fn fn, void *ctx)
{
    for (const struct node *n = l->head; n; n = n->next)
        fn(&n->rec, ctx);
}

static void print_rec(const struct record *r, void *ctx)
{
    (void)ctx;
    printf("  #%d %-6s (%d,%d) %.1f\n", r->id, r->name, r->pos.x, r->pos.y, r->weight);
}

static void sum_weight(const struct record *r, void *ctx)
{
    *(double *)ctx += r->weight;
}

static void list_free(struct list *l)
{
    while (l->head) {
        struct node *n = l->head;
        l->head = n->next;
        free(n);
    }
    l->count = 0;
}

int main(void)
{
    struct list l = { 0, 0 };
    list_push(&l, node_new(3, "gamma", 5, 1, 2.5));
    list_push(&l, node_new(1, "delta", -2, 7, 1.25));
    list_push(&l, node_new(2, "alpha", 0, 3, 9.0));
    list_push(&l, node_new(4, "beta", 1, 1, 0.5));

    static const struct { const char *label; cmp_fn fn; } orders[] = {
        { "by id", cmp_id }, { "by name", cmp_name }, { "by distance", cmp_dist },
    };
    for (unsigned i = 0; i < sizeof orders / sizeof orders[0]; i++) {
        printf("%s:\n", orders[i].label);
        list_sort(&l, orders[i].fn);
        list_each(&l, print_rec, NULL);
    }
    double total = 0;
    list_each(&l, sum_weight, &total);
    printf("count=%d total=%.2f\n", l.count, total);
    list_free(&l);
    return 0;
}
