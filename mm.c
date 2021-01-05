/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  Blocks are never coalesced or reused.  The size of
 * a block is found at the first aligned word before the block (we need
 * it for realloc).
 *
 * This code is correct and blazingly fast, but very bad usage-wise since
 * it never frees anything.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
//#define DEBUG
//#ifdef DEBUG
//#define debug(...) printf(__VA_ARGS__)
//#else
//#define debug(...)
//#endif

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

#define DEBUG
#ifdef DEBUG
#define debug(...) dprintf(STDERR_FILENO, __VA_ARGS__)
#else
#define debug(...)
#undef assert
#define assert(...)
#endif

uint32_t free_counter = 0;
uint32_t malloc_counter = 0;
uint32_t split_counter = 0;

typedef uint32_t block_header;

struct __attribute__((__packed__)) block_t {
  block_header header;
  /*
   * We don't know what the size of the payload will be, so we will
   * declare it as a zero-length array.  This allow us to obtain a
   * pointer to the start of the payload.
   */
  uint8_t payload[];
};
typedef struct block_t block_t;

const int CLASSES[] = {4,     8,         10,        12,        14,   16,
                       22,    28,        32,        64,        128,  256,
                       512,   1024,      2048,      4096,      8192, 16384,
                       65536, 2 * 65536, 3 * 65536, 4 * 65536, 0};

#define MINIMAL_PAYLOAD_SIZE CLASSES[0]
#define MINIMAL_BLOCK_SIZE (sizeof(block_t) + MINIMAL_PAYLOAD_SIZE)

#define CLASSES_N (sizeof(CLASSES) / sizeof(typeof(*CLASSES)))
static struct block_t *heapp[CLASSES_N] = {NULL};
static int sizes[CLASSES_N] = {0};
//#define MAGIC ((void *)NULL)
#define MAGIC ((void *)0xCAFEBABE)

int find_list_for_size(size_t size) {
  int i = 0;
  while (CLASSES[i + 1]) {
    if (CLASSES[i] >= size) {
      break;
    }
    i++;
  }
  return i;
}

static void *block_end(block_t *block) {
  return (void *)((char *)block + (block->header & -2));
}

static size_t round_up(size_t size) {
  return (size + ALIGNMENT - 1) & -ALIGNMENT;
}
static block_header *get_header(block_t *block) {
  return &block->header;
}
// static block_footer *get_footer(block_t *block) {
//  block_footer *footerp =
//    (block_footer *)(block_end(block) - sizeof(block_footer));
//
//  return footerp;
//}

static size_t get_size(block_t *block) {
  //  assert(*get_header(block) == *get_footer(block));
  return *get_header(block) & -2;
}

// static size_t get_size_from_footer(block_t *block) {
//  return *get_footer(block) & -2;
//}

static bool block_is_allocated(block_t *block) {
  assert(block != NULL);
  return block->header & 1;
}
#define GET_NEXT(block) (*((block_t **)&block->payload))
static block_t *get_next(block_t *block) {
  assert(block != NULL);
  assert(((int64_t)GET_NEXT(block)) % 2 == 0);
  block_t *next = GET_NEXT(block);
  if (block_is_allocated(block)) {
    assert(next == NULL);
  }
  return next;
}

/*static block_t *list_last(block_t *list) {
  while (get_next(list)) {
    list = get_next(list);
  }
  return list;
}*/

bool list_has_cycle(block_t *list) {
  //  return false;
  block_t *tail = list;
  block_t *head = list;
  while (tail != NULL && head != NULL && get_next(head)) {
    tail = get_next(tail);
    head = get_next(get_next(head));
    if (tail == head) {
      printf("CYCLE DETECTED %p\n", tail);
      fflush(NULL);
      return true;
    }
  }
  return false;
}

static void set_next(block_t *block, block_t *next) {
  assert(block != next);
  if (next != NULL) {
    assert(!block_is_allocated(block));
  }
  block_t **payload = (block_t **)&block->payload;
  *payload = next;
  assert(GET_NEXT(block) == next);
}
static void set_header(block_t *block, size_t size, bool is_allocated,
                       block_t *next) {
  assert(block != NULL);
  assert(size == -1 || size > 0);
  if (size == -1) {
    size = get_size(block);
  }
  *get_header(block) = size | is_allocated;
  //  *get_footer(block) = size | is_allocated;
  //  assert(*get_header(block) == *get_footer(block));
  assert(((void *)next) < mem_sbrk(0));
  set_next(block, next);
}

static block_t *block_resize(block_t *block, size_t size) {
  assert(size > 0);
  size_t old_size = get_size(block);
  size_t new_block_size = old_size - size;
  assert(new_block_size >= MINIMAL_BLOCK_SIZE);
  set_header(block, size, block_is_allocated(block), get_next(block));
  block_t *new_block = block_end(block);
  set_header(new_block, new_block_size, false, NULL);
  return new_block;
}

block_t *list_get_first(int class) {
  return heapp[class];
}

bool list_contains(block_t *list, block_t *search_for) {
  while (list != NULL) {
    if (list == search_for) {
      return true;
    }
    list = get_next(list);
  }
  return false;
}

block_t *list_first_fit(int class, size_t desired_size) {
  if (heapp[class] == NULL) {
    return NULL;
  }
  //  else {
  //    block_t *current = heapp[class];
  //    assert(get_size(current) >= desired_size);
  //    heapp[class] = get_next(current);
  //    set_next(current, NULL);
  //    return current;
  //  }

  block_t *current = heapp[class];
  if (get_size(current) >= desired_size) {
    heapp[class] = get_next(current);
    set_next(current, NULL);
    return current;
  }
  block_t *next = get_next(current);
  for (; next != NULL; next = get_next(current)) {
    if (get_size(next) >= desired_size) {
      set_next(current, get_next(next));
      set_next(next, NULL);
      break;
    }
    current = next;
  }
  return next;
}

block_t *search_for_block_of_size(size_t desired_size) {
  int class = find_list_for_size(desired_size);
  for (int i = class; i < CLASSES_N; i++) {
    block_t *block_found = list_first_fit(i, desired_size);
    if (block_found != NULL) {
      return block_found;
    }
  }
  return NULL;
}

bool list_is_sorted(block_t *list) {
  while (get_next(list) != NULL) {
    if (get_next(list) < list) {
      debug("NOT SORTED next: %p is < than root: %p\n", get_next(list), list);
      return false;
    }
    list = get_next(list);
  }
  return true;
}

static bool block_is_adjacent(block_t *block_pred, block_t *block_succ) {
  assert(block_pred < block_succ);
  assert(block_pred != NULL);
  assert(block_succ != NULL);
  void *pred_end = block_end(block_pred);
  assert(((block_t *)pred_end) <= block_succ);
  return pred_end == block_succ;
}

block_t *list_find_coalescable_block(block_t **out_lower_bound,
                                     block_t **out_upper_bound, int32_t *out_n,
                                     size_t *out_cluster_size, block_t *list,
                                     size_t desired_size) {
#ifdef DEBUG
  const block_t *original_list = list;
#endif
  block_t *curr = NULL;
  size_t cluster_size = -1;
  while (list != NULL) {
    cluster_size = get_size(list);
    *out_n = 1;
    for (curr = list; true; curr = get_next(curr)) {
      if (cluster_size >= desired_size) {
        *out_upper_bound = get_next(curr);
        goto end;
      }
      block_t *next = get_next(curr);
      if (next == NULL) {
        list = NULL;
        break;
      }
      if (block_is_adjacent(curr, next)) {
        cluster_size += get_size(next);
        ++(*out_n);

      } else {
        list = next;
        *out_lower_bound = curr;
        break;
      }
    }
  }

end:
  if (list != NULL) {
    *out_cluster_size = cluster_size;
    assert(*out_cluster_size >= desired_size);
    assert(*out_n > 0);
    assert(get_next(curr) == *out_upper_bound);
    if (*out_lower_bound == NULL) {
      assert(original_list == list);
    } else {
      assert(get_next(*out_lower_bound) == list);
    }
    //    assert(*out_lower_bound != NULL);
    //    if (*out_upper_bound != NULL) {
    //      assert(block_is_adjacent(list, *out_upper_bound));
    //    }
  } else {
    *out_n = 0;
    *out_upper_bound = NULL;
    *out_lower_bound = NULL;
    *out_cluster_size = 0;
  }
  return list;
}

block_t *list_find_largest_coalescable_block(
  block_t **out_lower_bound, block_t **out_upper_bound, int32_t *out_n,
  size_t *out_cluster_size, block_t *list, size_t desired_size) {
  block_t *coalescable = list;
  size_t previous_size = 0;
  block_t *result = NULL;
  do {
    block_t *lower_bound = NULL;
    block_t *upper_bound = NULL;
    int32_t n = -1;
    size_t cluster_size = -1;
    coalescable = list_find_coalescable_block(
      &lower_bound, &upper_bound, &n, &cluster_size, list, desired_size);
    if (cluster_size >= previous_size) {
      result = coalescable;
      *out_lower_bound = lower_bound;
      *out_upper_bound = upper_bound;
      *out_n = n;
      *out_cluster_size = cluster_size;
    }
  } while (coalescable != NULL);
  return result;
}

int list_length(block_t *list) {
  int i = 0;
  while (list != NULL) {
    i++;
    list = get_next(list);
  }
  return i;
}

void list_push(block_t *block) {
  assert(block != NULL);
  assert(!block_is_allocated(block));
  assert(get_size(block) > 0);
  assert(get_next(block) == NULL);
  const int list_index = find_list_for_size(get_size(block));
#ifdef DEBUG
//  const int lsize = list_length(list_get_first(list_index));
#endif
  if (heapp[list_index] == NULL) { /// adding to empty list
    heapp[list_index] = block;
  } else {
    assert(!block_is_allocated(heapp[list_index]));
    block_t *root = heapp[list_index];
    if (block < root) { /// case when block is already smaller than root
      set_next(block, heapp[list_index]);
      heapp[list_index] = block;
    } else { /// case when we have to find place for our block
      while (get_next(root) != NULL && block > get_next(root)) {
        if (get_next(root) == NULL) {
          break;
        }
        root = get_next(root);
      }
      block_t *next = get_next(root);
      if (next && block_is_adjacent(block, next)) {
        size_t joint_size = get_size(block) + get_size(next);
        debug("JOIN %p and %p, size: %ld+%ld=%ld\n", block, next,
              get_size(block), get_size(next), joint_size);
        block_t *next_next = get_next(next);
        set_next(root, next_next);
        set_header(block, joint_size, false, NULL);
        list_push(block);
      } else {

        set_next(root, block);
        set_next(block, next);
      }
    }
  }
  //  assert(!list_has_cycle(heapp[list_index]));
  //  assert(list_length(list_get_first(list_index)) == (lsize + 1));
  assert(list_is_sorted(heapp[list_index]));
}

int block_position(block_t *list, block_t *block, int from) {
  for (int p = 0; list != NULL; p++) {
    if (list == block && p >= from) {
      return p;
    }
    list = get_next(list);
  }
  return -1;
}

int heap_size() {
  int size = 0;
  for (int i = 0; i < CLASSES_N; i++) {
    block_t *head = list_get_first(i);

    for (; head != NULL; size++) {
      head = get_next(head);
    }
  }
  return size;
}

bool heap_contains(block_t *block) {
  for (int i = 0; i < CLASSES_N; i++) {
    block_t *head = list_get_first(i);
    for (; head != NULL;) {
      if (head == block) {
        //        return true;
        assert(false);
      }
      head = get_next(head);
    }
  }
  return false;
}

void search_for_block(block_t *block) {
  for (int i = 0; i < CLASSES_N; i++) {
    block_t *head = list_get_first(i);

    for (int j = 0; head != NULL; j++) {
      if (head == block) {
        debug("FOUND in [%d] at pos: %d\n", i, j);
      }
      head = get_next(head);
    }
  }
}

block_t *pointer_to_block(void *ptr) {
  return (block_t *)((int8_t *)ptr - (sizeof(struct block_t)));
}

void update_sizes() {
  for (int i = 0; i < CLASSES_N; i++) {
    block_t *head = list_get_first(i);
    sizes[i] = list_length(head);
  }
}

/*
 * mm_init - Called when a new trace starts.
 */
int mm_init() {
  /* Pad heap start so first payload is at ALIGNMENT. */
  if ((long)mem_sbrk(ALIGNMENT - offsetof(block_t, payload)) < 0)
    return -1;

  for (int i = 0; i < CLASSES_N; i++) {
    heapp[i] = NULL;
  }

  return 0;
}
static void block_coalesce(block_t *coalescable, int class,
                           block_t *lower_bound, block_t *upper_bound,
                           int32_t n, size_t cluster_size) {
  set_header(coalescable, cluster_size, false, NULL);
  debug("COALESCED [%d] %p, %d, %ld\n", class, coalescable, n, cluster_size);
  if (lower_bound == NULL) {
    heapp[class] = upper_bound;
  } else {
    assert(list_contains(list_get_first(class), lower_bound));
    set_next(lower_bound, upper_bound);
  }
  assert(!list_has_cycle(list_get_first(class)));
  if (upper_bound != NULL) {
    assert(list_contains(list_get_first(class), upper_bound));
  }
}

block_t *heap_try_to_coalesce(size_t desired_size) {
  const int initial_class = find_list_for_size(desired_size);
  for (int class = initial_class; class >= 0; --class) {
    block_t *lower_bound = NULL;
    block_t *upper_bound = NULL;
    int32_t n = -1;
    size_t cluster_size = -1;
    block_t *list = list_get_first(class);
    block_t *coalescable = list_find_coalescable_block(
      &lower_bound, &upper_bound, &n, &cluster_size, list, desired_size);

    if (coalescable != NULL) {
#ifdef DEBUG
      const int lsize = list_length(list);
#endif
      block_coalesce(coalescable, class, lower_bound, upper_bound, n,
                     cluster_size);
      assert(!list_contains(list_get_first(class), coalescable));
      assert(list_length(list_get_first(class)) == (lsize - n));
      assert(get_size(coalescable) >= desired_size);
    }
    return coalescable;
  }
  return NULL;
}

static void heap_cleanup() {
  for (int class = 0; class < CLASSES_N - 1; class ++) {
    for (int i = 0; true; i++) {
      block_t *lower_bound = NULL;
      block_t *upper_bound = NULL;
      int32_t n = -1;
      size_t cluster_size = -1;
      block_t *list = list_get_first(class);
      block_t *coalescable = list_find_coalescable_block(
        &lower_bound, &upper_bound, &n, &cluster_size, list,
        CLASSES[class + 1] - 1);
      if (coalescable != NULL) {
#ifdef DEBUG
        const int lsize = list_length(list);
#endif
        debug("CLEANUP ");
        block_coalesce(coalescable, class, lower_bound, upper_bound, n,
                       cluster_size);
        assert(!list_contains(list_get_first(class), coalescable));
        assert(list_length(list_get_first(class)) == (lsize - n));
        list_push(coalescable);
      } else {
        break;
      }
    }
  }
}

block_t *allocate_new_block(size_t size) {
  block_t *block = mem_sbrk(size);
  if ((long)block < 0)
    return NULL;

  set_header(block, size, false, NULL);
  return block;
}

block_t *split_block(block_t *block, size_t desired_size) {
  assert((get_size(block) - desired_size) >= 0);
  if (desired_size <= 16) {
    return NULL;
  }
  if ((get_size(block) - desired_size) <= MINIMAL_BLOCK_SIZE) {
    return NULL;
  }
#ifdef DEBUG
  const size_t old_size = get_size(block);
#endif
  block_t *new_block = block_resize(block, desired_size);
  split_counter++;
  debug("%d SPLITTED %p=%ld into %ld and %ld sized blocks [%p]\n",
        split_counter, block, old_size, get_size(block), get_size(new_block),
        new_block);
  return new_block;
}

block_t *find_block(size_t size) {
#ifdef DEBUG
  const int list_index = find_list_for_size(size);
//  const int previous_length = list_length(list_get_first(list_index));
#endif
  //  const int hsize = heap_size();
  //  (void)hsize;
  block_t *block = search_for_block_of_size(size);
  if (block == NULL) {
    block = heap_try_to_coalesce(size);
  }
  assert(block_position(list_get_first(list_index), block, 0) == -1);
  if (block == NULL) {
    block = allocate_new_block(size);
    debug("ALLOCATED %p PAYLOAD %p\n", block, block->payload);
    assert(get_next(block) == NULL);
    assert(get_size(block) >= size);
    set_header(block, -1, true, NULL);
    return block;
  }
  //  assert(heap_size() == (hsize - 1));
  assert(get_next(block) == NULL);
  block_t *splitted_block = split_block(block, size);
  if (splitted_block != NULL) {
    list_push(splitted_block);
    //    assert(heap_size() == hsize);
  }
  set_header(block, -1, true, NULL);
  //  assert(list_length(list_get_first(list_index)) <=
  //         previous_length - (splitted_block == NULL ? 1 : 0));
  debug("FOUND %p PAYLOAD %p\n", block, block->payload);
  return block;
}

/*
 * malloc - Allocate a block by incrementing the brk pointer.
 *      Always allocate a block whose size is a multiple of the alignment.
 */
void *malloc(size_t size) {
  malloc_counter++;
  assert(size > 0);
#ifdef DEBUG
  const size_t desired_size = size;
#endif
  debug("%u MALLOC %ld ", malloc_counter, size);
  size = round_up(sizeof(block_t) + /// header and next
                  size              /// payload
                  //                 + sizeof(block_header) /// footer

  );
  block_t *block = find_block(size);

  //  search_for_block((block_t *)0x800000000);
  assert(get_size(block) >= desired_size);
  assert(block_is_allocated(block));
  assert(get_next(block) == NULL);
  assert(!heap_contains(block));
#ifdef DEBUG
  update_sizes();
#endif
  if (malloc_counter % 100 == 0) {
    heap_cleanup();
  }
  return block->payload;
}

/*
 * free - We don't know how to free a block.  So we ignore this call.
 *      Computers have big memories; surely it won't be a problem.
 */
void free(void *ptr) {
  free_counter++;
  assert(ptr != NULL);
  block_t *block = pointer_to_block(ptr);
  debug("%d FREE %p %p %ld\n", free_counter, ptr, block, get_size(block));
  assert(!heap_contains(block));
  assert(get_size(block) > 0);
  assert(get_size(block) % 2 == 0);
  assert(block_is_allocated(block));
  //  assert(GET_NEXT(block) == NULL);

#ifdef DEBUG
//  const int hsize = heap_size();
//  const int list_index = find_list_for_size(get_size(block));
//  const int previous_length = list_length(list_get_first(list_index));
#endif
  set_header(block, -1, false, NULL);
  list_push(block);
  /*{
    int32_t n = -1;
    size_t cluster_size = -1;
    block_t *upper_bound = NULL;
    block_t *lower_bound = NULL;
    block_t *coalescable = list_find_coalescable_block(
      &lower_bound, &upper_bound, &n, &cluster_size, list_get_first(list_index),
      1 * get_size(block));
    if (coalescable != NULL) {
      debug("COALESCABLE %p %d\n", coalescable, n);
    }
  }*/
//  assert(heap_size() == (hsize + 1));
//  assert(list_length(list_get_first(list_index)) == (previous_length + 1));
#ifdef DEBUG
  update_sizes();
#endif
}

/*
 * realloc - Change the size of the block by mallocing a new block,
 *      copying its data, and freeing the old block.
 **/
void *realloc(void *old_ptr, size_t size) {
  {
#ifdef DEBUG
    block_t *block = pointer_to_block(old_ptr);
#endif
    debug("REALLOC %p %p %ld\n", old_ptr, block, get_size(block));
  }
  /* If size == 0 then this is just free, and we return NULL. */
  if (size == 0) {
    free(old_ptr);
    return NULL;
  }

  /* If old_ptr is NULL, then this is just malloc. */
  if (!old_ptr)
    return malloc(size);

  void *new_ptr = malloc(size);

  /* If malloc() fails, the original block is left untouched. */
  if (!new_ptr)
    return NULL;

  /* Copy the old data. */
  block_t *block = old_ptr - offsetof(block_t, payload);
  size_t old_size = get_size(block);
  if (size < old_size)
    old_size = size;
  memcpy(new_ptr, old_ptr, old_size);

  /* Free the old block. */
  free(old_ptr);

  return new_ptr;
}

/*
 * calloc - Allocate the block and set it to zero.
 */
void *calloc(size_t nmemb, size_t size) {
  debug("CALLOC ");
  size_t bytes = nmemb * size;
  void *new_ptr = malloc(bytes);

  /* If malloc() fails, skip zeroing out the memory. */
  if (new_ptr)
    memset(new_ptr, 0, bytes);

  return new_ptr;
}

void validate_list(block_t *list) {
  while (list != NULL) {
    assert(!block_is_allocated(list));
    assert(get_size(list) > 0);
    assert(get_size(list) % 2 == 0);
    assert(((void *)get_next(list)) < mem_sbrk(0));
    //    assert(!list_has_cycle(list));
    assert(list_is_sorted(list));
    list = get_next(list);
  }
}

/*
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap(int verbose) {
  for (int i = 0; i < CLASSES_N; i++) {
    validate_list(heapp[i]);
  }
  update_sizes();
}
