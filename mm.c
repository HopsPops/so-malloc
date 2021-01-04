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

#define debug(...) dprintf(STDERR_FILENO, __VA_ARGS__)
//#undef assert
//#define assert(...)

uint32_t free_counter = 0;
uint32_t malloc_counter = 0;

struct block_t {
  int32_t header;
  struct block_t *next;
  /*
   * We don't know what the size of the payload will be, so we will
   * declare it as a zero-length array.  This allow us to obtain a
   * pointer to the start of the payload.
   */
  uint8_t payload[];
};
typedef struct block_t block_t;

const int CLASSES[] = {2,  4,   6,   8,   10,   12,   14,   16, 32,
                       64, 128, 256, 512, 1024, 2048, 4096, 0};

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

static size_t round_up(size_t size) {
  return (size + ALIGNMENT - 1) & -ALIGNMENT;
}

static size_t get_size(block_t *block) {
  return block->header & -2;
}

static block_t *get_next(block_t *block) {
  assert(block != NULL);
  return block->next;
}

bool has_cycle(block_t *list) {
  return false;
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
  block->next = next;
}
static void set_header(block_t *block, size_t size, bool is_allocated,
                       block_t *next) {
  assert(block != NULL);
  assert(size == -1 || size > 0);
  if (size == -1) {
    size = get_size(block);
  }
  block->header = size | is_allocated;
  assert(((void *)next) < mem_sbrk(0));
  set_next(block, next);
}

static bool is_block_allocated(block_t *block) {
  assert(block != NULL);
  return block->header & 1;
}

block_t *list_get_first(int class) {
  return heapp[class];
}
block_t *search_for_block_of_size(int class, size_t desired_size) {
  if (heapp[class] == NULL) {
    return NULL;
  }
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

void list_push(block_t *block) {
  assert(block != NULL);
  assert(!is_block_allocated(block));
  assert(get_size(block) > 0);
  assert(get_next(block) == NULL);
  int list_index = find_list_for_size(get_size(block));
  if (heapp[list_index] == NULL) {
    heapp[list_index] = block;
  } else {
    assert(!is_block_allocated(heapp[list_index]));
    set_next(block, heapp[list_index]);
    heapp[list_index] = block;
  }
  assert(!has_cycle(heapp[list_index]));
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

bool is_in_heap(block_t *block) {
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
  return (block_t *)((int8_t *)ptr -
                     (sizeof(int64_t) + sizeof(struct block_t *)));
}

int free_length(block_t *list) {
  int i = 0;
  while (list != NULL) {
    i++;
    list = get_next(list);
  }
  return i;
}

void update_sizes() {
  for (int i = 0; i < CLASSES_N; i++) {
    block_t *head = list_get_first(i);
    sizes[i] = free_length(head);
  }
}

/*
 * mm_init - Called when a new trace starts.
 */
int mm_init(void) {
  /* Pad heap start so first payload is at ALIGNMENT. */
  if ((long)mem_sbrk(ALIGNMENT - offsetof(block_t, payload)) < 0)
    return -1;

  (void)block_position;
  (void)is_block_allocated;
  for (int i = 0; i < CLASSES_N; i++) {
    heapp[i] = NULL;
  }

  return 0;
}

block_t *allocate_new_block(size_t size) {
  block_t *block = mem_sbrk(size);
  if ((long)block < 0)
    return NULL;

  set_header(block, size, true, NULL);
  return block;
}

block_t *split_block(block_t *block, size_t desired_size) {
  return NULL;
}

block_t *find_block(size_t size) {
  int list_index = find_list_for_size(size);
  int previous_length = free_length(list_get_first(list_index));
  (void)previous_length;
  const int hsize = heap_size();
  (void)hsize;
  block_t *block = search_for_block_of_size(list_index, size);
  assert(block_position(list_get_first(list_index), block, 0) == -1);
  if (block == NULL) {
    block = allocate_new_block(size);
    debug("ALLOCATED %p PAYLOAD %p\n", block, block->payload);
    assert(get_next(block) == NULL);
    assert(get_size(block) >= size);
    return block;
  }
  assert(heap_size() == (hsize - 1));
  assert(get_next(block) == NULL);
  block_t *splitted_block = split_block(block, size);
  if (splitted_block != NULL) {
    /// TODO
    //    heapp[list_index] = block->next;
  }
  set_header(block, -1, true, NULL);
  assert(free_length(list_get_first(list_index)) == previous_length - 1);
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
  const size_t desired_size = size;
  (void)desired_size;
  debug("%u MALLOC %ld ", malloc_counter, size);
  size = round_up(sizeof(block_t) + size);
  block_t *block = find_block(size);

  //  search_for_block((block_t *)0x800000000);
  assert(get_size(block) >= desired_size);
  assert(is_block_allocated(block));
  assert(get_next(block) == NULL);
  assert(!is_in_heap(block));
  update_sizes();
  return block->payload;
}

/*
 * free - We don't know how to free a block.  So we ignore this call.
 *      Computers have big memories; surely it won't be a problem.
 */
void free(void *ptr) {
  free_counter++;
  const int hsize = heap_size();
  (void)hsize;
  assert(ptr != NULL);
  block_t *block = pointer_to_block(ptr);
  debug("%d FREE %p %p %ld\n", free_counter, ptr, block, get_size(block));
  assert(!is_in_heap(block));
  assert(get_size(block) > 0);
  assert(get_size(block) % 2 == 0);
  assert(get_next(block) == NULL);
  assert(is_block_allocated(block));

  int list_index = find_list_for_size(get_size(block));
  int previous_length = free_length(list_get_first(list_index));
  (void)previous_length;
  set_header(block, -1, false, NULL);
  list_push(block);
  assert(heap_size() == (hsize + 1));
  assert(free_length(list_get_first(list_index)) == (previous_length + 1));
  update_sizes();
}

/*
 * realloc - Change the size of the block by mallocing a new block,
 *      copying its data, and freeing the old block.
 **/
void *realloc(void *old_ptr, size_t size) {
  {
    block_t *block = pointer_to_block(old_ptr);
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
    assert(!is_block_allocated(list));
    assert(get_size(list) > 0);
    assert(get_size(list) % 2 == 0);
    assert(((void *)get_next(list)) < mem_sbrk(0));
    assert(!has_cycle(list));
    list = list->next;
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
