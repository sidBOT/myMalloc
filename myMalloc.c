#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "myMalloc.h"
#include "printing.h"

/* Due to the way assert() prints error messges we use out own assert function
 * for deteminism when testing assertions
 */
#ifdef TEST_ASSERT
  inline static void assert(int e) {
    if (!e) {
      const char * msg = "Assertion Failed!\n";
      write(2, msg, strlen(msg));
      exit(1);
    }
  }
#else
  #include <assert.h>
#endif

int countList(header * h);

/*
 * Mutex to ensure thread safety for the freelist
 */
static pthread_mutex_t mutex;

/*
 * Array of sentinel nodes for the freelists
 */
header freelistSentinels[N_LISTS];

/*
 * Pointer to the second fencepost in the most recently allocated chunk from
 * the OS. Used for coalescing chunks
 */
header * lastFencePost;

/*
 * Pointer to maintian the base of the heap to allow printing based on the
 * distance from the base of the heap
 */ 
void * base;

/*
 * List of chunks allocated by  the OS for printing boundary tags
 */
header * osChunkList [MAX_OS_CHUNKS];
size_t numOsChunks = 0;

/*
 * direct the compiler to run the init function before running main
 * this allows initialization of required globals
 */
static void init (void) __attribute__ ((constructor));

// Helper functions for manipulating pointers to headers
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off);
static inline header * get_left_header(header * h);
static inline header * ptr_to_header(void * p);

// Helper functions for allocating more memory from the OS
static inline void initialize_fencepost(header * fp, size_t left_size);
static inline void insert_os_chunk(header * hdr);
static inline void insert_fenceposts(void * raw_mem, size_t size);
static header * allocate_chunk(size_t size);

// Helper functions for freeing a block
static inline void deallocate_object(void * p);

// Helper functions for allocating a block
static inline header * allocate_object(size_t raw_size);

// Helper functions for verifying that the data structures are structurally 
// valid
static inline header * detect_cycles();
static inline header * verify_pointers();
static inline bool verify_freelist();
static inline header * verify_chunk(header * chunk);
static inline bool verify_tags();

static void init();

static bool isMallocInitialized;

/**
 * @brief Helper function to retrieve a header pointer from a pointer and an 
 *        offset
 *
 * @param ptr base pointer
 * @param off number of bytes from base pointer where header is located
 *
 * @return a pointer to a header offset bytes from pointer
 */
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off) {
	return (header *)((char *) ptr + off);
}

/**
 * @brief Helper function to get the header to the right of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
header * get_right_header(header * h) {
	return get_header_from_offset(h, get_size(h));
}

/**
 * @brief Helper function to get the header to the left of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
inline static header * get_left_header(header * h) {
  return get_header_from_offset(h, -h->left_size);
}

/**
 * @brief Fenceposts are marked as always allocated and may need to have
 * a left object size to ensure coalescing happens properly
 *
 * @param fp a pointer to the header being used as a fencepost
 * @param left_size the size of the object to the left of the fencepost
 */
inline static void initialize_fencepost(header * fp, size_t left_size) {
	set_state(fp,FENCEPOST);
	set_size(fp, ALLOC_HEADER_SIZE);
	fp->left_size = left_size;
}

/**
 * @brief Helper function to maintain list of chunks from the OS for debugging
 *
 * @param hdr the first fencepost in the chunk allocated by the OS
 */
inline static void insert_os_chunk(header * hdr) {
  if (numOsChunks < MAX_OS_CHUNKS) {
    osChunkList[numOsChunks++] = hdr;
  }
}

/**
 * @brief given a chunk of memory insert fenceposts at the left and 
 * right boundaries of the block to prevent coalescing outside of the
 * block
 *
 * @param raw_mem a void pointer to the memory chunk to initialize
 * @param size the size of the allocated chunk
 */
inline static void insert_fenceposts(void * raw_mem, size_t size) {
  // Convert to char * before performing operations
  char * mem = (char *) raw_mem;

  // Insert a fencepost at the left edge of the block
  header * leftFencePost = (header *) mem;
  initialize_fencepost(leftFencePost, ALLOC_HEADER_SIZE);

  // Insert a fencepost at the right edge of the block
  header * rightFencePost = get_header_from_offset(mem, size - ALLOC_HEADER_SIZE);
  initialize_fencepost(rightFencePost, size - 2 * ALLOC_HEADER_SIZE);
}

/**
 * @brief Allocate another chunk from the OS and prepare to insert it
 * into the free list
 *
 * @param size The size to allocate from the OS
 *
 * @return A pointer to the allocable block in the chunk (just after the 
 * first fencpost)
 */
static header * allocate_chunk(size_t size) {
  void * mem = sbrk(size);
  
  insert_fenceposts(mem, size);
  header * hdr = (header *) ((char *)mem + ALLOC_HEADER_SIZE);
  set_state(hdr, UNALLOCATED);
  set_size(hdr, size - 2 * ALLOC_HEADER_SIZE);
  hdr->left_size = ALLOC_HEADER_SIZE;
  return hdr;
}
static inline void addBlockToList(header * block, int list) {
	
	//If not in list 58, then make it 58
	if(list >= N_LISTS) {
		list = N_LISTS-1;
	}
	
	header * f = &freelistSentinels[list];
	block->prev = f;
	block->next = f->next;
	block->prev->next = block;
	block->next->prev = block;
	
}

/**
 * @brief Helper allocate an object given a raw request size from the user
 *
 * @param raw_size number of bytes the user needs
 *
 * @return A block satisfying the user's request
 */
static inline header * allocate_object(size_t raw_size) {
	
	
  	// TODO implement allocation
	if(raw_size == 0) {
		return NULL;
	}
	//Get the new rounded size of 8 bytes
	size_t raw_size_new = (raw_size + ALLOC_HEADER_SIZE + 7) & ~7;
	if(raw_size_new < 32) {raw_size_new = 32;} // set to 32 if lower than 32
	//Get the proper index
	size_t list = (raw_size_new / 8) - 3;
	if(list >= N_LISTS) {
		list = N_LISTS - 1;
	}
	//list -= 3;
	header * sve = NULL;
	
	while(list < N_LISTS) {
		header * ptr = &freelistSentinels[list];
		
		while(ptr->next != ptr) {
			if(raw_size_new <= get_size(ptr->next)) {
				int size_need = get_size(ptr->next) - raw_size_new;
				if(size_need >= sizeof(header)) {			
					sve = ptr->next;
					ptr->next->next->prev = ptr;
					ptr->next = ptr->next->next;
					set_size(sve, size_need);
					header * newBlock = get_header_from_offset(sve, get_size(sve));
					newBlock->left_size = get_size(sve); //set left size of new block
					set_size_and_state(newBlock, raw_size_new, ALLOCATED); //set size&state
					header * fencePost = get_header_from_offset(newBlock, get_size(newBlock));
					fencePost->left_size = get_size(newBlock);
					addBlockToList(sve, (size_need/8)-3);//add back to list
					
					//return (void *)(header *)((char *) newBlock + ALLOC_HEADER_SIZE);
					return get_header_from_offset(newBlock, ALLOC_HEADER_SIZE);
					
				}else {
				
					header * newBlock = ptr->next;
					ptr->next->next->prev = ptr;
					ptr->next = ptr->next->next;
					set_size_and_state(newBlock, raw_size_new, ALLOCATED);
					header * fencePost = get_header_from_offset(newBlock, get_size(newBlock));
					fencePost->left_size = get_size(newBlock);
					//return (void *)(header *)((char *) newBlock + ALLOC_HEADER_SIZE);
					return get_header_from_offset(newBlock, ALLOC_HEADER_SIZE);
				}
			}
			ptr = ptr->next;
		}
		
		list++;
	}
	
	header * pt = allocate_chunk(ARENA_SIZE);
	header * lfp_old = lastFencePost;
	if(pt == NULL) {	
		return NULL;
	}
	lastFencePost = get_right_header(pt);
	header * prev_block_lfp = get_header_from_offset(pt, (-2*ALLOC_HEADER_SIZE));//(header *)((char *)pt - (2*ALLOC_HEADER_SIZE));
	if(prev_block_lfp == lfp_old) {
		//numOsChunks--;
		header * tmp = get_left_header(lfp_old);
		if(get_state(tmp) == UNALLOCATED) {
			set_size(tmp, (get_size(tmp) + 2*ALLOC_HEADER_SIZE + get_size(pt)));
			set_state(tmp, UNALLOCATED);
			lastFencePost->left_size = get_size(tmp);
			tmp->prev->next = tmp->next;
			tmp->next->prev = tmp->prev;
			addBlockToList(tmp, (get_size(tmp)/8)-3);
			return allocate_object(raw_size);

		}else {
			set_size_and_state(lfp_old, (get_size(pt) + 2*ALLOC_HEADER_SIZE), UNALLOCATED);
			lastFencePost->left_size = get_size(lfp_old);
			addBlockToList(lfp_old, (get_size(lfp_old)/8)-3);
			return allocate_object(raw_size);
		}
	
		
	}else {
		//lastFencePost->left_size = get_size(pt);
		
		insert_os_chunk(get_left_header(pt));
		addBlockToList(pt, ((get_size(pt)/8)-3));
		allocate_object(raw_size);
		
	}
	//lastFencePost = get_right_header(pt);
	//return;

}

/**
 * @brief Helper to get the header from a pointer allocated with malloc
 *
 * @param p pointer to the data region of the block
 *
 * @return A pointer to the header of the block
 */
static inline header * ptr_to_header(void * p) {
  return (header *)((char *) p - ALLOC_HEADER_SIZE); //sizeof(header));
}

/**
 * @brief Helper to manage deallocation of a pointer returned by the user
 *
 * @param p The pointer returned to the user by a call to malloc
 */

static inline void deallocate_object(void * p) {
  	// TODO implement deallocation
	if(p == NULL) {
		return;
	}
	header * malloc_header = ptr_to_header(p);
	if(get_state(malloc_header) == UNALLOCATED) {
		fprintf(stderr,"Double Free Detected\n"); //removed \n from assert!
		assert(false);
	}
	set_state(malloc_header,UNALLOCATED);
	header * left = get_left_header(malloc_header);
	header * right = get_right_header(malloc_header);
	
	int count = 0;
	int flag;
	
	if(get_state(left) == UNALLOCATED && get_state(right) == UNALLOCATED) {
		set_size(left, get_size(malloc_header)+get_size(left) + get_size(right));
		header * rightHeader = get_right_header(right);
		rightHeader->left_size = get_size(left);
		right->prev->next = right->next;
		right->next->prev = right->prev;
		if(((get_size(left)/8)-3 < 58)) {
			left->prev->next = left->next;
			left->next->prev = left->prev;
			size_t list = (get_size(left)/8)-3;
			addBlockToList(left, list);	
			return;
		}
	}
	else if(get_state(right) == UNALLOCATED) {
		set_size(malloc_header, get_size(malloc_header)+get_size(right));
		header * rightHeader = get_right_header(right);
		rightHeader->left_size = get_size(malloc_header);
		if(((get_size(right)/8)-3 < 58)) {
			right->prev->next = right->next;
			right->next->prev = right->prev;
			size_t list = (get_size(malloc_header)/8)-3;
			addBlockToList(malloc_header, list);
			return;
		}else {
			malloc_header->next = right->next;
			malloc_header->prev = right->prev;
			malloc_header->next->prev = malloc_header;
			malloc_header->next->prev = malloc_header;
			return;
		}
	}
	else if(get_state(left) == UNALLOCATED) {
		set_size(left, get_size(malloc_header)+get_size(left));
		right->left_size = get_size(left);
		if(((get_size(left)/8)-3 < 58)) {
			left->prev->next = left->next;
			left->next->prev = left->prev;
			size_t list = (get_size(left)/8)-3;
			addBlockToList(left, list);
			return;
		} 
	}else {
		right->left_size = get_size(malloc_header);
		size_t list = (get_size(malloc_header)/8)-3;
		addBlockToList(malloc_header, list);
	}	

	
  	
}

/**
 * @brief Helper to detect cycles in the free list
 * https://en.wikipedia.org/wiki/Cycle_detection#Floyd's_Tortoise_and_Hare
 *
 * @return One of the nodes in the cycle or NULL if no cycle is present
 */
static inline header * detect_cycles() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * slow = freelist->next, * fast = freelist->next->next; 
         fast != freelist; 
         slow = slow->next, fast = fast->next->next) {
      if (slow == fast) {
        return slow;
      }
    }
  }
  return NULL;
}

/**
 * @brief Helper to verify that there are no unlinked previous or next pointers
 *        in the free list
 *
 * @return A node whose previous and next pointers are incorrect or NULL if no
 *         such node exists
 */
static inline header * verify_pointers() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * cur = freelist->next; cur != freelist; cur = cur->next) {
      if (cur->next->prev != cur || cur->prev->next != cur) {
        return cur;
      }
    }
  }
  return NULL;
}

/**
 * @brief Verify the structure of the free list is correct by checkin for 
 *        cycles and misdirected pointers
 *
 * @return true if the list is valid
 */
static inline bool verify_freelist() {
  header * cycle = detect_cycles();
  if (cycle != NULL) {
    fprintf(stderr, "Cycle Detected\n");
    print_sublist(print_object, cycle->next, cycle);
    return false;
  }

  header * invalid = verify_pointers();
  if (invalid != NULL) {
    fprintf(stderr, "Invalid pointers\n");
    print_object(invalid);
    return false;
  }

  return true;
}

/**
 * @brief Helper to verify that the sizes in a chunk from the OS are correct
 *        and that allocated node's canary values are correct
 *
 * @param chunk AREA_SIZE chunk allocated from the OS
 *
 * @return a pointer to an invalid header or NULL if all header's are valid
 */
static inline header * verify_chunk(header * chunk) {
	if (get_state(chunk) != FENCEPOST) {
		fprintf(stderr, "Invalid fencepost\n");
		print_object(chunk);
		return chunk;
	}
	
	for (; get_state(chunk) != FENCEPOST; chunk = get_right_header(chunk)) {
		if (get_size(chunk)  != get_right_header(chunk)->left_size) {
			fprintf(stderr, "Invalid sizes\n");
			print_object(chunk);
			return chunk;
		}
	}
	
	return NULL;
}

/**
 * @brief For each chunk allocated by the OS verify that the boundary tags
 *        are consistent
 *
 * @return true if the boundary tags are valid
 */
static inline bool verify_tags() {
  for (size_t i = 0; i < numOsChunks; i++) {
    header * invalid = verify_chunk(osChunkList[i]);
    if (invalid != NULL) {
      return invalid;
    }
  }

  return NULL;
}

/**
 * @brief Initialize mutex lock and prepare an initial chunk of memory for allocation
 */
static void init() {
  // Initialize mutex for thread safety
  pthread_mutex_init(&mutex, NULL);

#ifdef DEBUG
  // Manually set printf buffer so it won't call malloc when debugging the allocator
  setvbuf(stdout, NULL, _IONBF, 0);
#endif // DEBUG

  // Allocate the first chunk from the OS
  header * block = allocate_chunk(ARENA_SIZE);

  header * prevFencePost = get_header_from_offset(block, -ALLOC_HEADER_SIZE);
  insert_os_chunk(prevFencePost);

  lastFencePost = get_header_from_offset(block, get_size(block));

  // Set the base pointer to the beginning of the first fencepost in the first
  // chunk from the OS
  base = ((char *) block) - ALLOC_HEADER_SIZE; //sizeof(header);

  // Initialize freelist sentinels
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    freelist->next = freelist;
    freelist->prev = freelist;
  }

  // Insert first chunk into the free list
  header * freelist = &freelistSentinels[N_LISTS - 1];
  freelist->next = block;
  freelist->prev = block;
  block->next = freelist;
  block->prev = freelist;
}

/* 
 * External interface
 */
void * my_malloc(size_t size) {
  pthread_mutex_lock(&mutex);
  header * hdr = allocate_object(size); 
  pthread_mutex_unlock(&mutex);
  return hdr;
}

void * my_calloc(size_t nmemb, size_t size) {
  return memset(my_malloc(size * nmemb), 0, size * nmemb);
}

void * my_realloc(void * ptr, size_t size) {
  void * mem = my_malloc(size);
  memcpy(mem, ptr, size);
  my_free(ptr);
  return mem; 
}

void my_free(void * p) {
  pthread_mutex_lock(&mutex);
  deallocate_object(p);
  pthread_mutex_unlock(&mutex);
}

bool verify() {
  return verify_freelist() && verify_tags();
}
