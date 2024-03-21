#ifndef __BLUNDER_H__

#define __BLUNDER_H__

#include <linux/spinlock.h>
#include <linux/types.h>


#define BLUNDER_MAX_FDS 0x10
#define BLUNDER_MAX_MAP_SIZE 0x20000

/*
 * @mapping: kernel mapping where IPC messages will be received.
 * @mapping_size: size of the mapping.
 * @buffers: list of `blunder_buffer` allocations.
 * @user_buffer_offset: distance between userspace buffer and mapping
 */
struct blunder_alloc {
	spinlock_t lock;
	void *mapping;
	size_t mapping_size;
	ptrdiff_t user_buffer_offset;
	struct list_head buffers;
};

struct blunder_buffer {
	struct list_head buffers_node;
	atomic_t free;
	size_t buffer_size;
	size_t data_size;
	size_t offsets_size;
	unsigned char data[0];
};

#define MIN_BUF_SIZE sizeof(struct blunder_buffer) + 0x10

struct blunder_message {
	struct list_head entry;
	int opcode;
	struct blunder_proc *from;
	struct blunder_buffer *buffer;
	size_t num_files;
	struct file **files;
};

/*
 * @refcount: number of references for this object.
 * @rb_node : links procs in blunder_device.
 * @alloc: the allocator for incoming messages
 * @handles: rb-tree of handles to other blunder_proc.
 * @messages: list of IPC messages to be delivered to this proc
 */
struct blunder_proc {
	struct kref refcount;
	spinlock_t lock;
	int pid;
	int dead;
	struct rb_node rb_node;
	struct blunder_alloc alloc;
	struct list_head messages;
};

// Do we need any other global state?
struct blunder_device {
	spinlock_t lock;
	struct rb_root procs;
	struct blunder_proc *context_manager;
};

struct blunder_user_message {
	int handle;
	int opcode;
	void *data;
	size_t data_size;
	size_t *offsets;
	size_t offsets_size;
	int *fds;
	size_t num_fds;
};

#define IOCTL_BLUNDER_SET_CTX_MGR	_IOWR('s', 1, uint64_t)
#define IOCTL_BLUNDER_SEND_MSG		_IOWR('s', 2, struct blunder_user_message)
#define IOCTL_BLUNDER_RECV_MSG		_IOWR('s', 3, struct blunder_user_message)
#define IOCTL_BLUNDER_FREE_BUF		_IOWR('s', 4, void *)

#endif
