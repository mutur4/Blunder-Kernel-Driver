#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>
#include <linux/memory.h>
#include <linux/fdtable.h>
#include <linux/vmalloc.h>
#include <asm/io.h>

#include "blunder.h"


struct blunder_device blunder_device;

struct blunder_buffer *blunder_alloc_get_buf(struct blunder_alloc *alloc, size_t size) {

    struct blunder_buffer *buf = NULL;
    struct blunder_buffer *new_buf = NULL;
    list_for_each_entry(buf, &alloc->buffers, buffers_node) {
        if (atomic_read(&buf->free) && buf->buffer_size >= size) {

            pr_err("blunder: Free buffer at %lx, size %lx\n",buf, buf->buffer_size);

            // Is there enough space to split? Then do it!
            uint64_t remaining = buf->buffer_size - size;
            
            if (remaining > MIN_BUF_SIZE) {

                // Make new buf at the end of this buf
                new_buf = (struct blunder_buffer *)((void *)&buf->data[size]);
                // New buffer size is remaining - header
                new_buf->buffer_size = remaining - sizeof(*new_buf);
                // Adjust old buffer size to size
                buf->buffer_size = size;
                // Mark as free
                atomic_set(&new_buf->free, 1);

                pr_err("blunder: splitting buffer. New buffer at %lx, size %lx\n",new_buf, new_buf->buffer_size);


                // Add to list after our current entry
                list_add(&new_buf->buffers_node, &buf->buffers_node);
            }

            // Mark buf as non-free and return it
            atomic_set(&buf->free, 0);
            return buf;
        }
    }

    // If we got here we're out of mem!
    return NULL;
    
}

void blunder_alloc_free_buf(struct blunder_alloc *alloc, struct blunder_buffer *buf) {
    // FIXME Merge adjacent buffers if possible!
    atomic_set(&buf->free, 1);
}

/*
 * At release time we expect the mapping to be gone,
 * since the file holds a ref to the proc and the mapping 
 * holds a ref to the file.
 * 
 * We can thus just release the file altogether.
 */

static void blunder_proc_release(struct kref *refcount) {
    struct blunder_proc *proc = container_of(refcount, struct blunder_proc, refcount);
    
    // Remove ourselves?

    pr_err("blunder: proc for pid %d deleted\n", proc->pid);
    kfree(proc->alloc.mapping);
    kfree(proc);
}

static void blunder_proc_put(struct blunder_proc *proc) {
    kref_put(&proc->refcount, blunder_proc_release);
}



static struct blunder_proc * blunder_proc_for_pid_locked(int pid) {
    struct rb_node **p = &blunder_device.procs.rb_node;
    struct rb_node *parent = NULL;
    struct blunder_proc *cur_proc;

    /* Find insertion point by pid */
    while (*p) {

        parent = *p;
        cur_proc = rb_entry(parent, struct blunder_proc, rb_node);

        if (pid < cur_proc->pid)
            p = &(*p)->rb_left;
        else if (pid > cur_proc->pid)
            p = &(*p)->rb_right;
        else {
            return cur_proc;
        }
    }

    /* Now found, return NULL */
    return NULL;
}

static struct blunder_proc * blunder_proc_for_pid(int pid) {
    struct blunder_proc *proc = NULL;
    spin_lock(&blunder_device.lock);
    proc = blunder_proc_for_pid_locked(pid);
    if (proc)
        kref_get(&proc->refcount);
    spin_unlock(&blunder_device.lock);
    return proc;
}


static void blunder_release_buf(struct blunder_proc *proc, struct blunder_buffer *buf) {
    size_t off;
    size_t *offsets;
    struct blunder_handle *h;

    if(!buf)
        return;

    // TODO Handle object references in a future release

    /* And now release the buffer itself */
    blunder_alloc_free_buf(&proc->alloc, buf);
}

static void blunder_release_msg(struct blunder_proc *proc, struct blunder_message *msg) {

    // NOTE: Message has to be already unlinked!

    int f;

    spin_lock(&proc->lock);
    if (msg->files && msg->num_files) {
        /* Files not transfered to userspace must be released. */
        for (f = 0; f < msg->num_files ; f++) {
            fput(msg->files[f]);
        }

        kfree(msg->files);
    }
    spin_unlock(&proc->lock);

    /* And finally throw away the message itself */
    kfree(msg);
}

static int blunder_set_ctx_mgr(struct blunder_proc *proc) {
    spin_lock(&blunder_device.lock);

    if (blunder_device.context_manager && !blunder_device.context_manager->dead) {
        /* Can't do, current context manager is alive */
        spin_unlock(&blunder_device.lock);
        return -EPERM;
    }

    /* Drop the current context_manager */
    if (blunder_device.context_manager) {
        kref_put(&blunder_device.context_manager->refcount, blunder_proc_release);
        blunder_device.context_manager = NULL;
    }

    kref_get(&proc->refcount);
    blunder_device.context_manager = proc;

    spin_unlock(&blunder_device.lock);

    pr_err("blunder: process %d became context manager\n", proc->pid);
    return 0;
}

static int blunder_import_fds(struct blunder_message *msg, int * __user ufds, int num_fds) {
    int fds[BLUNDER_MAX_FDS];
    int i;

    // Skip if no fds
    if (num_fds == 0)
        return 0;

    // num_fds must be verified before calling this!
    if (copy_from_user(fds, ufds, num_fds*sizeof(fds[0]))) {
        return -EFAULT;
    }

    msg->files = kzalloc(num_fds*sizeof(*msg->files), GFP_KERNEL);

    for(i=0; i < num_fds; i++) {
        msg->files[i] = fget(fds[i]);

        if (!msg->files[i]) {
            pr_err("blunder: bad fd %d\n", fds[i]);
            break;
        }
    }

    pr_err("blunder: imported %d files\n", i);
    msg->num_files = i;

    return 0;
}

static int blunder_send_msg(struct blunder_proc *proc, struct blunder_user_message * __user arg) {
    int ret = 0;
    int curr_fd;
    struct blunder_user_message umsg;
    struct blunder_message *msg = NULL;
    struct blunder_handle *target_handle = NULL;
    struct blunder_proc *target = NULL;
    struct blunder_buffer *buf = NULL;

    size_t off;
    size_t *offsets;
    struct blunder_handle *h;

    /* Read data in */
    if (copy_from_user(&umsg, arg, sizeof(umsg))) {
        return -EFAULT;
    }

    /* Verify parameters first */
    // FIXME We do not support offsets and objects yet!
    if (umsg.data_size > BLUNDER_MAX_MAP_SIZE || umsg.offsets_size > 0 
        || umsg.num_fds > BLUNDER_MAX_FDS) {
        return -EINVAL;
    }

    /* Try to figure out destination */
    if (umsg.handle == 0) {
        spin_lock(&blunder_device.lock);
        if (blunder_device.context_manager && !blunder_device.context_manager->dead) {
            target = blunder_device.context_manager;
            kref_get(&target->refcount);
        }
        spin_unlock(&blunder_device.lock);
    } else {
        // blunder_proc_for_pid gets us a ref to the process if it exists
        target = blunder_proc_for_pid(umsg.handle);
    }

    if (!target) {
        return -ENOENT;
    }

    /* Got a target. Allocate message of the right size for the fds */
    msg = kzalloc(sizeof(*msg) + umsg.num_fds*sizeof(struct file *), GFP_KERNEL);
    if (!msg) {
        ret = -ENOMEM;
        goto release_target;
    }

    /* Import files now */
    blunder_import_fds(msg, umsg.fds, umsg.num_fds);

    /* Get buffer */
    buf = blunder_alloc_get_buf(&target->alloc, umsg.data_size + umsg.offsets_size);
    if(!buf) {
        ret = -ENOMEM;
        goto release_msg;
    }

    buf->data_size = umsg.data_size;
    msg->buffer = buf;
    msg->from = proc->pid;


    if (copy_from_user(buf->data, umsg.data, umsg.data_size)) {
        ret = -EFAULT;
        goto release_buf;
    }

    //OK We're good to go now. Link it into the target
    spin_lock(&target->lock);
    list_add_tail(&msg->entry, &target->messages);
    spin_unlock(&target->lock);

    pr_err("blunder: Added message to target %d\n", target->pid);
    /* We can release the target now */
    blunder_proc_put(target);
    return 0;


release_buf:
    blunder_alloc_free_buf(&proc->alloc, buf);

release_msg:
    blunder_release_msg(proc, msg);
    
release_target:
    blunder_proc_put(target);

    return ret;

}

static int blunder_recv_msg(struct blunder_proc *proc, struct blunder_user_message * __user arg) {
    int ret = 0;
    int fds[BLUNDER_MAX_FDS];
    int curr_fd;
    struct blunder_user_message umsg;
    struct blunder_message *msg = NULL;

    /* Read data in */
    if (copy_from_user(&umsg, arg, sizeof(umsg))) {
        return -EFAULT;
    }

    spin_lock(&proc->lock);

    if (!proc->alloc.mapping) {
        goto out_unlock;
    }

    /* Pull from queue */

    msg = list_first_entry_or_null(&proc->messages, struct blunder_message, entry);

    if (!msg) {
        ret = -ENOENT;
        goto out_unlock;
    }

    /* We got a message, delete it from the list and unlock the proc */
    list_del_init(&msg->entry);
    spin_unlock(&proc->lock);

    /*
     * Step 1: install all fd's we have.
     */
    pr_err("blunder: Receiving message with %d files\n", msg->num_files);
    for (curr_fd=0; curr_fd < msg->num_files; curr_fd++) {
        fds[curr_fd] = get_unused_fd_flags(O_CLOEXEC);
        if (fds[curr_fd] < 0) {
            /* Can't make a new fd, return error */
            ret = -ENOSPC;
            goto out_release;
        }

        fd_install(fds[curr_fd], msg->files[curr_fd]);
    }

    /*
     * Now we can copy the data out. Start with the fds.
     * We remove them from the buffer first to prevent 
     * double-freeing them.
     */
    umsg.num_fds = msg->num_files;
    kfree(msg->files);
    msg->files = NULL;
    msg->num_files = 0;

    pr_err("blunder: Copying back %d fds\n", umsg.num_fds);
    if (copy_to_user(umsg.fds, fds, umsg.num_fds * sizeof(fds[0]))) {
        ret = -EFAULT;
        /* Drop them if we fail to copy back as well. */
        goto out_release;
    }

    /* And finally setup the buffer */
    umsg.data = msg->buffer->data - proc->alloc.user_buffer_offset;
    pr_err("blunder: kernel data at %lx, user data at %lx\n", msg->buffer->data, umsg.data);
    umsg.data_size = msg->buffer->data_size;

    // TODO Implement objects!
    umsg.offsets = 0;
    umsg.offsets_size = msg->buffer->offsets_size;

    umsg.handle = msg->from;
    umsg.opcode = msg->opcode;
    if(copy_to_user(arg, &umsg, sizeof(umsg))) {
        ret = -EFAULT;
        goto out_release;
    }

    pr_debug("blunder: blunder_recv_msg done\n");
    return 0;

out_release:
    /* Close the fds we have installed so far */
    if (curr_fd) {
        while(--curr_fd) {
            close_fd(fds[curr_fd]);
        }
    }


    /* Free the message and buffer */
    blunder_release_msg(proc, msg);
    return ret;

out_unlock:

    spin_unlock(&proc->lock);
    return ret;
}

static int blunder_free_buf(struct blunder_proc *proc, unsigned long arg) {
    struct blunder_buffer *buf = NULL;
    uint64_t kdata = arg + proc->alloc.user_buffer_offset;
    int ret = -EEXIST;

    // Precondition: proc->lock for this alloc is held!
    spin_lock(&proc->lock);
    list_for_each_entry(buf, &proc->alloc.buffers, buffers_node) {
        if (atomic_read(&buf->free) == 0 && buf->data == kdata) {
            pr_err("blunder: setting buffer at %lx as free\n", kdata);
            atomic_set(&buf->free, 1);
            ret = 0;
            break;
        }
    }
    spin_unlock(&proc->lock);
    return ret;
}

static long blunder_ioctl (struct file *file, unsigned int code, unsigned long arg) {

    struct blunder_proc *proc = (struct blunder_proc *)file->private_data;

    switch(code) {
        case IOCTL_BLUNDER_SET_CTX_MGR:
            return blunder_set_ctx_mgr(proc);
        
        case IOCTL_BLUNDER_SEND_MSG:
            return blunder_send_msg(proc, (struct blunder_user_message * __user)arg);

        case IOCTL_BLUNDER_RECV_MSG:
            return blunder_recv_msg(proc, (struct blunder_user_message * __user)arg);

        case IOCTL_BLUNDER_FREE_BUF:
            return blunder_free_buf(proc, arg);
        default:
            return -EINVAL;
        }

}

static void blunder_add_proc_locked(struct blunder_proc *proc) {
    struct rb_node **p = &blunder_device.procs.rb_node;
    struct rb_node *parent = NULL;
    struct blunder_proc *cur_proc;
    int pid = proc->pid;

    /* Find insertion point by pid */
    while (*p) {

        parent = *p;
        cur_proc = rb_entry(parent, struct blunder_proc, rb_node);

        if (pid < cur_proc->pid)
            p = &(*p)->rb_left;
        else if (pid > cur_proc->pid)
            p = &(*p)->rb_right;
        else {
            /* This shouldn't happen! */
            BUG();
        }
    }

    /* Found insertion point now */
    rb_link_node(&proc->rb_node, parent, p);
    rb_insert_color(&proc->rb_node, &blunder_device.procs);

    pr_err("Added new proc for pid %d!\n", pid);

} 

static int blunder_open(struct inode *inode, struct file *file)
{
    /*
     * For simplicity, only one open per process is allowed.
     */

    struct blunder_proc *proc = blunder_proc_for_pid(current->group_leader->pid);
    if (proc) {
        blunder_proc_put(proc);
        return -EINVAL;
    }

    /*
     * Open is allowed. Let's make a new proc.
     */
    proc = (struct blunder_proc *)kzalloc(sizeof(*proc), GFP_KERNEL);
    if (!proc) {
        return -ENOMEM;
    }

    pr_err("blunder: allocated proc of size %x\n", sizeof(struct blunder_proc));
    /* Initialize device */
    spin_lock_init(&proc->lock);
    kref_init(&proc->refcount);
    proc->pid = current->group_leader->pid;
    proc->dead = 0;
    INIT_LIST_HEAD(&proc->messages);
    INIT_LIST_HEAD(&proc->alloc.buffers);

    /* Now try to add the device */
    spin_lock(&blunder_device.lock);
    if (blunder_proc_for_pid_locked(current->group_leader->pid)) {
        /* Raced with another thread for insertion. Error out. */
        goto err_free_unlock;
    }
    blunder_add_proc_locked(proc);
    spin_unlock(&blunder_device.lock);

    /* Save this proc into private_data */
    file->private_data = (void *)proc;

    return 0;

err_free_unlock:
    spin_unlock(&blunder_device.lock);
    kfree(proc);
    return -EINVAL;    
}

static int blunder_close(struct inode *inodep, struct file *filp)
{
    struct blunder_proc *proc = (struct blunder_proc *)filp->private_data;
  
    spin_lock(&blunder_device.lock);

    // If we're the context_manager, unregister ourselves.
    if (blunder_device.context_manager == proc) {
        blunder_device.context_manager = NULL;
        blunder_proc_put(proc);
    }

    // Remove from rb_tree. From this point on nobody can look us up.
    rb_erase(&proc->rb_node, &blunder_device.procs);
    spin_unlock(&blunder_device.lock);

    // Drop reference owned by file
    blunder_proc_put(proc);

    return 0;
}

static int blunder_mmap(struct file *filp, struct vm_area_struct *vma) {
    struct blunder_proc *proc = (struct blunder_proc *)filp->private_data;
    unsigned long pfn = 0;
    size_t sz = vma->vm_end - vma->vm_start;
    int ret = -EINVAL;
    void *buf = NULL;

    /* Bail out if mapping is too large or writable */
    if (sz > BLUNDER_MAX_MAP_SIZE || vma->vm_flags & VM_WRITE) {
        goto out;
    }  

    /* Preallocate before we lock */

    buf = kmalloc(sz, GFP_KERNEL);
    if (IS_ERR(buf)) {
        ret = PTR_ERR(buf);
        goto out;
    }
    
    spin_lock(&proc->lock);
    /* Bail out if already mapped */
    if (proc->alloc.mapping) {
        /* Prevent double initialization! */
        goto out_unlock;
        
    }

    /* Initialize and actually map pages */
    pr_err("blunder: Allocated %d bytes mapping at %lx for pid %d\n", sz, (unsigned long)buf, proc->pid);
    proc->alloc.mapping = buf;
    proc->alloc.mapping_size = sz;
    proc->alloc.user_buffer_offset = (unsigned long)proc->alloc.mapping - vma->vm_start; 


    /* Initialize allocator first buffer */
    struct blunder_buffer *first_buf = (struct blunder_buffer *)proc->alloc.mapping;
    
    /* The whole thing minus the size of our header */
    first_buf->buffer_size = proc->alloc.mapping_size - sizeof(*first_buf);
    atomic_set(&first_buf->free,1);
    list_add(&first_buf->buffers_node, &proc->alloc.buffers);


    /* Just map the whole thing */
    pfn = virt_to_phys(proc->alloc.mapping) >> PAGE_SHIFT;
    ret = remap_pfn_range(vma, vma->vm_start, pfn, sz, vma->vm_page_prot);

    if (ret) {
        // Failed to remap. Undo what we did before unlock
        proc->alloc.mapping = NULL;
        proc->alloc.mapping_size = 0;
        kfree(buf);
    }

out_unlock:
    spin_unlock(&proc->lock);
out:
    return ret;
}


static const struct file_operations blunder_fops = {
    .owner			= THIS_MODULE,
    .open			= blunder_open,
    .release		= blunder_close,
    .llseek 		= no_llseek,
    .unlocked_ioctl = blunder_ioctl,
    .mmap           = blunder_mmap,
};

struct miscdevice blunder_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "blunder",
    .fops = &blunder_fops,
};

static int __init misc_init(void)
{
    int error;

    spin_lock_init(&blunder_device.lock);
    blunder_device.context_manager = NULL;
    blunder_device.procs.rb_node = NULL;

    error = misc_register(&blunder_miscdev);
    if (error) {
        pr_err("can't misc_register :(\n");
        return error;
    }

    pr_err("blunder IPC subsystem initialized!\n");

    return 0;
}

static void __exit misc_exit(void)
{
    misc_deregister(&blunder_miscdev);
}

module_init(misc_init)
module_exit(misc_exit)

MODULE_LICENSE("GPL");