/* Check Zig's FUSE layouts and callback signatures against the C headers. */

#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <stddef.h>
#include <stdio.h>

typedef int (*getattr_t)(const char *, struct stat *, struct fuse_file_info *);
typedef int (*readlink_t)(const char *, char *, size_t);
typedef int (*mknod_t)(const char *, mode_t, dev_t);
typedef int (*mkdir_t)(const char *, mode_t);
typedef int (*path_t)(const char *);
typedef int (*two_path_t)(const char *, const char *);
typedef int (*rename_t)(const char *, const char *, unsigned int);
typedef int (*chmod_t)(const char *, mode_t, struct fuse_file_info *);
typedef int (*chown_t)(const char *, uid_t, gid_t, struct fuse_file_info *);
typedef int (*truncate_t)(const char *, off_t, struct fuse_file_info *);
typedef int (*file_info_t)(const char *, struct fuse_file_info *);
typedef int (*read_t)(const char *, char *, size_t, off_t, struct fuse_file_info *);
typedef int (*write_t)(const char *, const char *, size_t, off_t, struct fuse_file_info *);
typedef int (*statfs_t)(const char *, struct statvfs *);
typedef int (*fsync_t)(const char *, int, struct fuse_file_info *);
typedef int (*setxattr_t)(const char *, const char *, const char *, size_t, int);
typedef int (*getxattr_t)(const char *, const char *, char *, size_t);
typedef int (*listxattr_t)(const char *, char *, size_t);
typedef int (*readdir_t)(const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *, enum fuse_readdir_flags);
typedef void *(*init_t)(struct fuse_conn_info *, struct fuse_config *);
typedef void (*destroy_t)(void *);
typedef int (*access_t)(const char *, int);
typedef int (*create_t)(const char *, mode_t, struct fuse_file_info *);
typedef int (*utimens_t)(const char *, const struct timespec[2], struct fuse_file_info *);

/* -Werror turns a callback signature mismatch into a build failure. */
#define SIG(type, name) type name = op->name; (void)name

static void check_signatures(const struct fuse_operations *op)
{
    SIG(getattr_t, getattr); SIG(readlink_t, readlink); SIG(mknod_t, mknod);
    SIG(mkdir_t, mkdir); SIG(path_t, unlink); SIG(path_t, rmdir);
    SIG(two_path_t, symlink); SIG(rename_t, rename); SIG(two_path_t, link);
    SIG(chmod_t, chmod); SIG(chown_t, chown); SIG(truncate_t, truncate);
    SIG(file_info_t, open); SIG(read_t, read); SIG(write_t, write);
    SIG(statfs_t, statfs); SIG(file_info_t, flush); SIG(file_info_t, release);
    SIG(fsync_t, fsync); SIG(setxattr_t, setxattr); SIG(getxattr_t, getxattr);
    SIG(listxattr_t, listxattr); SIG(two_path_t, removexattr);
    SIG(file_info_t, opendir); SIG(readdir_t, readdir); SIG(file_info_t, releasedir);
    SIG(fsync_t, fsyncdir); SIG(init_t, init); SIG(destroy_t, destroy);
    SIG(access_t, access); SIG(create_t, create); SIG(utimens_t, utimens);
}

#define OP(name) printf("offsetof fuse_operations %s %zu\n", #name, offsetof(struct fuse_operations, name))
#define CFG(name) printf("offsetof fuse_config %s %zu\n", #name, offsetof(struct fuse_config, name))
#define CTX(name) printf("offsetof fuse_context %s %zu\n", #name, offsetof(struct fuse_context, name))

int main(void)
{
    struct fuse_operations op = {0};
    check_signatures(&op);

    printf("FUSE_VERSION %d\n", FUSE_VERSION);
    printf("sizeof fuse_operations %zu\n", sizeof(struct fuse_operations));
    printf("sizeof fuse_file_info %zu\n", sizeof(struct fuse_file_info));
    printf("sizeof fuse_context %zu\n", sizeof(struct fuse_context));

    printf("offsetof fuse_file_info flags %zu\n", offsetof(struct fuse_file_info, flags));
    printf("offsetof fuse_file_info fh %zu\n", offsetof(struct fuse_file_info, fh));

    CTX(fuse); CTX(uid); CTX(gid); CTX(pid); CTX(private_data); CTX(umask);

    CFG(set_gid); CFG(gid); CFG(set_uid); CFG(uid); CFG(set_mode); CFG(umask);
    CFG(entry_timeout); CFG(negative_timeout); CFG(attr_timeout);
    CFG(intr); CFG(intr_signal); CFG(remember); CFG(hard_remove);
    CFG(use_ino); CFG(readdir_ino); CFG(direct_io); CFG(kernel_cache); CFG(auto_cache);

    OP(getattr); OP(readlink); OP(mknod); OP(mkdir); OP(unlink); OP(rmdir);
    OP(symlink); OP(rename); OP(link); OP(chmod); OP(chown); OP(truncate);
    OP(open); OP(read); OP(write); OP(statfs); OP(flush); OP(release);
    OP(fsync); OP(setxattr); OP(getxattr); OP(listxattr); OP(removexattr);
    OP(opendir); OP(readdir); OP(releasedir); OP(fsyncdir); OP(init);
    OP(destroy); OP(access); OP(create); OP(lock); OP(utimens); OP(bmap);
    OP(ioctl); OP(poll); OP(write_buf); OP(read_buf); OP(flock);
    OP(fallocate); OP(copy_file_range); OP(lseek);
#if FUSE_VERSION >= FUSE_MAKE_VERSION(3, 18)
    OP(statx);
#endif
#if FUSE_VERSION >= FUSE_MAKE_VERSION(3, 19)
    OP(syncfs);
#endif
    return 0;
}
