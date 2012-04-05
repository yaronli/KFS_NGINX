#ifndef _KFS_API_H
#define _KFS_API_H


#ifdef _cplusplus
extern "C"{
#endif
#include <sys/types.h>

#define KFS_FILENAME_MAX_LEN 256
#define KFS_FILE_MAX_CNT     1024

    int kfs_init(const char *metaServerHost, int metaServerPort, const char *user, const char *passwd);
    int kfs_open(const char *pathname, int flags);
    //int kfs_open(const char *pathname, int flags, mode_t mode);
    ssize_t kfs_read(int fd, void *buf, size_t count);

    ssize_t kfs_write(int fd, const void *buf, size_t count);
    off_t kfs_lseek(int fd, off_t offset, int whence);
    ssize_t kfs_pread(int fd, void *buf, size_t count, off_t offset);
    ssize_t kfs_pwrite(int fd, const void *buf, size_t count, off_t offset);
    int kfs_fsync(int fd);
    int kfs_close(int fd);
    int kfs_stat(const char *path, struct stat *st);
    int kfs_readdir(const char *path, char filename_list[][KFS_FILENAME_MAX_LEN], char filetype_list[][5], int *file_cnt);
#ifdef _cplusplus
}
#endif

#endif
