#include "includes.h"
#include "dbutil.h"
#include "errno.h"
#include "sshpty.h"

/* Android 14兼容性处理，可能需要移除或替换一些系统调用 */

#if defined(HAVE_OPENPTY)
#undef HAVE_DEV_PTMX
#endif

#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#if defined(USE_DEV_PTMX) && defined(HAVE_STROPTS_H)
# include <stropts.h>
#endif

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

/*
 * 为Android 14修改，支持通过设备管理分配PTY
 * 返回0表示无法分配，返回非零表示成功。成功时返回PTY和TTY的文件描述符，和TTY名字。
 */
int
pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, int namebuflen)
{
#if defined(HAVE_OPENPTY)
    /* 对于OpenPTY的兼容性处理：OpenPTY在Android 14上不直接支持，可能需要手动分配PTY */
    char *name;
    int i;

    i = openpty(ptyfd, ttyfd, NULL, NULL, NULL);
    if (i < 0) {
        dropbear_log(LOG_WARNING, 
                "pty_allocate: openpty: %.100s", strerror(errno));
        return 0;
    }
    name = ttyname(*ttyfd);
    if (!name) {
        dropbear_exit("ttyname fails for openpty device");
    }

    strlcpy(namebuf, name, namebuflen); /* 可能会截断 */
    return 1;
#else /* HAVE_OPENPTY */
    #if defined(USE_DEV_PTMX)
    /* Android 14可能使用/dev/ptmx设备 */
    int ptm;
    char *pts;

    ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (ptm < 0) {
        dropbear_log(LOG_WARNING,
                "pty_allocate: /dev/ptmx: %.100s", strerror(errno));
        return 0;
    }

    if (grantpt(ptm) < 0) {
        dropbear_log(LOG_WARNING,
                "grantpt: %.100s", strerror(errno));
        return 0;
    }

    if (unlockpt(ptm) < 0) {
        dropbear_log(LOG_WARNING,
                "unlockpt: %.100s", strerror(errno));
        return 0;
    }

    pts = ptsname(ptm);
    if (pts == NULL) {
        dropbear_log(LOG_WARNING,
                "Slave pty side name could not be obtained.");
    }

    strlcpy(namebuf, pts, namebuflen);
    *ptyfd = ptm;

    /* 打开从设备 */
    *ttyfd = open(namebuf, O_RDWR | O_NOCTTY);
    if (*ttyfd < 0) {
        dropbear_log(LOG_ERR,
            "error opening pts %.100s: %.100s", namebuf, strerror(errno));
        close(*ptyfd);
        return 0;
    }

    return 1;
    #else /* USE_DEV_PTMX */
    /* 通过设备路径分配 */
    const char *name;

    *ptyfd = open("/dev/ptc", O_RDWR | O_NOCTTY);
    if (*ptyfd < 0) {
        dropbear_log(LOG_ERR,
            "Could not open /dev/ptc: %.100s", strerror(errno));
        return 0;
    }
    name = ttyname(*ptyfd);
    if (!name) {
        dropbear_exit("ttyname fails for /dev/ptc device");
    }
    strlcpy(namebuf, name, namebuflen);
    *ttyfd = open(name, O_RDWR | O_NOCTTY);
    if (*ttyfd < 0) {
        dropbear_log(LOG_ERR,
            "Could not open pty slave side %.100s: %.100s",
            name, strerror(errno));
        close(*ptyfd);
        return 0;
    }
    return 1;
    #endif /* USE_DEV_PTMX */
#endif /* HAVE_OPENPTY */
}

/* 释放TTY，恢复其归属 */
void
pty_release(const char *tty_name)
{
    if (chown(tty_name, (uid_t) 0, (gid_t) 0) < 0
            && (errno != ENOENT)) {
        dropbear_log(LOG_ERR,
                "chown %.100s 0 0 failed: %.100s", tty_name, strerror(errno));
    }
    if (chmod(tty_name, (mode_t) 0666) < 0
            && (errno != ENOENT)) {
        dropbear_log(LOG_ERR,
            "chmod %.100s 0666 failed: %.100s", tty_name, strerror(errno));
    }
}

/* 设置TTY为当前进程的控制TTY */
void
pty_make_controlling_tty(int *ttyfd, const char *tty_name)
{
    int fd;

    /* Android上可能不支持TIOCNOTTY，因此可以跳过 */
    signal(SIGTTOU, SIG_IGN);

    /* 首先断开当前控制TTY */
    if (setsid() < 0) {
        dropbear_log(LOG_ERR,
            "setsid: %.100s", strerror(errno));
    }

    /* 设置控制TTY */
#ifdef TIOCSCTTY
    if (ioctl(*ttyfd, TIOCSCTTY, NULL) < 0) {
        dropbear_log(LOG_ERR,
            "ioctl(TIOCSCTTY): %.100s", strerror(errno));
    }
#endif

    fd = open(tty_name, O_RDWR);
    if (fd < 0) {
        dropbear_log(LOG_ERR,
            "%.100s: %.100s", tty_name, strerror(errno));
    } else {
        close(fd);
    }
}

/* 修改窗口大小 */
void
pty_change_window_size(int ptyfd, int row, int col,
    int xpixel, int ypixel)
{
    struct winsize w;

    w.ws_row = row;
    w.ws_col = col;
    w.ws_xpixel = xpixel;
    w.ws_ypixel = ypixel;
    (void) ioctl(ptyfd, TIOCSWINSZ, &w);
}

void
pty_setowner(struct passwd *pw, const char *tty_name)
{
    struct group *grp;
    gid_t gid;
    mode_t mode;
    struct stat st;

    /* 获取tty的组信息 */
    grp = getgrnam("tty");
    if (grp) {
        gid = grp->gr_gid;
        mode = S_IRUSR | S_IWUSR | S_IWGRP;
    } else {
        gid = pw->pw_gid;
        mode = S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH;
    }

    /* 修改所有者和权限 */
    if (stat(tty_name, &st)) {
        dropbear_exit("pty_setowner: stat(%.101s) failed: %.100s",
                tty_name, strerror(errno));
    }

    if (st.st_uid != pw->pw_uid || !(st.st_gid == gid || st.st_gid == pw->pw_gid)) {
        if (chown(tty_name, pw->pw_uid, gid) < 0) {
            dropbear_exit("chown(%.100s, %u, %u) failed: %.100s",
                tty_name, (unsigned int)pw->pw_uid, (unsigned int)gid,
                strerror(errno));
        }
    }

    if ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
        if (chmod(tty_name, mode) < 0) {
            dropbear_exit("chmod(%.100s, 0%o) failed: %.100s",
                tty_name, mode, strerror(errno));
        }
    }
}
