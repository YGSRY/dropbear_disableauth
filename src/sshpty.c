#include "includes.h"
#include "dbutil.h"
#include "errno.h"
#include "sshpty.h"

#if defined(USE_DEV_PTMX)
# include <stropts.h>
#endif

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

/* 分配伪终端 */
int pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, int namebuflen) {
    int ptm;
    char *pts;

    /* 打开主伪终端设备 */
    ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (ptm < 0) {
        dropbear_log(LOG_WARNING, "pty_allocate: /dev/ptmx: %.100s", strerror(errno));
        return 0;
    }

    /* 授权并解锁伪终端 */
    if (grantpt(ptm) < 0) {
        dropbear_log(LOG_WARNING, "grantpt: %.100s", strerror(errno));
        return 0;
    }
    if (unlockpt(ptm) < 0) {
        dropbear_log(LOG_WARNING, "unlockpt: %.100s", strerror(errno));
        return 0;
    }

    /* 获取伪终端的名字 */
    pts = ptsname(ptm);
    if (pts == NULL) {
        dropbear_log(LOG_WARNING, "Slave pty side name could not be obtained.");
        return 0;
    }

    strlcpy(namebuf, pts, namebuflen);
    *ptyfd = ptm;

    /* 打开从伪终端 */
    *ttyfd = open(namebuf, O_RDWR | O_NOCTTY);
    if (*ttyfd < 0) {
        dropbear_log(LOG_ERR, "error opening pts %.100s: %.100s", namebuf, strerror(errno));
        close(*ptyfd);
        return 0;
    }

    /* 如果系统支持，推送流模块 */
    #if !defined(HAVE_CYGWIN) && defined(I_PUSH)
        if (ioctl(*ttyfd, I_PUSH, "ptem") < 0) {
            dropbear_log(LOG_WARNING, "ioctl I_PUSH ptem: %.100s", strerror(errno));
        }
        if (ioctl(*ttyfd, I_PUSH, "ldterm") < 0) {
            dropbear_log(LOG_WARNING, "ioctl I_PUSH ldterm: %.100s", strerror(errno));
        }
        #ifndef __hpux
        if (ioctl(*ttyfd, I_PUSH, "ttcompat") < 0) {
            dropbear_log(LOG_WARNING, "ioctl I_PUSH ttcompat: %.100s", strerror(errno));
        }
        #endif
    #endif

    return 1;
}

/* 释放伪终端 */
void pty_release(const char *tty_name) {
    if (chown(tty_name, (uid_t) 0, (gid_t) 0) < 0 && (errno != ENOENT)) {
        dropbear_log(LOG_ERR, "chown %.100s 0 0 failed: %.100s", tty_name, strerror(errno));
    }
    if (chmod(tty_name, (mode_t) 0666) < 0 && (errno != ENOENT)) {
        dropbear_log(LOG_ERR, "chmod %.100s 0666 failed: %.100s", tty_name, strerror(errno));
    }
}

/* 设置控制终端 */
void pty_make_controlling_tty(int *ttyfd, const char *tty_name) {
    int fd;
#ifdef USE_VHANGUP
    void *old;
#endif /* USE_VHANGUP */

    /* 忽略SIGTTOU信号 */
    signal(SIGTTOU, SIG_IGN);

    /* 首先断开与旧的控制终端 */
#ifdef TIOCNOTTY
    fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
    if (fd >= 0) {
        (void) ioctl(fd, TIOCNOTTY, NULL);
        close(fd);
    }
#endif /* TIOCNOTTY */

    /* 创建新会话 */
    if (setsid() < 0) {
        dropbear_log(LOG_ERR, "setsid: %.100s", strerror(errno));
    }

    /* 验证我们是否成功断开控制终端 */
    fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
    if (fd >= 0) {
        dropbear_log(LOG_ERR, "Failed to disconnect from controlling tty.");
        close(fd);
    }

    /* 设置新的控制终端 */
#ifdef TIOCSCTTY
    if (ioctl(*ttyfd, TIOCSCTTY, NULL) < 0) {
        dropbear_log(LOG_ERR, "ioctl(TIOCSCTTY): %.100s", strerror(errno));
    }
#endif /* TIOCSCTTY */
#ifdef HAVE_NEWS4
    if (setpgrp(0, 0) < 0) {
        dropbear_log(LOG_ERR, "setpgrp: %.100s", strerror(errno));
    }
#endif /* HAVE_NEWS4 */
#ifdef USE_VHANGUP
    old = mysignal(SIGHUP, SIG_IGN);
    vhangup();
    mysignal(SIGHUP, old);
#endif /* USE_VHANGUP */

    /* 打开指定的tty设备 */
    fd = open(tty_name, O_RDWR);
    if (fd < 0) {
        dropbear_log(LOG_ERR, "%.100s: %.100s", tty_name, strerror(errno));
    } else {
#ifdef USE_VHANGUP
        close(*ttyfd);
        *ttyfd = fd;
#else /* USE_VHANGUP */
        close(fd);
#endif /* USE_VHANGUP */
    }

    /* 验证是否已成功设置控制终端 */
    fd = open(_PATH_TTY, O_WRONLY);
    if (fd < 0) {
        dropbear_log(LOG_ERR, "open /dev/tty failed - could not set controlling tty: %.100s", strerror(errno));
    } else {
        close(fd);
    }
}

/* 更改伪终端窗口大小 */
void pty_change_window_size(int ptyfd, int row, int col, int xpixel, int ypixel) {
    struct winsize w;

    w.ws_row = row;
    w.ws_col = col;
    w.ws_xpixel = xpixel;
    w.ws_ypixel = ypixel;
    (void) ioctl(ptyfd, TIOCSWINSZ, &w);
}

void pty_setowner(struct passwd *pw, const char *tty_name) {
    struct group *grp;
    gid_t gid;
    mode_t mode;
    struct stat st;

    /* 获取“tty”组 */
    grp = getgrnam("tty");
    if (grp) {
        gid = grp->gr_gid;
        mode = S_IRUSR | S_IWUSR | S_IWGRP;
    } else {
        gid = pw->pw_gid;
        mode = S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH;
    }

    /* 获取tty设备信息 */
    if (stat(tty_name, &st)) {
        dropbear_exit("pty_setowner: stat(%.101s) failed: %.100s", tty_name, strerror(errno));
    }

    /* 修改tty的拥有者和权限 */
    if (st.st_uid != pw->pw_uid || !(st.st_gid == gid || st.st_gid == pw->pw_gid)) {
        if (chown(tty_name, pw->pw_uid, gid) < 0) {
            if (errno == EROFS && (st.st_uid == pw->pw_uid || st.st_uid == 0)) {
                dropbear_log(LOG_ERR, "chown(%.100s, %u, %u) failed: %.100s", tty_name, (unsigned int)pw->pw_uid, (unsigned int)gid, strerror(errno));
            } else {
                dropbear_exit("chown(%.100s, %u, %u) failed: %.100s", tty_name, (unsigned int)pw->pw_uid, (unsigned int)gid, strerror(errno));
            }
        }
    }

    if ((st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != mode) {
        if (chmod(tty_name, mode) < 0) {
            if (errno == EROFS && (st.st_mode & (S_IRGRP | S_IROTH)) == 0) {
                dropbear_log(LOG_ERR, "chmod(%.100s, 0%o) failed: %.100s", tty_name, mode, strerror(errno));
            } else {
                dropbear_exit("chmod(%.100s, 0%o) failed: %.100s", tty_name, mode, strerror(errno));
            }
        }
    }
}
