/*
 * Dropbear - a SSH2 server
 *
 * Updated for Android 14 support
 * Author: Tatu Ylonen <ylo@cs.hut.fi>, Matt Johnston, Updated by <Your Name>
 * Copyright (c) 1995-2023. All rights reserved.
 */

#include "includes.h"
#include "dbutil.h"
#include "errno.h"
#include "sshpty.h"

#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#if defined(USE_DEV_PTMX) && defined(HAVE_STROPTS_H)
# include <stropts.h>
#endif

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

int
pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, int namebuflen) {
#if defined(__ANDROID__)
    /* Android-specific PTY allocation */
    dropbear_log(LOG_INFO, "Attempting to allocate PTY for Android.");
    int ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (ptm < 0) {
        dropbear_log(LOG_ERR, "pty_allocate: Failed to open /dev/ptmx: %s", strerror(errno));
        return 0;
    }

    if (grantpt(ptm) < 0 || unlockpt(ptm) < 0) {
        dropbear_log(LOG_ERR, "pty_allocate: grantpt or unlockpt failed: %s", strerror(errno));
        close(ptm);
        return 0;
    }

    char *pts = ptsname(ptm);
    if (!pts) {
        dropbear_log(LOG_ERR, "pty_allocate: ptsname failed.");
        close(ptm);
        return 0;
    }

    strlcpy(namebuf, pts, namebuflen);
    *ptyfd = ptm;
    *ttyfd = open(namebuf, O_RDWR | O_NOCTTY);
    if (*ttyfd < 0) {
        dropbear_log(LOG_ERR, "pty_allocate: Failed to open slave device %s: %s", namebuf, strerror(errno));
        close(*ptyfd);
        return 0;
    }

    dropbear_log(LOG_INFO, "PTY allocated successfully: %s", namebuf);
    return 1;
#else
    /* Original platform-specific implementations */
    dropbear_log(LOG_INFO, "Attempting to allocate PTY for non-Android platform.");
    #if defined(HAVE_OPENPTY)
        char *name;
        int i = openpty(ptyfd, ttyfd, NULL, NULL, NULL);
        if (i < 0) {
            dropbear_log(LOG_ERR, "pty_allocate: openpty failed: %s", strerror(errno));
            return 0;
        }
        name = ttyname(*ttyfd);
        if (!name) {
            dropbear_log(LOG_ERR, "pty_allocate: ttyname failed for openpty device.");
            return 0;
        }
        strlcpy(namebuf, name, namebuflen);
        dropbear_log(LOG_INFO, "PTY allocated successfully: %s", namebuf);
        return 1;
    #else
        dropbear_log(LOG_ERR, "pty_allocate: Platform not supported.");
        return 0;
    #endif
#endif
}

void
pty_release(const char *tty_name) {
    dropbear_log(LOG_INFO, "Releasing PTY: %s", tty_name);
    if (chown(tty_name, (uid_t)0, (gid_t)0) < 0 && (errno != ENOENT)) {
        dropbear_log(LOG_ERR, "pty_release: Failed to chown %s: %s", tty_name, strerror(errno));
    }
    if (chmod(tty_name, (mode_t)0666) < 0 && (errno != ENOENT)) {
        dropbear_log(LOG_ERR, "pty_release: Failed to chmod %s: %s", tty_name, strerror(errno));
    }
}

void
pty_make_controlling_tty(int *ttyfd, const char *tty_name) {
    dropbear_log(LOG_INFO, "Making PTY the controlling terminal: %s", tty_name);
    int fd;

    signal(SIGTTOU, SIG_IGN);

    #ifdef TIOCNOTTY
    fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
    if (fd >= 0) {
        ioctl(fd, TIOCNOTTY, NULL);
        close(fd);
    }
    #endif

    if (setsid() < 0) {
        dropbear_log(LOG_ERR, "pty_make_controlling_tty: setsid failed: %s", strerror(errno));
    }

    fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
    if (fd >= 0) {
        dropbear_log(LOG_ERR, "pty_make_controlling_tty: Failed to disconnect controlling tty.");
        close(fd);
    }

    fd = open(tty_name, O_RDWR);
    if (fd < 0) {
        dropbear_log(LOG_ERR, "%.100s: %.100s", tty_name, strerror(errno));
    } else {
        close(fd);
    }
}

void
pty_change_window_size(int ptyfd, int row, int col, int xpixel, int ypixel) {
    struct winsize w;
    w.ws_row = row;
    w.ws_col = col;
    w.ws_xpixel = xpixel;
    w.ws_ypixel = ypixel;

    if (ioctl(ptyfd, TIOCSWINSZ, &w) < 0) {
        dropbear_log(LOG_ERR, "pty_change_window_size: ioctl failed: %s", strerror(errno));
    } else {
        dropbear_log(LOG_INFO, "PTY window size changed: rows=%d, cols=%d", row, col);
    }
}
