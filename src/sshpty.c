/*
 * Dropbear - a SSH2 server
 *
 * Updated for Android compatibility.
 */

#include "includes.h"
#include "dbutil.h"
#include "errno.h"
#include "sshpty.h"

#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

/*
 * Allocates and opens a pty. Returns 0 if no pty could be allocated,
 * or nonzero if a pty was successfully allocated. On success, open
 * file descriptors for the pty and tty sides and the name of the tty
 * side are returned (the buffer must be able to hold at least 64 characters).
 */

int pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, int namebuflen) {
#ifdef USE_DEV_PTMX
    /* Android-specific: Using /dev/ptmx for pty allocation */
    int ptm;
    char *pts;

    dropbear_log(LOG_INFO, "Attempting to allocate pty using /dev/ptmx.");

    ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (ptm < 0) {
        dropbear_log(LOG_WARNING, "pty_allocate: /dev/ptmx: %.100s", strerror(errno));
        return 0;
    }

    if (grantpt(ptm) < 0) {
        dropbear_log(LOG_WARNING, "grantpt failed: %.100s", strerror(errno));
        close(ptm);
        return 0;
    }

    if (unlockpt(ptm) < 0) {
        dropbear_log(LOG_WARNING, "unlockpt failed: %.100s", strerror(errno));
        close(ptm);
        return 0;
    }

    pts = ptsname(ptm);
    if (pts == NULL) {
        dropbear_log(LOG_WARNING, "ptsname failed: Unable to get slave pty name.");
        close(ptm);
        return 0;
    }

    strlcpy(namebuf, pts, namebuflen);
    *ptyfd = ptm;

    /* Open the slave side. */
    *ttyfd = open(namebuf, O_RDWR | O_NOCTTY);
    if (*ttyfd < 0) {
        dropbear_log(LOG_ERR, "Error opening slave pty: %.100s", strerror(errno));
        close(*ptyfd);
        return 0;
    }

    dropbear_log(LOG_INFO, "Pty allocated successfully: ptyfd=%d, ttyfd=%d, name=%s", *ptyfd, *ttyfd, namebuf);
    return 1;

#else
    #ifdef HAVE_OPENPTY
    /* Use openpty as a fallback */
    if (openpty(ptyfd, ttyfd, namebuf, NULL, NULL) < 0) {
        dropbear_log(LOG_WARNING, "openpty failed: %.100s", strerror(errno));
        return 0;
    }

    dropbear_log(LOG_INFO, "Pty allocated using openpty: ptyfd=%d, ttyfd=%d, name=%s", *ptyfd, *ttyfd, namebuf);
    return 1;

    #else
    dropbear_log(LOG_WARNING, "No supported pty allocation method found.");
    return 0;

    #endif
#endif
}

/*
 * Releases the tty. Its ownership is returned to root, and permissions to 0666.
 */

void pty_release(const char *tty_name) {
    if (chown(tty_name, (uid_t) 0, (gid_t) 0) < 0 && (errno != ENOENT)) {
        dropbear_log(LOG_WARNING, "chown %s failed: %.100s", tty_name, strerror(errno));
    }
    if (chmod(tty_name, (mode_t) 0666) < 0 && (errno != ENOENT)) {
        dropbear_log(LOG_WARNING, "chmod %s 0666 failed: %.100s", tty_name, strerror(errno));
    }
}

/*
 * Makes the tty the controlling tty and sets it to sane modes.
 */

void pty_make_controlling_tty(int *ttyfd, const char *tty_name) {
    int fd;

    /* Disconnect from the old controlling tty. */
    signal(SIGTTOU, SIG_IGN);

#ifdef TIOCNOTTY
    fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
    if (fd >= 0) {
        ioctl(fd, TIOCNOTTY, NULL);
        close(fd);
    }
#endif

    if (setsid() < 0) {
        dropbear_log(LOG_ERR, "setsid failed: %.100s", strerror(errno));
    }

#ifdef TIOCSCTTY
    if (ioctl(*ttyfd, TIOCSCTTY, NULL) < 0) {
        dropbear_log(LOG_ERR, "ioctl(TIOCSCTTY) failed: %.100s", strerror(errno));
    }
#endif

    fd = open(tty_name, O_RDWR);
    if (fd < 0) {
        dropbear_log(LOG_ERR, "Failed to open tty %s: %.100s", tty_name, strerror(errno));
    } else {
        close(fd);
    }
}

/*
 * Changes the window size associated with the pty.
 */

void pty_change_window_size(int ptyfd, int row, int col, int xpixel, int ypixel) {
    struct winsize w;

    w.ws_row = row;
    w.ws_col = col;
    w.ws_xpixel = xpixel;
    w.ws_ypixel = ypixel;

    if (ioctl(ptyfd, TIOCSWINSZ, &w) < 0) {
        dropbear_log(LOG_WARNING, "ioctl(TIOCSWINSZ) failed: %.100s", strerror(errno));
    }
}

/*
 * Sets the owner of the pty.
 */

void pty_setowner(struct passwd *pw, const char *tty_name) {
    struct group *grp;
    gid_t gid;
    mode_t mode;

    grp = getgrnam("tty");
    gid = grp ? grp->gr_gid : pw->pw_gid;
    mode = grp ? (S_IRUSR | S_IWUSR | S_IWGRP) : (S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH);

    if (chown(tty_name, pw->pw_uid, gid) < 0) {
        dropbear_log(LOG_ERR, "chown %s failed: %.100s", tty_name, strerror(errno));
    }

    if (chmod(tty_name, mode) < 0) {
        dropbear_log(LOG_ERR, "chmod %s failed: %.100s", tty_name, strerror(errno));
    }
}
