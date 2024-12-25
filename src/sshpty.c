/*
 * Dropbear - a SSH2 server
 *
 * Copied from OpenSSH-3.5p1 source, modified by Matt Johnston 2003
 * 
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Allocating a pseudo-terminal, and making it the controlling tty.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/*RCSID("OpenBSD: sshpty.c,v 1.7 2002/06/24 17:57:20 deraadt Exp ");*/

#include "includes.h"
#include "dbutil.h"
#include "errno.h"
#include "sshpty.h"

/* Pty allocated with _getpty gets broken if we do I_PUSH:es to it. */
#if defined(HAVE__GETPTY) || defined(HAVE_OPENPTY)
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
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

int
pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, int namebuflen)
{
#if defined(USE_DEV_PTMX)
   /* Android-specific: Using /dev/ptmx for pty allocation */
   int ptm;
   char *pts;

   ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY);
   if (ptm < 0) {
       dropbear_log(LOG_WARNING, "pty_allocate: /dev/ptmx: %.100s", strerror(errno));
       return 0;
   }
   if (grantpt(ptm) < 0) {
       dropbear_log(LOG_WARNING, "grantpt: %.100s", strerror(errno));
       return 0;
   }
   if (unlockpt(ptm) < 0) {
       dropbear_log(LOG_WARNING, "unlockpt: %.100s", strerror(errno));
       return 0;
   }
   pts = ptsname(ptm);
   if (pts == NULL) {
       dropbear_log(LOG_WARNING, "Slave pty side name could not be obtained.");
       return 0;
   }
   strlcpy(namebuf, pts, namebuflen);
   *ptyfd = ptm;

   /* Open the slave side. */
   *ttyfd = open(namebuf, O_RDWR | O_NOCTTY);
   if (*ttyfd < 0) {
       dropbear_log(LOG_ERR, "error opening pts %.100s: %.100s", namebuf, strerror(errno));
       close(*ptyfd);
       return 0;
   }
   return 1;
#else
   /* Fallback to other methods for non-Android platforms */
   #if defined(HAVE_OPENPTY)
      char *name;
      int i;

      i = openpty(ptyfd, ttyfd, NULL, NULL, NULL);
      if (i < 0) {
          dropbear_log(LOG_WARNING, "pty_allocate: openpty: %.100s", strerror(errno));
          return 0;
      }
      name = ttyname(*ttyfd);
      if (!name) {
          dropbear_exit("ttyname fails for openpty device");
      }

      strlcpy(namebuf, name, namebuflen);  /* possible truncation */
      return 1;
   #else
      #ifdef HAVE__GETPTY
         char *slave;

         slave = _getpty(ptyfd, O_RDWR, 0622, 0);
         if (slave == NULL) {
             dropbear_log(LOG_WARNING, "pty_allocate: _getpty: %.100s", strerror(errno));
             return 0;
         }
         strlcpy(namebuf, slave, namebuflen);
         *ttyfd = open(namebuf, O_RDWR | O_NOCTTY);
         if (*ttyfd < 0) {
             dropbear_log(LOG_WARNING, "pty_allocate error: ttyfd open error");
             close(*ptyfd);
             return 0;
         }
         return 1;
      #else
         dropbear_log(LOG_WARNING, "No supported pty allocation method found.");
         return 0;
      #endif
   #endif
#endif
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

void
pty_release(const char *tty_name)
{
   if (chown(tty_name, (uid_t) 0, (gid_t) 0) < 0 && (errno != ENOENT)) {
       dropbear_log(LOG_WARNING, "chown %.100s failed: %.100s", tty_name, strerror(errno));
   }
   if (chmod(tty_name, (mode_t) 0666) < 0 && (errno != ENOENT)) {
       dropbear_log(LOG_WARNING, "chmod %.100s 0666 failed: %.100s", tty_name, strerror(errno));
   }
}

/* Makes the tty the processes controlling tty and sets it to sane modes. */

void
pty_make_controlling_tty(int *ttyfd, const char *tty_name)
{
   int fd;

   /* First disconnect from the old controlling tty. */
   signal(SIGTTOU, SIG_IGN);

   /* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
   fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
   if (fd >= 0) {
       (void) ioctl(fd, TIOCNOTTY, NULL);
       close(fd);
   }
#endif
   if (setsid() < 0) {
       dropbear_log(LOG_ERR, "setsid: %.100s", strerror(errno));
   }

   fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
   if (fd >= 0) {
       dropbear_log(LOG_ERR, "Failed to disconnect from controlling tty.\n");
       close(fd);
   }

   /* Make it our controlling tty. */
#ifdef TIOCSCTTY
   if (ioctl(*ttyfd, TIOCSCTTY, NULL) < 0) {
       dropbear_log(LOG_ERR, "ioctl(TIOCSCTTY): %.100s", strerror(errno));
   }
#endif

   fd = open(tty_name, O_RDWR);
   if (fd < 0) {
       dropbear_log(LOG_ERR, "%.100s: %.100s", tty_name, strerror(errno));
   } else {
       close(fd);
   }
}

/* Changes the window size associated with the pty. */

void
pty_change_window_size(int ptyfd, int row, int col, int xpixel, int ypixel)
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

   /* Determine the group to make the owner of the tty. */
   grp = getgrnam("tty");
   if (grp) {
       gid = grp->gr_gid;
       mode = S_IRUSR | S_IWUSR | S_IWGRP;
   } else {
       gid = pw->pw_gid;
       mode = S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH;
   }

   if (stat(tty_name, &st)) {
       dropbear_exit("pty_setowner: stat(%.101s) failed: %.100s", tty_name, strerror(errno));
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
