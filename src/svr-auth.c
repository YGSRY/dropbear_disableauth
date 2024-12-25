/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

/* This file (auth.c) handles authentication requests, passing it to the
 * particular type (auth-passwd, auth-pubkey). */


#include "includes.h"
#include "dbutil.h"
#include "session.h"
#include "buffer.h"
#include "ssh.h"
#include "packet.h"
#include "auth.h"
#include "runopts.h"
#include "dbrandom.h"

static int checkusername(const char *username, unsigned int userlen);

/* initialise the first time for a session, resetting all parameters */
void svr_authinitialise() {
    memset(&ses.authstate, 0, sizeof(ses.authstate));
#if DROPBEAR_SVR_PUBKEY_AUTH
    ses.authstate.authtypes |= AUTH_TYPE_PUBKEY;
#endif
#if DROPBEAR_SVR_PASSWORD_AUTH || DROPBEAR_SVR_PAM_AUTH
    if (!svr_opts.noauthpass) {
        ses.authstate.authtypes |= AUTH_TYPE_PASSWORD;
    }
#endif
}

/* Send a banner message if specified to the client. The client might
 * ignore this, but possibly serves as a legal "no trespassing" sign */
void send_msg_userauth_banner(const buffer *banner) {

    TRACE(("enter send_msg_userauth_banner"))

    CHECKCLEARTOWRITE();

    buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_BANNER);
    buf_putbufstring(ses.writepayload, banner);
    buf_putstring(ses.writepayload, "en", 2);

    encrypt_packet();

    TRACE(("leave send_msg_userauth_banner"))
}

/* handle a userauth request, check validity, pass to password or pubkey
 * checking, and handle success or failure */
void recv_msg_userauth_request() {

    char *username = NULL, *servicename = NULL, *methodname = NULL;
    unsigned int userlen, servicelen, methodlen;

    TRACE(("enter recv_msg_userauth_request"))

    /* Directly skip all authentication logic and send success message */
    if (ses.authstate.authdone == 1) {
        TRACE(("leave recv_msg_userauth_request: authdone already"))
        return;
    }

    /* Send the banner if it exists */
    if (svr_opts.banner) {
        send_msg_userauth_banner(svr_opts.banner);
        buf_free(svr_opts.banner);
        svr_opts.banner = NULL;
    }

    /* Read the username, servicename, and methodname */
    username = buf_getstring(ses.payload, &userlen);
    servicename = buf_getstring(ses.payload, &servicelen);
    methodname = buf_getstring(ses.payload, &methodlen);

    /* Check that the service is 'ssh-connection', else exit */
    if (servicelen != SSH_SERVICE_CONNECTION_LEN
            && (strncmp(servicename, SSH_SERVICE_CONNECTION, SSH_SERVICE_CONNECTION_LEN) != 0)) {
        m_free(username);
        m_free(servicename);
        m_free(methodname);
        dropbear_exit("unknown service in auth");
    }

    /* Directly send success message, bypassing all checks */
    send_msg_userauth_success();

    m_free(username);
    m_free(servicename);
    m_free(methodname);
}

/* Send a failure message to the client, in responds to a userauth_request. */
void send_msg_userauth_failure(int partial, int incrfail) {

    buffer *typebuf = NULL;

    TRACE(("enter send_msg_userauth_failure"))

    CHECKCLEARTOWRITE();
    
    buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_FAILURE);

    /* Put a list of allowed types */
    typebuf = buf_new(30); /* long enough for PUBKEY and PASSWORD */

    if (ses.authstate.authtypes & AUTH_TYPE_PUBKEY) {
        buf_putbytes(typebuf, (const unsigned char *)AUTH_METHOD_PUBKEY, AUTH_METHOD_PUBKEY_LEN);
        if (ses.authstate.authtypes & AUTH_TYPE_PASSWORD) {
            buf_putbyte(typebuf, ',');
        }
    }
    
    if (ses.authstate.authtypes & AUTH_TYPE_PASSWORD) {
        buf_putbytes(typebuf, (const unsigned char *)AUTH_METHOD_PASSWORD, AUTH_METHOD_PASSWORD_LEN);
    }

    buf_putbufstring(ses.writepayload, typebuf);

    TRACE(("auth fail: methods %d, '%.*s'", ses.authstate.authtypes,
                typebuf->len, typebuf->data))

    buf_free(typebuf);

    buf_putbyte(ses.writepayload, partial ? 1 : 0);
    encrypt_packet();

    if (incrfail) {
        /* The SSH_MSG_AUTH_FAILURE response is delayed to attempt to
        avoid user enumeration and slow brute force attempts. */
        const unsigned int mindelay = 250000000;
        const unsigned int vardelay = 100000000;
        suseconds_t rand_delay;
        struct timespec delay;

        gettime_wrapper(&delay);
        delay.tv_sec -= ses.authstate.auth_starttime.tv_sec;
        delay.tv_nsec -= ses.authstate.auth_starttime.tv_nsec;

        /* Carry */
        if (delay.tv_nsec < 0) {
            delay.tv_nsec += 1000000000;
            delay.tv_sec -= 1;
        }

        genrandom((unsigned char*)&rand_delay, sizeof(rand_delay));
        rand_delay = mindelay + (rand_delay % vardelay);

        if (delay.tv_sec == 0 && delay.tv_nsec <= mindelay) {
            /* Compensate for elapsed time */
            delay.tv_nsec = rand_delay - delay.tv_nsec;
        } else {
            /* No time left or time went backwards, just delay anyway */
            delay.tv_sec = 0;
            delay.tv_nsec = rand_delay;
        }

        while (nanosleep(&delay, &delay) == -1 && errno == EINTR) { /* Go back to sleep */ }
        ses.authstate.failcount++;
    }

    if (ses.authstate.failcount >= svr_opts.maxauthtries) {
        char * userstr;
        /* XXX - send disconnect ? */
        TRACE(("Max auth tries reached, exiting"))

        if (ses.authstate.pw_name == NULL) {
            userstr = "is invalid";
        } else {
            userstr = ses.authstate.pw_name;
        }
        dropbear_exit("Max auth tries reached - user '%s'",
                userstr);
    }
    
    TRACE(("leave send_msg_userauth_failure"))
}

/* Send a success message to the user, and set the "authdone" flag */
void send_msg_userauth_success() {

    TRACE(("enter send_msg_userauth_success"))

    CHECKCLEARTOWRITE();

    buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_SUCCESS);
    encrypt_packet();

    /* authdone must be set after encrypt_packet() for delayed-zlib mode */
    ses.authstate.authdone = 1;
    ses.connect_time = 0;


    if (ses.authstate.pw_uid == 0) {
        ses.allowprivport = 1;
    }

    /* Remove from the list of pre-auth sockets. Should be m_close(), since if
     * we fail, we might end up leaking connection slots, and disallow new
     * logins - a nasty situation. */							
    m_close(svr_ses.childpipe);

    TRACE(("leave send_msg_userauth_success"))
}
