#include <sys/socket.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
parent(int sock)
{
	int		 fd;
	char		 data = 'X';
	struct msghdr	 msg;
	struct cmsghdr	*cmsg;
	union {
		struct cmsghdr	 hdr;
		unsigned char	 buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct iovec iov[1];
	int i;

	for (i = 0; i < 1000000; ++i) {
		if ((fd = open("/dev/null", O_RDONLY)) == -1)
			err(1, "parent: open /dev/null");

		iov[0].iov_base = &data;
		iov[0].iov_len = 1;

		memset(&msg, 0, sizeof(msg));
		msg.msg_control = &cmsgbuf.buf;
		msg.msg_controllen = sizeof(cmsgbuf.buf);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		*(int *)CMSG_DATA(cmsg) = fd;

		fprintf(stderr, "parent: sending %d\n", fd);
		if (sendmsg(sock, &msg, 0) == -1)
			err(1, "parent:sendmsg");
		close(fd);
	}

	return 0;
}

int
child(int sock)
{
	int		 fd;
	char		 data;
	struct msghdr	 msg;
	struct cmsghdr	*cmsg;
	union {
		struct cmsghdr	 hdr;
		unsigned char	 buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct iovec iov[1];
	ssize_t n;

	for (;;) {
		iov[0].iov_base = &data;
		iov[0].iov_len = 1;

		memset(&msg, 0, sizeof(msg));
		msg.msg_control = &cmsgbuf.buf;
		msg.msg_controllen = sizeof(cmsgbuf.buf);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;

		if ((n = recvmsg(sock, &msg, 0)) == -1)
			err(1, "child: recvmsg");
		if (n == 0)
			errx(0, "child: done!");
		if ((msg.msg_flags & MSG_TRUNC) ||
		    (msg.msg_flags & MSG_CTRUNC))
			errx(1, "child: control message truncated");
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
		     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
			    cmsg->cmsg_level == SOL_SOCKET &&
			    cmsg->cmsg_type == SCM_RIGHTS) {
				fd = *(int *)CMSG_DATA(cmsg);
				fprintf(stderr, "child: recv fd %d\n",
				    fd);
				close(fd);
			}
		}
	}
}

int
main(void)
{
	int	 p[2];
	pid_t	 pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, p) == -1)
		err(1, "socketpair");

	if ((pid = fork()) == -1)
		err(1, "fork");
	if (pid == 0) {
		close(p[0]);
		return child(p[1]);
	}

	close(p[1]);
	return parent(p[0]);
}
