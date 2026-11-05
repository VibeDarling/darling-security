// Permanent privilege drop for the tokend child. Kept in a header so a host
// test can interpose setuid/setgid and run the same code.
#ifndef _H_TOKEND_PRIVDROP
#define _H_TOKEND_PRIVDROP

#include <cerrno>
#include <unistd.h>

// Returns 0 on success or an errno value. Never best effort: a root process
// must end up with the requested real/effective uid and gid, otherwise this
// reports failure. Supplementary groups are not cleared.
// A process that is not root holds no privilege to relinquish.
inline int tokendDropPrivileges(uid_t uid, gid_t gid)
{
	if (::geteuid() != 0)
		return 0;
	if (::setgid(gid) != 0)
		return errno;
	if (::setuid(uid) != 0)
		return errno;
	if (::getuid() != uid || ::geteuid() != uid || ::getgid() != gid || ::getegid() != gid)
		return EPERM;
	return 0;
}

#endif // _H_TOKEND_PRIVDROP
