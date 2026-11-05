// Host test for tokendDropPrivileges(); setuid/setgid/get*id are replaced by
// fakes, so no privilege is needed. Build and run:
//   c++ -std=c++11 -Wall -I../src tokend_privdrop_test.cpp -o t && ./t
#include "tokend_privdrop.h"
#include <cstdio>

static uid_t fUid, fEuid;
static gid_t fGid, fEgid;
static int failSetuid, failSetgid, noopSet, calls;

extern "C" {
uid_t geteuid(void) { return fEuid; }
uid_t getuid(void) { return fUid; }
gid_t getgid(void) { return fGid; }
gid_t getegid(void) { return fEgid; }
int setgid(gid_t g) { calls++; if (failSetgid) { errno = EPERM; return -1; } if (!noopSet) fGid = fEgid = g; return 0; }
int setuid(uid_t u) { calls++; if (failSetuid) { errno = EPERM; return -1; } if (!noopSet) fUid = fEuid = u; return 0; }
}

static int bad;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); bad++; } } while (0)

static void reset(uid_t u)
{
	fUid = fEuid = u; fGid = fEgid = 0;
	failSetuid = failSetgid = noopSet = calls = 0;
}

int main()
{
	reset(0);
	CHECK(tokendDropPrivileges(77, 88) == 0);
	CHECK(fUid == 77 && fEuid == 77 && fGid == 88 && fEgid == 88);

	reset(0); failSetuid = 1;
	CHECK(tokendDropPrivileges(77, 88) == EPERM);

	reset(0); failSetgid = 1;
	CHECK(tokendDropPrivileges(77, 88) == EPERM);
	CHECK(calls == 1);			// uid is not touched after a failed gid drop

	reset(0); noopSet = 1;		// calls succeed but the ids did not change
	CHECK(tokendDropPrivileges(77, 88) == EPERM);

	reset(500);					// not root: nothing to relinquish
	CHECK(tokendDropPrivileges(77, 88) == 0);
	CHECK(calls == 0);

	puts(bad ? "FAILED" : "ok");
	return bad != 0;
}
