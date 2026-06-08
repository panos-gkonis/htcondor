#include "condor_common.h"
#include "condor_config.h"
#include "condor_debug.h"
#include "condor_open.h"
#include "condor_fsync.h"
#include "condor_uid.h"
#include "directory.h"
#include "subsystem_info.h"
#include "basename.h"
#include "classad/jsonSource.h"

#include <string>

#include <linux/falloc.h>

#if !defined(SEEK_DATA)
#define SEEK_DATA 3
#endif

static bool
switch_identity(uid_t uid, gid_t gid, uid_t &old_uid, gid_t &old_gid)
{
	old_uid = geteuid();
	old_gid = getegid();
	if (setegid(gid) != 0) {
		dprintf(D_ALWAYS, "async user log helper: setegid(%llu) failed: errno %d (%s)\n",
			(unsigned long long)gid, errno, strerror(errno));
		return false;
	}
	if (seteuid(uid) != 0) {
		dprintf(D_ALWAYS, "async user log helper: seteuid(%llu) failed: errno %d (%s)\n",
			(unsigned long long)uid, errno, strerror(errno));
		setegid(old_gid);
		return false;
	}
	return true;
}

static void
restore_identity(uid_t old_uid, gid_t old_gid)
{
	if (seteuid(old_uid) != 0) {
		dprintf(D_ALWAYS, "async user log helper: failed to restore uid %llu: errno %d (%s)\n",
			(unsigned long long)old_uid, errno, strerror(errno));
	}
	if (setegid(old_gid) != 0) {
		dprintf(D_ALWAYS, "async user log helper: failed to restore gid %llu: errno %d (%s)\n",
			(unsigned long long)old_gid, errno, strerror(errno));
	}
}

static bool
ensure_parent_dir(const std::string &path, mode_t mode)
{
	size_t pos = path.find_last_of("/\\");
	if (pos == std::string::npos) {
		return true;
	}
	std::string dir = path.substr(0, pos);
	if (dir.empty()) {
		return true;
	}
	bool ok = mkdir_and_parents_if_needed(dir.c_str(), mode, PRIV_UNKNOWN);
	if (!ok) {
		dprintf(D_ALWAYS, "async user log helper: failed to create directory %s: errno %d (%s)\n",
			dir.c_str(), errno, strerror(errno));
	}
	return ok;
}

static bool
write_target(const std::string &path, uid_t uid, gid_t gid, const std::string &payload)
{
	uid_t old_uid = 0;
	gid_t old_gid = 0;
	if (!switch_identity(uid, gid, old_uid, old_gid)) {
		return false;
	}
	if (!ensure_parent_dir(path, 0755)) {
		restore_identity(old_uid, old_gid);
		return false;
	}
	int fd = safe_open_wrapper_follow(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0664);

	if (fd < 0) {
		dprintf(D_ALWAYS, "async user log helper: open(%s) failed: errno %d (%s)\n",
			path.c_str(), errno, strerror(errno));
		restore_identity(old_uid, old_gid);
		return false;
	}

	bool ok = true;
	if (write(fd, payload.data(), payload.length()) != (ssize_t)payload.length()) {
		dprintf(D_ALWAYS, "async user log helper: write(%s) failed: errno %d (%s)\n",
			path.c_str(), errno, strerror(errno));
		ok = false;
	}
	if (close(fd) != 0) {
		dprintf(D_ALWAYS, "async user log helper: close(%s) failed: errno %d (%s)\n",
			path.c_str(), errno, strerror(errno));
		ok = false;
	}
	restore_identity(old_uid, old_gid);
	return ok;
}

static bool
process_command(const std::string &line)
{
	classad::ClassAd ad;
	classad::ClassAdJsonParser parser;
	if (!parser.ParseClassAd(line, ad, true)) {
		dprintf(D_ALWAYS, "async user log helper: malformed command JSON\n");
		return false;
	}

	long long uid = -1;
	long long gid = -1;
	std::string path;
	if (!ad.LookupString("Path", path) || path.empty()) {
		dprintf(D_ALWAYS, "async user log helper: missing or empty Path\n");
		return false;
	}
	if (!ad.LookupInteger("Uid", uid)) {
		dprintf(D_ALWAYS, "async user log helper: missing or invalid Uid\n");
		return false;
	}
	if (!ad.LookupInteger("Gid", gid)) {
		dprintf(D_ALWAYS, "async user log helper: missing or invalid Gid\n");
		return false;
	}
	if (!fullpath(path.c_str())) {
		dprintf(D_ALWAYS, "async user log helper: Path is not absolute: %s\n", path.c_str());
		return false;
	}
	if (uid < 0 || gid < 0) {
		dprintf(D_ALWAYS, "async user log helper: invalid uid/gid %lld/%lld\n", uid, gid);
		return false;
	}

	std::string payload;
	if (!ad.LookupString("Payload", payload)) {
		dprintf(D_ALWAYS, "async user log helper: write missing Payload\n");
		return false;
	}
	return write_target(path, (uid_t)uid, (gid_t)gid, payload);
}

static off_t
find_first_command_offset(int fd)
{
	off_t search_offset = 0;
	char chunk[8192];

	while (true) {
		off_t data_offset = lseek(fd, search_offset, SEEK_DATA);
		if (data_offset < 0) {
			if (errno == ENXIO) {
				off_t end = lseek(fd, 0, SEEK_END);
				return end < 0 ? 0 : end;
			}
			if (errno != EINVAL) {
				dprintf(D_ALWAYS, "async user log helper: SEEK_DATA failed: errno %d (%s)\n",
					errno, strerror(errno));
			}
			data_offset = search_offset;
		}
		if (lseek(fd, data_offset, SEEK_SET) < 0) {
			return 0;
		}
		ssize_t n = read(fd, chunk, sizeof(chunk));
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			dprintf(D_ALWAYS, "async user log helper: read while seeking command start failed: errno %d (%s)\n",
				errno, strerror(errno));
			return 0;
		}
		if (n == 0) {
			return data_offset;
		}
		for (ssize_t i = 0; i < n; ++i) {
			if (chunk[i] != '\0') {
				return data_offset + i;
			}
		}
		search_offset = data_offset + n;
	}
}

static void
commit_command_offset(int fd, const char *command_path, off_t offset)
{
	if (offset <= 0) {
		return;
	}
	if (fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 0, offset) < 0) {
		dprintf(D_ALWAYS, "async user log helper: failed to punch command-file hole through offset %lld: errno %d (%s)\n",
			(long long)offset, errno, strerror(errno));
		return;
	}
	if (condor_fdatasync(fd, command_path) != 0) {
		dprintf(D_ALWAYS, "async user log helper: failed to fsync command file %s after hole punch: errno %d (%s)\n",
			command_path, errno, strerror(errno));
	}
}

int
main(int argc, char **argv)
{
	set_mySubSystem("ASYNC_USERLOG_HELPER", false, SUBSYSTEM_TYPE_TOOL);
	config();

	if (argc != 2) {
		fprintf(stderr, "usage: %s <command-file>\n", argv[0]);
		return 1;
	}
	const char *command_path = argv[1];

	uid_t condor_uid = get_condor_uid();
	gid_t condor_gid = get_condor_gid();
	uid_t old_uid = 0;
	gid_t old_gid = 0;
	if (!switch_identity(condor_uid, condor_gid, old_uid, old_gid)) {
		return 1;
	}
	int fd = safe_open_wrapper_follow(command_path, O_RDWR | O_CREAT, 0664);
	restore_identity(old_uid, old_gid);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n", command_path, strerror(errno));
		return 1;
	}

	off_t offset = find_first_command_offset(fd);
	if (lseek(fd, offset, SEEK_SET) < 0) {
		offset = 0;
		lseek(fd, 0, SEEK_SET);
	}

	std::string buffer;
	char chunk[8192];
	while (true) {
		ssize_t n = read(fd, chunk, sizeof(chunk));
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			dprintf(D_ALWAYS, "async user log helper: read failed: errno %d (%s)\n",
				errno, strerror(errno));
			break;
		}
		if (n == 0) {
			sleep(1);
			continue;
		}
		buffer.append(chunk, n);
		size_t newline = std::string::npos;
		while ((newline = buffer.find('\n')) != std::string::npos) {
			std::string line = buffer.substr(0, newline);
			buffer.erase(0, newline + 1);
			offset += newline + 1;
			process_command(line);
			commit_command_offset(fd, command_path, offset);
		}
	}

	close(fd);
	return 0;
}
