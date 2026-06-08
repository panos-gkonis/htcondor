#include "condor_common.h"
#include "condor_config.h"
#include "condor_debug.h"
#include "condor_open.h"
#include "condor_fsync.h"
#include "condor_uid.h"
#include "directory.h"
#include "subsystem_info.h"
#include "basename.h"

#include <string>
#include <limits>
#include <map>

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

class UserLogFdCache
{
public:
	UserLogFdCache(uid_t uid, gid_t gid) {
		m_switched = switch_identity(uid, gid, m_old_uid, m_old_gid);
	}

	~UserLogFdCache() {
		closeAll();
		if (m_switched) {
			restore_identity(m_old_uid, m_old_gid);
		}
	}

	bool writeTarget(const std::string &path, const std::string &payload) {
		if (!m_switched) {
			return false;
		}

		int fd = getFd(path);
		if (fd < 0) {
			return false;
		}
		ssize_t written = write(fd, payload.data(), payload.length());
		if (written != (ssize_t)payload.length()) {
			if (written < 0) {
				dprintf(D_ALWAYS, "async user log helper: write(%s) failed: errno %d (%s)\n",
					path.c_str(), errno, strerror(errno));
			} else {
				dprintf(D_ALWAYS, "async user log helper: partial write(%s): wrote %lld of %lld bytes\n",
					path.c_str(), (long long)written, (long long)payload.length());
			}
			return false;
		}
		return true;
	}

private:
	int getFd(const std::string &path) {
		auto it = m_fds.find(path);
		if (it != m_fds.end()) {
			return it->second;
		}

		if (!ensure_parent_dir(path, 0755)) {
			return -1;
		}
		int fd = safe_open_wrapper_follow(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0664);
		if (fd < 0) {
			dprintf(D_ALWAYS, "async user log helper: open(%s) failed: errno %d (%s)\n",
				path.c_str(), errno, strerror(errno));
			return -1;
		}
		m_fds[path] = fd;
		return fd;
	}

	void closeAll() {
		for (auto &entry: m_fds) {
			if (close(entry.second) != 0) {
				dprintf(D_ALWAYS, "async user log helper: close(%s) failed: errno %d (%s)\n",
					entry.first.c_str(), errno, strerror(errno));
			}
		}
		m_fds.clear();
	}

	bool m_switched = false;
	uid_t m_old_uid = 0;
	gid_t m_old_gid = 0;
	std::map<std::string, int> m_fds;
};

static bool
parse_command_filename(const char *name, uid_t &uid, gid_t &gid)
{
	errno = 0;
	char *end = nullptr;
	unsigned long long uid_value = strtoull(name, &end, 10);
	if (errno != 0 || end == name || *end != '-') {
		return false;
	}

	const char *gid_start = end + 1;
	if (*gid_start == '\0') {
		return false;
	}
	errno = 0;
	unsigned long long gid_value = strtoull(gid_start, &end, 10);
	if (errno != 0 || *end != '\0') {
		return false;
	}
	if (uid_value > std::numeric_limits<uid_t>::max() ||
		gid_value > std::numeric_limits<gid_t>::max()) {
		return false;
	}

	uid = (uid_t)uid_value;
	gid = (gid_t)gid_value;
	return true;
}

static bool
process_command(const std::string &record, UserLogFdCache &fd_cache)
{
	size_t newline = record.find('\n');
	if (newline == std::string::npos) {
		dprintf(D_ALWAYS, "async user log helper: malformed command missing path delimiter\n");
		return false;
	}
	std::string path = record.substr(0, newline);
	if (!fullpath(path.c_str())) {
		dprintf(D_ALWAYS, "async user log helper: Path is not absolute: %s\n", path.c_str());
		return false;
	}

	std::string payload = record.substr(newline + 1);
	return fd_cache.writeTarget(path, payload);
}

static off_t
find_first_command_offset(int fd)
{
	off_t data_offset = lseek(fd, 0, SEEK_DATA);
	if (data_offset >= 0) {
		return data_offset;
	}
	if (errno == ENXIO) {
		off_t end = lseek(fd, 0, SEEK_END);
		return end < 0 ? 0 : end;
	}
	if (errno != EINVAL) {
		dprintf(D_ALWAYS, "async user log helper: SEEK_DATA failed: errno %d (%s)\n",
			errno, strerror(errno));
	}
	return 0;
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

static bool
process_command_bunch(const std::string &buffer, uid_t uid, gid_t gid,
	size_t &commit_length)
{
	commit_length = 0;
	// This is an optimistic batch, not a stable snapshot: process all complete
	// records that were readable before EOF, including records appended while
	// this scan was in progress.
	size_t last_terminator = buffer.find_last_of('\0');
	if (last_terminator == std::string::npos) {
		return true;
	}

	size_t cursor = 0;
	size_t process_length = last_terminator + 1;
	UserLogFdCache fd_cache(uid, gid);
	while (cursor < process_length) {
		size_t record_start = buffer.find_first_not_of('\0', cursor);
		if (record_start == std::string::npos || record_start >= process_length) {
			commit_length = process_length;
			return true;
		}

		size_t record_end = buffer.find('\0', record_start);
		if (record_end == std::string::npos || record_end >= process_length) {
			return true;
		}

		bool ok = process_command(buffer.substr(record_start, record_end - record_start),
			fd_cache);
		commit_length = record_end + 1;
		if (!ok) {
			return false;
		}
		cursor = record_end + 1;
	}
	return true;
}

static bool
process_command_file(const char *command_path, uid_t uid, gid_t gid)
{
	priv_state priv = set_condor_priv();
	int fd = safe_open_wrapper_follow(command_path, O_RDWR);
	set_priv(priv);
	if (fd < 0) {
		dprintf(D_ALWAYS, "async user log helper: failed to open command file %s: errno %d (%s)\n",
			command_path, errno, strerror(errno));
		return false;
	}

	off_t offset = find_first_command_offset(fd);
	if (lseek(fd, offset, SEEK_SET) < 0) {
		dprintf(D_ALWAYS, "async user log helper: failed to seek command file %s to offset %lld: errno %d (%s)\n",
			command_path, (long long)offset, errno, strerror(errno));
		close(fd);
		return false;
	}

	bool ok = true;
	std::string buffer;
	char chunk[8192];
	while (true) {
		ssize_t n = read(fd, chunk, sizeof(chunk));
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			dprintf(D_ALWAYS, "async user log helper: read(%s) failed: errno %d (%s)\n",
				command_path, errno, strerror(errno));
			ok = false;
			break;
		}
		if (n == 0) {
			break;
		}
		buffer.append(chunk, n);
	}

	size_t commit_length = 0;
	if (ok) {
		ok = process_command_bunch(buffer, uid, gid, commit_length);
		if (commit_length > 0) {
			priv = set_condor_priv();
			commit_command_offset(fd, command_path, offset + commit_length);
			set_priv(priv);
		}
	}

	close(fd);
	return ok;
}

static void
process_command_dir(const char *command_dir)
{
	Directory dir(command_dir, PRIV_CONDOR);
	const char *name = nullptr;
	while ((name = dir.Next())) {
		if (dir.IsDirectory() || dir.IsSymlink()) {
			continue;
		}

		uid_t uid = 0;
		gid_t gid = 0;
		if (!parse_command_filename(name, uid, gid)) {
			dprintf(D_FULLDEBUG, "async user log helper: ignoring command file with invalid name %s\n",
				name);
			continue;
		}

		process_command_file(dir.GetFullPath(), uid, gid);
	}
}

int
main(int argc, char **argv)
{
	set_mySubSystem("ASYNC_USERLOG_HELPER", false, SUBSYSTEM_TYPE_TOOL);
	config();

	if (argc != 2) {
		fprintf(stderr, "usage: %s <command-directory>\n", argv[0]);
		return 1;
	}
	const char *command_dir = argv[1];

	uid_t condor_uid = get_condor_uid();
	gid_t condor_gid = get_condor_gid();
	uid_t old_uid = 0;
	gid_t old_gid = 0;
	if (!switch_identity(condor_uid, condor_gid, old_uid, old_gid)) {
		return 1;
	}
	bool made_dir = mkdir_and_parents_if_needed(command_dir, 0755, PRIV_UNKNOWN);
	restore_identity(old_uid, old_gid);
	if (!made_dir) {
		fprintf(stderr, "failed to create %s: %s\n", command_dir, strerror(errno));
		return 1;
	}

	while (true) {
		process_command_dir(command_dir);
		sleep(1);
	}

	return 0;
}
