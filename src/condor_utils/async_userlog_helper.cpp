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

#include <map>
#include <string>

#include <linux/falloc.h>

#if !defined(SEEK_DATA)
#define SEEK_DATA 3
#endif

struct CachedLog {
	int fd = -1;
	std::string path;
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;
};

static mode_t
parse_octal_mode(const std::string &text, mode_t fallback)
{
	char *end = nullptr;
	long value = strtol(text.c_str(), &end, 8);
	if (!end || *end != '\0' || value < 0) {
		return fallback;
	}
	return (mode_t)value;
}

static bool
lookup_required_string(classad::ClassAd &ad, const char *attr, std::string &value)
{
	if (!ad.LookupString(attr, value) || value.empty()) {
		dprintf(D_ALWAYS, "async user log helper: missing or empty %s\n", attr);
		return false;
	}
	return true;
}

static bool
lookup_required_int(classad::ClassAd &ad, const char *attr, long long &value)
{
	if (!ad.LookupInteger(attr, value)) {
		dprintf(D_ALWAYS, "async user log helper: missing or invalid %s\n", attr);
		return false;
	}
	return true;
}

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
ensure_parent_dir(const std::string &path, mode_t mode, uid_t uid, gid_t gid)
{
	size_t pos = path.find_last_of("/\\");
	if (pos == std::string::npos) {
		return true;
	}
	std::string dir = path.substr(0, pos);
	if (dir.empty()) {
		return true;
	}
	uid_t old_uid = 0;
	gid_t old_gid = 0;
	if (!switch_identity(uid, gid, old_uid, old_gid)) {
		return false;
	}
	bool ok = mkdir_and_parents_if_needed(dir.c_str(), mode, PRIV_UNKNOWN);
	restore_identity(old_uid, old_gid);
	if (!ok) {
		dprintf(D_ALWAYS, "async user log helper: failed to create directory %s: errno %d (%s)\n",
			dir.c_str(), errno, strerror(errno));
	}
	return ok;
}

static bool
open_target(CachedLog &log, mode_t create_mode, mode_t dir_mode)
{
	if (log.fd >= 0) {
		return true;
	}
	if (!ensure_parent_dir(log.path, dir_mode, log.uid, log.gid)) {
		return false;
	}
	uid_t old_uid = 0;
	gid_t old_gid = 0;
	if (!switch_identity(log.uid, log.gid, old_uid, old_gid)) {
		return false;
	}
	log.fd = safe_open_wrapper_follow(log.path.c_str(),
		O_WRONLY | O_CREAT | O_APPEND, create_mode);
	restore_identity(old_uid, old_gid);
	if (log.fd < 0) {
		dprintf(D_ALWAYS, "async user log helper: open(%s) failed: errno %d (%s)\n",
			log.path.c_str(), errno, strerror(errno));
		return false;
	}
	return true;
}

static bool
process_command(const std::string &line, std::map<std::string, CachedLog> &logs)
{
	classad::ClassAd ad;
	classad::ClassAdJsonParser parser;
	if (!parser.ParseClassAd(line, ad, true)) {
		dprintf(D_ALWAYS, "async user log helper: malformed command JSON\n");
		return false;
	}

	long long version = 0;
	long long uid = -1;
	long long gid = -1;
	std::string log_id;
	std::string op;
	std::string path;
	if (!lookup_required_int(ad, "Version", version) || version != 1 ||
		!lookup_required_string(ad, "LogId", log_id) ||
		!lookup_required_string(ad, "Op", op) ||
		!lookup_required_string(ad, "Path", path) ||
		!lookup_required_int(ad, "Uid", uid) ||
		!lookup_required_int(ad, "Gid", gid)) {
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
	if (op != "open" && op != "close" && op != "write") {
		dprintf(D_ALWAYS, "async user log helper: invalid Op %s\n", op.c_str());
		return false;
	}

	if (op == "close") {
		auto it = logs.find(log_id);
		if (it != logs.end()) {
			if (it->second.fd >= 0) {
				close(it->second.fd);
			}
			logs.erase(it);
		}
		return true;
	}

	std::string create_mode_text = "0664";
	std::string dir_mode_text = "0755";
	ad.LookupString("CreateMode", create_mode_text);
	ad.LookupString("DirMode", dir_mode_text);
	mode_t create_mode = parse_octal_mode(create_mode_text, 0664);
	mode_t dir_mode = parse_octal_mode(dir_mode_text, 0755);

	CachedLog &log = logs[log_id];
	log.path = path;
	log.uid = (uid_t)uid;
	log.gid = (gid_t)gid;

	if (op == "open") {
		return open_target(log, create_mode, dir_mode);
	}
	if (op == "write") {
		std::string payload;
		bool fsync = false;
		if (!ad.LookupString("Payload", payload)) {
			dprintf(D_ALWAYS, "async user log helper: write missing Payload\n");
			return false;
		}
		ad.LookupBool("Fsync", fsync);
		if (!open_target(log, create_mode, dir_mode)) {
			return false;
		}
		if (write(log.fd, payload.data(), payload.length()) != (ssize_t)payload.length()) {
			dprintf(D_ALWAYS, "async user log helper: write(%s) failed: errno %d (%s)\n",
				log.path.c_str(), errno, strerror(errno));
			return false;
		}
		if (fsync && condor_fdatasync(log.fd, log.path.c_str()) != 0) {
			dprintf(D_ALWAYS, "async user log helper: fsync(%s) failed: errno %d (%s)\n",
				log.path.c_str(), errno, strerror(errno));
			return false;
		}
		return true;
	}
	return false;
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

static bool
commit_command_offset(int fd, const char *command_path, off_t offset)
{
	if (offset <= 0) {
		return true;
	}
	if (fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 0, offset) < 0) {
		dprintf(D_ALWAYS, "async user log helper: failed to punch command-file hole through offset %lld: errno %d (%s)\n",
			(long long)offset, errno, strerror(errno));
		return false;
	}
	if (condor_fdatasync(fd, command_path) != 0) {
		dprintf(D_ALWAYS, "async user log helper: failed to fsync command file %s after hole punch: errno %d (%s)\n",
			command_path, errno, strerror(errno));
		return false;
	}
	return true;
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

	std::map<std::string, CachedLog> logs;
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
			process_command(line, logs);
			commit_command_offset(fd, command_path, offset);
		}
	}

	for (auto &entry : logs) {
		if (entry.second.fd >= 0) {
			close(entry.second.fd);
		}
	}
	close(fd);
	return 0;
}
