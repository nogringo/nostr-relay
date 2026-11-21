#include <unistd.h>

#include "RelayServer.h"


static constexpr size_t BACKUP_CHUNK_SIZE = 1 << 20;
static constexpr uint64_t BACKUP_MAX_IN_FLIGHT = 8 << 20;

// Streams a compacted copy of the LMDB file to the websocket thread, no faster than the client reads it
void RelayServer::streamBackup(uint64_t backupId, std::shared_ptr<BackupStream> stream) {
    auto finish = [this, backupId](bool ok, uint64_t size) {
        backupRunning = false;
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::BackupDone{backupId, ok, size}});
        hubTrigger->send();
    };

    int fds[2];

    if (::pipe(fds)) {
        LE << "Backup failed: pipe(): " << strerror(errno);
        finish(false, 0);
        return;
    }

    std::thread([this, stream, finish, backupId, readFd = fds[0], writeFd = fds[1]]{
        bool copied = false;

        // Once readFd is closed, the copy fails with EPIPE (SIGPIPE is ignored)
        std::thread copier([&]{
            try {
                env.copy_fd(writeFd);
                copied = true;
            } catch (std::exception &e) {
                LW << "Backup copy stopped: " << e.what();
            }

            ::close(writeFd);
        });

        int readError = 0;
        bool cancelled = false;
        uint64_t size = 0;

        while (!readError) {
            std::string chunk(BACKUP_CHUNK_SIZE, '\0');
            size_t filled = 0;
            bool eof = false;

            while (filled < chunk.size()) {
                auto n = ::read(readFd, chunk.data() + filled, chunk.size() - filled);

                if (n > 0) filled += n;
                else if (n == 0) eof = true;
                else if (errno != EINTR) readError = errno;

                if (eof || readError) break;
            }

            if (filled) {
                std::unique_lock lock(stream->mutex);
                stream->cv.wait(lock, [&]{ return stream->cancelled || stream->inFlight < BACKUP_MAX_IN_FLIGHT; });
                cancelled = stream->cancelled;
                if (cancelled) break;
                stream->inFlight += filled;
                lock.unlock();

                chunk.resize(filled);
                size += filled;

                tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::BackupChunk{backupId, std::move(chunk)}});
                hubTrigger->send();
            }

            if (eof) break;
        }

        if (readError) LE << "Backup failed: read(): " << strerror(readError);

        ::close(readFd);
        copier.join();

        finish(copied && !readError && !cancelled, size);
    }).detach();
}
