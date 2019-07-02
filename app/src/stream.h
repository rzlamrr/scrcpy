#ifndef STREAM_H
#define STREAM_H

#include <stdbool.h>
#include <stdint.h>
#include <libavformat/avformat.h>
#include <SDL2/SDL_atomic.h>
#include <SDL2/SDL_thread.h>

#include "net.h"

struct video_buffer;

struct packet_header {
    uint64_t pts;
    uint32_t len;
};

struct stream {
    socket_t socket;
    struct video_buffer *video_buffer;
    SDL_Thread *thread;
    SDL_atomic_t stopped;
    struct decoder *decoder;
    struct recorder *recorder;
    AVCodecContext *codec_ctx;
    AVCodecParserContext *parser;
    struct receiver_state {
        struct packet_header packet_header;
        size_t remaining; // remaining bytes to receive on the socket for the current packet
    } receiver_state;
};

void
stream_init(struct stream *stream, socket_t socket,
            struct decoder *decoder, struct recorder *recorder);

bool
stream_start(struct stream *stream);

void
stream_stop(struct stream *stream);

void
stream_join(struct stream *stream);

#endif
