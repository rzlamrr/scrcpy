#include "stream.h"

#include <libavformat/avformat.h>
#include <libavutil/time.h>
#include <SDL2/SDL_assert.h>
#include <SDL2/SDL_events.h>
#include <SDL2/SDL_mutex.h>
#include <SDL2/SDL_thread.h>
#include <unistd.h>

#include "compat.h"
#include "config.h"
#include "buffer_util.h"
#include "decoder.h"
#include "events.h"
#include "lock_util.h"
#include "log.h"
#include "recorder.h"

#define BUFSIZE 0x10000
#define HEADER_SIZE 12
#define NO_PTS UINT64_C(-1)

struct packet_header {
    uint64_t pts;
    uint32_t len;
};

static inline bool
parse_packet(struct stream *stream, uint8_t **poutbuf, int *poutbuf_size,
             const uint8_t *buf, int buf_size) {
    size_t offset = 0;
    while (offset < buf_size) {
        int len = av_parser_parse2(stream->parser, stream->codec_ctx,
                                   poutbuf, poutbuf_size,
                                   &buf[offset], buf_size - offset,
                                   AV_NOPTS_VALUE, AV_NOPTS_VALUE, -1);
        SDL_assert(len);
        offset += len;
        if (*poutbuf_size) {
            // the whole buffer should have been consumed
            SDL_assert(offset == buf_size);
            return true;
        }
    }
    return false;
}

static bool
read_packet_header(socket_t socket, struct frame_header *header) {
    // The video stream contains raw packets, without time information. When we
    // record, we retrieve the timestamps separately, from a "meta" header
    // added by the server before each raw packet.
    //
    // The "meta" header length is 12 bytes:
    // [. . . . . . . .|. . . .]. . . . . . . . . . . . . . . ...
    //  <-------------> <-----> <-----------------------------...
    //        PTS        packet        raw packet
    //                    size
    //
    // It is followed by <packet_size> bytes containing the packet/frame.

    uint8_t buf[HEADER_SIZE];
    ssize_t r = net_recv_all(socket, buf, HEADER_SIZE);
    if (r < HEADER_SIZE) {
        LOGE("Unexpected end of stream on frame header");
        return false;
    }

    header->pts = buffer_read64be(buf);
    header->len = buffer_read32be(&buf[8]);
    return true;
}

static bool
read_packet(struct stream *stream, AVPacket *packet) {
    struct receiver_state *state = &stream->receiver_state;

    if (!state->remaining &&
            !read_packet_header(stream->socket, &state->packet_header)) {
        LOGE("Could not read packet header");
        return false;
    }
}

static bool
read_raw_packet(struct stream *stream, const struct frame_header *header,
                AVPacket *packet) {
#define PACKET_BUF_SIZE 0x10000
    // offset of the buffer relative to the whole packet
    size_t packet_offset = 0;

    LOGD("packet len: %d", (int) header->len);

    while (packet_offset < header->len) {
        uint8_t buf[PACKET_BUF_SIZE];
        size_t buf_size = header->len - packet_offset;
        if (buf_size > PACKET_BUF_SIZE) {
            buf_size = PACKET_BUF_SIZE;
        }
<
        ssize_t r = net_recv(stream->socket, buf, buf_size);
        if (r <= 0) {
            LOGE("Unexpected end of stream");
            return false;
        }
        packet_offset += r;

        LOGD("received: %d", (int) r);

        bool complete =
            parse_packet(stream, &packet->data, &packet->size, buf, r);
        // we should receive a complete AVPacket only if we injected the whole
        // buffer
        LOGD("%d %d %d", (int)complete, (int)packet_offset, (int)header->len);

        SDL_assert(complete == (packet_offset == header->len));
        if (complete) {
            packet->pts = header->pts;
            packet->dts = header->pts;
            return true;
        }
    }

    return false;
}

static bool
read_packet(struct stream *stream, AVPacket *packet) {
    struct frame_header header;

    // TODO concat first packet
    if (!read_packet_header(stream, &header)) {
        return false;
    }

    if (!read_raw_packet(stream, &header, packet)) {
        return false;
    }

    if (header.len == 27) {
        if (!read_packet_header(stream, &header)) {
            return false;
        }

        //header.len += 27;

        if (!read_raw_packet(stream, &header, packet)) {
            return false;
        }
        
    }

    return true;
}

static void
notify_stopped(void) {
    SDL_Event stop_event;
    stop_event.type = EVENT_STREAM_STOPPED;
    SDL_PushEvent(&stop_event);
}

static int
run_stream(void *data) {
    struct stream *stream = data;

    AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    if (!codec) {
        LOGE("H.264 decoder not found");
        goto end;
    }

    stream->codec_ctx = avcodec_alloc_context3(codec);
    if (!stream->codec_ctx) {
        LOGC("Could not allocate codec context");
        goto end;
    }

    if (stream->decoder && !decoder_open(stream->decoder, codec)) {
        LOGE("Could not open decoder");
        goto finally_free_codec_ctx;
    }

    if (stream->recorder && !recorder_open(stream->recorder, codec)) {
        LOGE("Could not open recorder");
        goto finally_close_decoder;
    }

    AVPacket packet;
    av_init_packet(&packet);
    packet.data = NULL;
    packet.size = 0;

    stream->parser = av_parser_init(AV_CODEC_ID_H264);
    stream->parser->flags |= PARSER_FLAG_COMPLETE_FRAMES;
    SDL_assert(stream->parser);

    while (!read_packet(stream, &packet)) {
        if (SDL_AtomicGet(&stream->stopped)) {
            // if the stream is stopped, the socket had been shutdown, so the
            // last packet is probably corrupted (but not detected as such by
            // FFmpeg) and will not be decoded correctly
            av_packet_unref(&packet);
            goto quit;
        }
        if (stream->decoder && !decoder_push(stream->decoder, &packet)) {
            av_packet_unref(&packet);
            goto quit;
        }

        if (stream->recorder) {
            // no need to rescale with av_packet_rescale_ts(), the timestamps
            // are in microseconds both in input and output
            if (!recorder_write(stream->recorder, &packet)) {
                LOGE("Could not write frame to output file");
                av_packet_unref(&packet);
                goto quit;
            }
        }

        av_packet_unref(&packet);
    }

    LOGD("End of frames");

quit:
    if (stream->recorder) {
        recorder_close(stream->recorder);
    }
finally_close_decoder:
    if (stream->decoder) {
        decoder_close(stream->decoder);
    }
finally_free_codec_ctx:
    avcodec_free_context(&stream->codec_ctx);
end:
    notify_stopped();
    return 0;
}

void
stream_init(struct stream *stream, socket_t socket,
            struct decoder *decoder, struct recorder *recorder) {
    stream->socket = socket;
    stream->decoder = decoder,
    stream->recorder = recorder;
    SDL_AtomicSet(&stream->stopped, 0);
}

bool
stream_start(struct stream *stream) {
    LOGD("Starting stream thread");

    stream->thread = SDL_CreateThread(run_stream, "stream", stream);
    if (!stream->thread) {
        LOGC("Could not start stream thread");
        return false;
    }
    return true;
}

void
stream_stop(struct stream *stream) {
    SDL_AtomicSet(&stream->stopped, 1);
    if (stream->decoder) {
        decoder_interrupt(stream->decoder);
    }
}

void
stream_join(struct stream *stream) {
    SDL_WaitThread(stream->thread, NULL);
}
