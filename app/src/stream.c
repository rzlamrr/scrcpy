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

#define BUFSIZE 0x200000
#define HEADER_SIZE 12
#define NO_PTS UINT64_C(-1)

#include "/home/rom/util/time.h"
static bool
read_packet_header(socket_t socket, struct packet_header *header) {
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
        LOGE("Unexpected end of stream on packet header");
        return false;
    }

    for (int i = 0; i < r; ++i) {
        printf("%02x ", buf[i]);
    }
    printf("\n");


    header->pts = buffer_read64be(buf);
    header->len = buffer_read32be(&buf[8]);
    LOGD("packet header read: %ld", timestamp_ms());
    return true;
}

static ssize_t
read_first_packet(struct stream *stream, uint8_t *buf, size_t len) {
    struct receiver_state *state = &stream->receiver_state;

    if (!read_packet_header(stream->socket, &state->packet_header)) {
        LOGE("Could not read first packet header");
        return -1;
    }

    size_t payload_len = state->packet_header.len;
    LOGD("payload_len = %x", (int)payload_len);
    if (payload_len >= BUFSIZE) {
        // in practice, it should be 20 or 30 bytes
        LOGE("Header packet too big");
        return -1;
    }

    ssize_t r = net_recv_all(stream->socket, buf, payload_len);
    if (r < payload_len) {
        LOGE("Unexpected end of stream during first packet payload");
        return -1;
    }

    return payload_len;
}

// read a (part of) a packet from the stream (consuming packet headers)
static ssize_t
read_packet(struct stream *stream, uint8_t *buf, size_t len) {
    struct receiver_state *state = &stream->receiver_state;

    LOGD("===");

    if (!state->remaining &&
            !read_packet_header(stream->socket, &state->packet_header)) {
        LOGE("Could not read packet header");
        return -1;
    }

    state->remaining = state->packet_header.len;
    SDL_assert(state->remaining);

    LOGD("net_recv_all = %d", (int) state->remaining);
    LOGD("packet receiving: %ld", timestamp_ms());
    ssize_t r = net_recv_all(stream->socket, buf, state->remaining);
    if (r <= 0) {
        LOGE("Unexpected end of stream");
        return -1;
    }

    LOGD("packet received: %ld", timestamp_ms());
    state->remaining -= r;
    LOGD("remaining = %d", (int) state->remaining);
    return r;
}

static bool
process_packet(struct stream *stream, AVPacket *packet) {
    if (SDL_AtomicGet(&stream->stopped)) {
        // if the stream is stopped, the socket had been shutdown, so the
        // last packet is probably corrupted (but not detected as such by
        // FFmpeg) and will not be decoded correctly
        return false;
    }

    if (stream->decoder && !decoder_push(stream->decoder, packet)) {
        return false;
    }

    if (stream->recorder && !recorder_write(stream->recorder, packet)) {
        return false;
    }

    return true;
}

static void
process_stream(struct stream *stream) {
    uint8_t buf[BUFSIZE];

    // read the H.264 header
    ssize_t header_len = read_first_packet(stream, buf, BUFSIZE);
    if (header_len == -1) {
        return;
    }

    size_t offset = header_len;

    if (stream->recorder) {
        //recorder_write_header(stream->recorder, buf, header_len);
    }

    // the header must be merged with the following packet (the first frame)
    // for decoding

    //ssize_t r = read_packet(stream, &buf[header_len], BUFSIZE - header_len);
    //if (r == -1) {
    //    return;
    //}


    for (;;) {
        ssize_t r = read_packet(stream, buf + offset, BUFSIZE - offset);
        if (r == -1) {
            return;
        }

        offset += r;

        uint8_t *in_data = buf;
        int in_len = offset;
        uint8_t *out_data = NULL;
        int out_size = 0;
        while (in_len) {
            LOGD("in_len before = %d", (int) in_len);
                LOGD("packet parsing: %ld", timestamp_ms());
            int len = av_parser_parse2(stream->parser, stream->codec_ctx,
                                       &out_data, &out_size, in_data, in_len,
                                       AV_NOPTS_VALUE, AV_NOPTS_VALUE, -1);
            LOGD("len = %d", (int) len);
            in_data += len;
            in_len -= len;
            LOGD("in_len = %d", (int) in_len);
            LOGD("out_size = %d", (int) out_size);

            if (out_size) {
                LOGD("has packet");
                AVPacket packet;
                av_init_packet(&packet);
                packet.data = out_data;
                packet.size = out_size;

                if (stream->parser->key_frame) {
                    packet.flags |= AV_PKT_FLAG_KEY;
                }

                LOGD("packet decoding: %ld", timestamp_ms());
                bool ok = process_packet(stream, &packet);
                av_packet_unref(&packet);

                if (!ok) {
                    return;
                }
                LOGD("packet decoded: %ld", timestamp_ms());
            }
        }
        offset = 0;

    }
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

    stream->parser = av_parser_init(AV_CODEC_ID_H264);
    //stream->parser->flags |= PARSER_FLAG_COMPLETE_FRAMES;
    //stream->parser->flags |= PARSER_FLAG_USE_CODEC_TS;

    process_stream(stream);

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
    stream->codec_ctx = NULL;
    stream->parser = NULL;
    stream->receiver_state.packet_header.pts = 0;
    stream->receiver_state.packet_header.len = 0;
    stream->receiver_state.remaining = 0;
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
