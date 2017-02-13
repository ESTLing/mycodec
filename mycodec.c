#include <stdio.h>
#include <string.h>
#include <libavcodec/avcodec.h>

#define BUFFER_SIZE 4096

typedef struct {
    FILE* file;
    AVCodec* codec;
    AVCodecContext* cctx;
    AVCodecParserContext* parse;
    AVFrame* frame;
    AVPacket packet;
} InputContext;

typedef struct {
    int initialized;
    FILE* file;
    AVCodec* codec;
    AVCodecContext* cctx;
    AVFrame* frame;
    AVPacket packet;
} OutputContext;

InputContext  inctx;
OutputContext outctx;

char infile[FILENAME_MAX];
char outfile[FILENAME_MAX];

enum AVCodecID inputID  = AV_CODEC_ID_NONE;
enum AVCodecID outputID = AV_CODEC_ID_NONE;

int init_input_context() {
    AVDictionary* opts = NULL;

    inctx.codec = avcodec_find_decoder(inputID);
    if (!inctx.codec) {
        fprintf(stderr, "Could not find proper codec.\n");
        exit(1);
    }

    inctx.cctx = avcodec_alloc_context3(inctx.codec);
    if (!inctx.cctx) {
        fprintf(stderr, "Could not alloc codec context.\n");
        exit(1);
    }

    inctx.parse = av_parser_init(inputID);
    if (!inctx.parse) {
        fprintf(stderr, "Could not init parse context.\n");
        exit(1);
    }

    av_dict_set(&opts, "refcounted_frames", "1", 0);

    if (avcodec_open2(inctx.cctx, inctx.codec, &opts) < 0 ) {
        fprintf(stderr, "Could not open codec.\n");
        exit(1);
    }

    inctx.file = fopen(infile, "rb");
    if (!inctx.file) {
        fprintf(stderr, "Could not open input file.\n");
        exit(1);
    }

    av_init_packet(&inctx.packet);

    inctx.frame = av_frame_alloc();
    if (!inctx.frame) {
        fprintf(stderr, "Could not alloc frame.\n");
        exit(1);
    }

    return 0;
}

int close_input_context() {
    if (inctx.cctx) {
        avcodec_close(inctx.cctx);
        av_free(inctx.cctx);
    }
    if (inctx.frame)
        av_frame_free(&inctx.frame);
    if (inctx.file)
        fclose(inctx.file);
    return 0;
}

int init_output_context() {
    if (outctx.initialized)
        return 0;

    outctx.codec = avcodec_find_encoder(outputID);
    if (!outctx.codec) {
        fprintf(stderr, "Could not find proper codec.\n");
        exit(1);
    }

    outctx.cctx = avcodec_alloc_context3(outctx.codec);
    if (!outctx.cctx) {
        fprintf(stderr, "Could not alloc codec context.\n");
        exit(1);
    }

    /* set argument here */
    outctx.cctx->bit_rate = inctx.cctx->bit_rate;
    outctx.cctx->width = inctx.cctx->width;
    outctx.cctx->height = inctx.cctx->height;
    outctx.cctx->pix_fmt = inctx.cctx->pix_fmt;
    outctx.cctx->time_base.den = inctx.cctx->framerate.num;
    outctx.cctx->time_base.num = inctx.cctx->framerate.den;
    outctx.cctx->gop_size = 10;
    outctx.cctx->max_b_frames = 1;
    /*
     * The following part of code cannot work as expect.
     * Actually, they can only run when based on same codec.
     */
    /* AVCodecParameters* param = avcodec_parameters_alloc(); */
    /* avcodec_parameters_from_context(param, inctx.cctx); */
    /* avcodec_parameters_to_context(outctx.cctx, param); */
    /* avcodec_parameters_free(&param); */

    if (avcodec_open2(outctx.cctx, outctx.codec, NULL) < 0) {
        fprintf(stderr, "Could not open codec.\n");
        exit(1);
    }

    outctx.file = fopen(outfile, "wb");
    if (!outctx.file) {
        fprintf(stderr, "Could not open output file.\n");
        exit(1);
    }

    av_init_packet(&outctx.packet);

    /* inctx and outctx share same frame */
    outctx.frame = inctx.frame;

    outctx.initialized = 1;
    return 0;
}

int close_output_context() {
    if (outctx.cctx) {
        avcodec_close(outctx.cctx);
        av_free(outctx.cctx);
    }

    outctx.frame = NULL;

    if (outctx.file) {
        fflush(outctx.file);
        fclose(outctx.file);
    }
    return 0;
}

int decode(AVCodecContext *avctx, AVFrame *frame, int *got_frame, AVPacket *pkt)
{
    int ret;

    *got_frame = 0;

    if (pkt) {
        ret = avcodec_send_packet(avctx, pkt);
        // In particular, we don't expect AVERROR(EAGAIN), because we read all
        // decoded frames with avcodec_receive_frame() until done.
        if (ret < 0)
            return ret == AVERROR_EOF ? 0 : ret;
    }

    ret = avcodec_receive_frame(avctx, frame);
    if (ret < 0 && ret != AVERROR(EAGAIN) && ret != AVERROR_EOF)
        return ret;
    if (ret >= 0)
        *got_frame = 1;

    return 0;
}

int encode(AVCodecContext *avctx, AVPacket *pkt, int *got_packet, AVFrame *frame)
{
    int ret;

    *got_packet = 0;

    ret = avcodec_send_frame(avctx, frame);
    if (ret < 0)
        return ret;

    ret = avcodec_receive_packet(avctx, pkt);
    if (!ret)
        *got_packet = 1;
    if (ret == AVERROR(EAGAIN)) // AVERROR_EOF AVERROR(EINVAL)
        return 0;

    return ret;
}

int flush_decoder() {
    int ret;

    /* Enter draining mode */
    ret = avcodec_send_packet(inctx.cctx, NULL);

    while(1) {
        ret = avcodec_receive_frame(inctx.cctx, inctx.frame);
        if (ret == AVERROR_EOF)
            break;
        if (ret < 0) {
            fprintf(stderr, "Error while receive frame(encode).\n");
            close_input_context();
            close_output_context();
            return ret;
        }

        ret = avcodec_send_frame(outctx.cctx, outctx.frame);
        if (ret < 0) {
            fprintf(stderr, "Error while send frame(encode).\n");
            close_input_context();
            close_output_context();
            return ret;
        }

        while(1) {
            ret = avcodec_receive_packet(outctx.cctx, &outctx.packet);
            if (ret == AVERROR(EAGAIN)) //got no new packet
                break;
            if (ret < 0) {
                fprintf(stderr, "Error while receive packet(encode).\n");
                close_input_context();
                close_output_context();
                return ret;
            }
            /* Write packet data to output file */
            fwrite(outctx.packet.data, 1, outctx.packet.size, outctx.file);
        }
    }

    return 0;
}

int flush_encoder() {
    int ret;

    /* Enter draining mode */
    ret = avcodec_send_frame(outctx.cctx, NULL);

    while(1) {
        ret = avcodec_receive_packet(outctx.cctx, &outctx.packet);
        if (ret == AVERROR_EOF)
            break;
        if (ret < 0) {
            fprintf(stderr, "Error while receive packet(encode).\n");
            close_input_context();
            close_output_context();
            return ret;
        }
        /* Write packet data to output file */
        fwrite(outctx.packet.data, 1, outctx.packet.size, outctx.file);
    }

    return 0;
}

int setInputParam(const char* filename, enum AVCodecID ID) {
    int len = strlen(filename);

    if (len >= FILENAME_MAX) {
        printf("Filename is request no longer than %d byte.\n", FILENAME_MAX);
        exit(1);
    }
    strcpy(infile, filename);

    inputID = ID;

    return 0;
}

int setOutputParam(const char* filename, enum AVCodecID ID) {
    int len = strlen(filename);

    if (len >= FILENAME_MAX) {
        printf("Filename is request no longer than %d byte.\n", FILENAME_MAX);
        exit(1);
    }
    strcpy(outfile, filename);

    outputID = ID;

    return 0;
}

int transcode() {
    uint8_t buffer[BUFFER_SIZE + FF_INPUT_BUFFER_PADDING_SIZE];
    int ret;

    memset(buffer+BUFFER_SIZE, 0, FF_INPUT_BUFFER_PADDING_SIZE);

    avcodec_register_all();

    init_input_context();
    /**
     * We cannot init outctx here, some information only can
     * get after at least one frame decoded.
     */
    outctx.initialized = 0;

    while (1) {
        uint8_t* curr_ptr = buffer;
        int curr_len, len;

        curr_len = fread(buffer, 1, BUFFER_SIZE, inctx.file);
        if (curr_len == 0) {
            break;
        }
        //printf("curr length = %d\n\n\n", curr_len);
        while (curr_len > 0) {
            len = av_parser_parse2(inctx.parse, inctx.cctx,
                                   &(inctx.packet.data), &(inctx.packet.size),
                                   curr_ptr, curr_len,
                                   AV_NOPTS_VALUE, AV_NOPTS_VALUE, AV_NOPTS_VALUE);
            curr_ptr += len;
            curr_len -= len;

            if (inctx.packet.size == 0) {
                continue;
            }

            /* Main process begin. */

            ret = avcodec_send_packet(inctx.cctx, &inctx.packet);
            if (ret < 0) {
                fprintf(stderr, "Error while send packet(decode).\n");
                close_input_context();
                close_output_context();
                return ret;
            }

            ret = avcodec_receive_frame(inctx.cctx, inctx.frame);
            if (ret == AVERROR(EAGAIN)) //got no new frame
                continue;
            if (ret < 0) {
                fprintf(stderr, "Error while receive frame(decode).\n");
                close_input_context();
                close_output_context();
                return ret;
            }

            /* After get first frame init outctx */
            if (!outctx.initialized) {
                init_output_context();
            }

            ret = avcodec_send_frame(outctx.cctx, outctx.frame);
            if (ret < 0) {
                fprintf(stderr, "Error while send frame(encode).\n");
                close_input_context();
                close_output_context();
                return ret;
            }

            while(1) {
                ret = avcodec_receive_packet(outctx.cctx, &outctx.packet);
                if (ret == AVERROR(EAGAIN)) //got no new packet
                    break;
                if (ret < 0) {
                    fprintf(stderr, "Error while receive packet(encode).\n");
                    close_input_context();
                    close_output_context();
                    return ret;
                }
                /* Write packet data to output file */
                fwrite(outctx.packet.data, 1, outctx.packet.size, outctx.file);
            }
            /* Main process end */
        }
    }

    ret = flush_decoder();
    if (ret < 0) return ret;
    ret = flush_encoder();
    if (ret < 0) return ret;

    close_input_context();
    close_output_context();

    return 0;
}

int main() {
    setInputParam("1.h264", AV_CODEC_ID_H264);
    setOutputParam("tmp.hevc", AV_CODEC_ID_HEVC);
    if (transcode() != 0)
        printf("Same thing may goes wrong, but I dont want to check it any more.\n");

    return 0;
}
