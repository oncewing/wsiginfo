/*
 * srsd_at.c  —  SRSD UDP 프로토콜로 AT 명령을 전송하는 Linux 전용 도구
 *
 * 빌드:  gcc -o srsd_at srsd_at.c
 * 사용:  ./srsd_at <단말기IP> [포트(기본:5002)]
 *
 * 전송 AT 명령: AT*W4CMD=Req_PDUSessConn
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <errno.h>

/* ── 상수 ─────────────────────────────────────────────────────────────── */
#define SRSD_DEFAULT_PORT   5002
#define SRSD_CMD_AT         2
#define SRSD_HEADER_SIZE    42      /* 4+16+16+2+4 */
#define SRSD_RECV_BUF       65535
#define SRSD_TIMEOUT_SEC    10

#define AT_COMMAND          "AT*W4CMD=Req_PDUSessConn"

static const uint8_t PROVIDER[16] = "woorinet\0\0\0\0\0\0\0\0";
static const uint8_t SECURE[16]   = "W35337396126969\0";

/* ── CRC16 ────────────────────────────────────────────────────────────── */
/*
 * agent.py의 _srsd_crc16()와 동일한 알고리즘.
 * 입력: frame_length ~ payload 전체 (CRC 필드 제외)
 */
static uint16_t crc16(const uint8_t *data, size_t len)
{
    uint16_t wCRC = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        uint8_t ch = (data[i] ^ (wCRC & 0xFF)) & 0xFF;
        ch = (ch ^ ((ch << 4) & 0xFF)) & 0xFF;
        wCRC = ((wCRC >> 8)
               ^ ((uint16_t)(ch << 8))
               ^ ((uint16_t)(ch << 3))
               ^ (ch >> 4)) & 0xFFFF;
    }
    return (~wCRC) & 0xFFFF;
}

/* ── 프레임 빌드 ──────────────────────────────────────────────────────── */
/*
 * 반환: 할당된 프레임 버퍼 (호출자가 free 해야 함)
 * frame_len: 전체 프레임 크기 저장
 */
static uint8_t *build_frame(uint16_t command,
                             const uint8_t *payload, uint32_t payload_size,
                             size_t *frame_len)
{
    /* frame_length 값 = HEADER(42) + payload + CRC(2) */
    uint32_t frame_length = SRSD_HEADER_SIZE + payload_size + 2;
    *frame_len = frame_length;

    uint8_t *buf = malloc(frame_length);
    if (!buf) { perror("malloc"); exit(1); }

    uint8_t *p = buf;

    /* [4] frame_length (LE) */
    uint32_t fl_le = htole32(frame_length);
    memcpy(p, &fl_le, 4); p += 4;

    /* [16] provider */
    memcpy(p, PROVIDER, 16); p += 16;

    /* [16] secure code */
    memcpy(p, SECURE, 16); p += 16;

    /* [2] command (LE) */
    uint16_t cmd_le = htole16(command);
    memcpy(p, &cmd_le, 2); p += 2;

    /* [4] payload_size (LE) */
    uint32_t ps_le = htole32(payload_size);
    memcpy(p, &ps_le, 4); p += 4;

    /* [n] payload */
    if (payload_size > 0)
        memcpy(p, payload, payload_size);
    p += payload_size;

    /* [2] CRC16 — frame_length 필드부터 payload까지 전체 */
    uint16_t crc = crc16(buf, SRSD_HEADER_SIZE + payload_size);
    buf[SRSD_HEADER_SIZE + payload_size]     = crc & 0xFF;
    buf[SRSD_HEADER_SIZE + payload_size + 1] = (crc >> 8) & 0xFF;

    return buf;
}

/* ── 응답 payload 추출 ────────────────────────────────────────────────── */
/*
 * 응답 프레임도 동일한 구조.
 * payload는 offset 42부터 시작.
 * 반환: 정적 버퍼 (덮어쓰기 주의), NULL = 파싱 실패
 */
static const char *parse_response(const uint8_t *resp, size_t resp_len)
{
    if (resp_len < (size_t)SRSD_HEADER_SIZE) {
        fprintf(stderr, "[오류] 응답 너무 짧음: %zu bytes\n", resp_len);
        return NULL;
    }

    uint32_t payload_size;
    memcpy(&payload_size, resp + 38, 4);   /* offset 38 = 4+16+16+2 */
    payload_size = le32toh(payload_size);

    if (resp_len < (size_t)(SRSD_HEADER_SIZE + payload_size)) {
        fprintf(stderr, "[오류] 응답 페이로드 불완전\n");
        return NULL;
    }

    /* null-terminate하여 반환 */
    static char payload_buf[65536];
    size_t copy_len = payload_size < sizeof(payload_buf) - 1
                      ? payload_size : sizeof(payload_buf) - 1;
    memcpy(payload_buf, resp + SRSD_HEADER_SIZE, copy_len);
    payload_buf[copy_len] = '\0';

    /* SRSD 오류 문자열 확인 */
    const char *error_strs[] = {
        "PROVIDER ERROR", "SECURE CODE ERROR", "CRC ERROR",
        "UNSUPPORTED", "INVALID ARGUMENT", "INTERNAL ERROR", NULL
    };
    for (int i = 0; error_strs[i]; i++) {
        if (strncmp(payload_buf, error_strs[i], strlen(error_strs[i])) == 0) {
            fprintf(stderr, "[SRSD 오류] %s\n", payload_buf);
            return NULL;
        }
    }

    return payload_buf;
}

/* ── UDP 송수신 ───────────────────────────────────────────────────────── */
static ssize_t srsd_send_recv(const char *ip, int port,
                              const uint8_t *frame, size_t frame_len,
                              uint8_t *recv_buf, size_t recv_buf_size)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    /* 수신 타임아웃 설정 */
    struct timeval tv = { .tv_sec = SRSD_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = inet_addr(ip),
    };

    if (sendto(sock, frame, frame_len, 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }

    /* 응답 수신 — 여러 패킷 누적 (frame_length 기준으로 완료 판단) */
    ssize_t total = 0;
    while (1) {
        ssize_t n = recvfrom(sock, recv_buf + total,
                             recv_buf_size - total, 0, NULL, NULL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;  /* 타임아웃 */
            perror("recvfrom");
            close(sock);
            return -1;
        }
        total += n;

        /* frame_length 필드 확인 후 수신 완료 여부 판단 */
        if (total >= 4) {
            uint32_t expected;
            memcpy(&expected, recv_buf, 4);
            expected = le32toh(expected);
            if ((uint32_t)total >= expected)
                break;
        }
    }

    close(sock);
    return total;
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    const char *ip       = (argc >= 2) ? argv[1] : "192.168.225.1";
    int         interval = (argc >= 3) ? atoi(argv[2]) : 5;
    int         max_try  = (argc >= 4) ? atoi(argv[3]) : 5;

    if (interval < 1) interval = 1;
    if (max_try  < 1) max_try  = 1;

    /* 프레임 빌드 (한 번만) */
    const uint8_t *payload    = (const uint8_t *)AT_COMMAND;
    uint32_t       payload_sz = (uint32_t)strlen(AT_COMMAND);
    size_t         frame_len;
    uint8_t       *frame = build_frame(SRSD_CMD_AT, payload, payload_sz, &frame_len);

    uint8_t recv_buf[SRSD_RECV_BUF];

    for (int attempt = 1; attempt <= max_try; attempt++) {
        ssize_t recv_len = srsd_send_recv(ip, SRSD_DEFAULT_PORT, frame, frame_len,
                                          recv_buf, sizeof(recv_buf));

        if (recv_len > 0) {
            const char *result = parse_response(recv_buf, recv_len);
            if (result && strstr(result, "OK") != NULL) {
                printf("OK\n");
                free(frame);
                return 0;
            }
        }

        if (attempt < max_try)
            sleep(interval);
    }

    printf("ERROR\n");
    free(frame);
    return 1;
}
