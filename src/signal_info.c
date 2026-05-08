#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "srs_cli.h"

#define PARA_NUM 4
#define DEF_OPT_ARR { "ant_bar", "nr_rsrp", "nr_rsrq", "nr_sinr" }

#define SRSD_PORT 5002
#define SIGNAL_INFO_COMMAND 1
#define DATAON_COMMAND 2
#define SHELL_COMMAND 102
#define DEFAULT_RETRY_INTERVAL_MS 50
#define DEFAULT_MAX_TRY 3
#define DATAON_AT_COMMAND "AT*W4CMD=Req_PDUSessConn"
#define DATAON_FLAG_FILE "Req_PDUSessConn_enabled"
#define DATAON_FLAG_CHECK_COMMAND "ls /var/tmp/ | grep Req_PDUSessConn_enabled"
#define DATAON_FLAG_TOUCH_COMMAND "touch /var/tmp/Req_PDUSessConn_enabled"
#define WSIGINFO_VERSION "2.0"

#define DEBUG_LEVEL_DISABLE 0
#define DEBUG_LEVEL_ALL 1
#define DEBUG_LEVEL_IMPORTANT 2

static int g_debug_level = DEBUG_LEVEL_DISABLE;

static void debug_log_impl(int level, const char *fmt, ...)
{
  char time_buf[32] = {0,};
  struct timeval tv;
  struct tm tm_now;
  va_list ap;

  if (g_debug_level == DEBUG_LEVEL_DISABLE)
    return;
  if (g_debug_level == DEBUG_LEVEL_IMPORTANT && level != DEBUG_LEVEL_IMPORTANT)
    return;

  gettimeofday(&tv, NULL);
  localtime_r(&tv.tv_sec, &tm_now);
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_now);

  fprintf(stderr, "[DEBUG][%s.%03ld] ", time_buf, tv.tv_usec / 1000);

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  fputc('\n', stderr);
}
#define DEBUG_LOG_ALL(fmt, ...) debug_log_impl(DEBUG_LEVEL_ALL, fmt, ##__VA_ARGS__)
#define DEBUG_LOG_IMPORTANT(fmt, ...) debug_log_impl(DEBUG_LEVEL_IMPORTANT, fmt, ##__VA_ARGS__)

typedef struct {
  char ip_addr[64];
  int interval;
  int max_try;
} dataon_thread_arg_type;

static void print_usage(const char *prog_name)
{
  fprintf(stderr,
          "Usage: %s [-a ip_addr] [-n max_try] [-i interval_ms] [-d debug_level] [-v]\n"
          "  -a ip_addr      target ip address (default: 192.168.225.1)\n"
          "  -n max_try      retry count (default: %d)\n"
          "  -i interval_ms  retry interval in milliseconds (default: %d)\n"
          "  -d debug_level  0=disable, 1=all, 2=important (default: %d)\n"
          "  -v              show version information\n",
          prog_name, DEFAULT_MAX_TRY, DEFAULT_RETRY_INTERVAL_MS, DEBUG_LEVEL_DISABLE);
}

static void print_version(void)
{
  printf("wsiginfo version %s\n", WSIGINFO_VERSION);
}

static int parse_int_arg(const char *opt_name, const char *opt_value, int *out_value)
{
  char *end_ptr = NULL;
  long parsed = 0;

  if (opt_value == NULL || *opt_value == '\0') {
    fprintf(stderr, "missing value for %s\n", opt_name);
    return -1;
  }

  errno = 0;
  parsed = strtol(opt_value, &end_ptr, 10);
  if (errno != 0 || end_ptr == opt_value || *end_ptr != '\0') {
    fprintf(stderr, "invalid numeric value for %s: %s\n", opt_name, opt_value);
    return -1;
  }

  if (parsed < INT_MIN || parsed > INT_MAX) {
    fprintf(stderr, "out of range value for %s: %s\n", opt_name, opt_value);
    return -1;
  }

  *out_value = (int)parsed;
  return 0;
}

static int normalize_retry_interval_ms(int interval_ms)
{
  if (interval_ms < 1)
    return DEFAULT_RETRY_INTERVAL_MS;

  return interval_ms;
}

static int normalize_max_try(int max_try)
{
  if (max_try < 1)
    return DEFAULT_MAX_TRY;

  return max_try;
}

static void sleep_retry_interval_ms(int interval_ms)
{
  usleep((useconds_t)interval_ms * 1000);
}

static void detach_worker_streams(void)
{
  int null_fd = open("/dev/null", O_RDWR);

  if (null_fd < 0)
    return;

  dup2(null_fd, STDIN_FILENO);
  dup2(null_fd, STDOUT_FILENO);

  if (null_fd > STDOUT_FILENO)
    close(null_fd);
}

static void disp_dump(const char *title, const char *buff, int total_len, int enable)
{
  int i = 0;
  int len = 0;
  char log_str[64] = {0,};

  if (!enable)
    return;

  SRSCLI_LOG("======== %s(%d) ========", title, total_len);

  for (i = 0; i < total_len; i++) {
    if ((i % 16) == 0 && i > 0) {
      SRSCLI_LOG("%s", log_str);
      memset(log_str, 0x00, sizeof(log_str));
      len = 0;
    }

    len += snprintf(&log_str[len], sizeof(log_str) - len - 1, "%02X ",
                    (unsigned char)buff[i]);
  }

  SRSCLI_LOG("%s", log_str);
  SRSCLI_LOG("====================");
}

static void gen_crc16(const unsigned char *data, unsigned int length, unsigned char *crc)
{
  unsigned char ch = 0;
  unsigned char tf = 0;
  unsigned char ts = 0;
  unsigned int wcrc = 0xFFFF;

  while (length-- > 0) {
    ch = *data++;
    ch = (ch ^ (unsigned char)(wcrc & 0x00FF));
    ch = (ch ^ (ch << 4));
    wcrc = (wcrc >> 8) ^ ((unsigned int)ch << 8) ^ ((unsigned int)ch << 3)
         ^ ((unsigned int)ch >> 4);
  }

  wcrc = ~wcrc;
  tf = (unsigned char)(wcrc & 0xFF);
  ts = (unsigned char)((wcrc >> 8) & 0xFF);

  crc[0] = tf;
  crc[1] = ts;
}

static void add_crc16(unsigned char *data, unsigned int length)
{
  unsigned char crc[2] = {0,};

  gen_crc16(data, length, crc);
  data[length] = crc[0];
  data[length + 1] = crc[1];
}

static int send_srs_request(const char *ip_addr, unsigned short command,
                            const char *payload, char *recv_buf, size_t recv_buf_size,
                            int enable_dump)
{
  int sock = -1;
  int len = -1;
  int payload_len = payload ? (int)strlen(payload) : 0;
  int packet_size = (int)sizeof(srs_mdm_info_header_type) + payload_len + 2;
  unsigned char *packet = NULL;
  struct sockaddr_in serv_addr;
  struct sockaddr_storage from_addr;
  socklen_t from_len = sizeof(from_addr);
  struct timeval tv;
  srs_mdm_info_header_type header = {0,};

  packet = (unsigned char *)calloc(1, packet_size);
  if (packet == NULL) {
    DEBUG_LOG_IMPORTANT("calloc failed: command=%u payload_len=%d", command, payload_len);
    return -1;
  }

  strncpy(header.provider, "woorinet", sizeof(header.provider));
  strncpy(header.secure, "W35337396126969", sizeof(header.secure));
  header.command = command;
  header.payload_size = payload_len;
  header.size = packet_size;

  memcpy(packet, &header, sizeof(header));
  if (payload_len > 0)
    memcpy(packet + sizeof(header), payload, payload_len);

  add_crc16(packet, packet_size - 2);
  DEBUG_LOG_ALL("send_srs_request start: ip=%s command=%u payload=\"%s\" packet_size=%d",
                ip_addr, command, payload ? payload : "", packet_size);
  disp_dump("SEND", (const char *)packet, packet_size, enable_dump);

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    DEBUG_LOG_IMPORTANT("socket failed: command=%u errno=%d", command, errno);
    free(packet);
    return -1;
  }

  tv.tv_sec = RCV_TIMEOUT_S;
  tv.tv_usec = RCV_TIMEOUT_US;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
    DEBUG_LOG_IMPORTANT("setsockopt failed: command=%u errno=%d", command, errno);
    close(sock);
    free(packet);
    return -1;
  }

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(SRSD_PORT);
  if (inet_pton(AF_INET, ip_addr, &serv_addr.sin_addr.s_addr) != 1) {
    DEBUG_LOG_IMPORTANT("inet_pton failed: ip=%s command=%u", ip_addr, command);
    close(sock);
    free(packet);
    return -1;
  }

  if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&serv_addr,
             sizeof(serv_addr)) < 0) {
    DEBUG_LOG_IMPORTANT("sendto failed: command=%u errno=%d", command, errno);
    close(sock);
    free(packet);
    return -1;
  }

  len = recvfrom(sock, recv_buf, recv_buf_size - 1, 0,
                 (struct sockaddr *)&from_addr, &from_len);
  if (len > 0) {
    recv_buf[len] = '\0';
    DEBUG_LOG_ALL("recvfrom success: command=%u recv_len=%d", command, len);
    disp_dump("RECV", recv_buf, len, enable_dump);
  } else {
    DEBUG_LOG_IMPORTANT("recvfrom failed or timeout: command=%u errno=%d", command, errno);
  }

  close(sock);
  free(packet);
  return len;
}

static int extract_response_payload(const char *recv_buf, int recv_len,
                                    char *payload_buf, size_t payload_buf_size)
{
  srs_mdm_info_header_type header = {0,};
  unsigned char crc16[2] = {0,};
  size_t copy_len = 0;

  if (recv_len < (int)sizeof(header)) {
    DEBUG_LOG_IMPORTANT("extract_response_payload short packet: recv_len=%d", recv_len);
    return -1;
  }

  memcpy(&header, recv_buf, sizeof(header));
  if ((int)header.size > recv_len || header.size < sizeof(header) + 2) {
    DEBUG_LOG_IMPORTANT("extract_response_payload invalid size: header.size=%u recv_len=%d",
                        header.size, recv_len);
    return -1;
  }
  if ((size_t)header.payload_size > (size_t)recv_len - sizeof(header) - 2) {
    DEBUG_LOG_IMPORTANT("extract_response_payload invalid payload_size: payload_size=%u recv_len=%d",
                        header.payload_size, recv_len);
    return -1;
  }

  gen_crc16((const unsigned char *)recv_buf, header.size - 2, crc16);
  if (crc16[0] != (unsigned char)recv_buf[header.size - 2]
      || crc16[1] != (unsigned char)recv_buf[header.size - 1]) {
    DEBUG_LOG_IMPORTANT("extract_response_payload crc mismatch");
    return -1;
  }

  copy_len = header.payload_size;
  if (copy_len >= payload_buf_size)
    copy_len = payload_buf_size - 1;

  memcpy(payload_buf, recv_buf + sizeof(header), copy_len);
  payload_buf[copy_len] = '\0';
  DEBUG_LOG_ALL("extract_response_payload success: command=%u payload=\"%s\"",
                header.command, payload_buf);

  return 0;
}

static int run_signal_info(const char *ip_addr, int interval, int max_try)
{
  int attempt = 0;
  int para_idx = 0;
  int enable_dump = 0;
  int len = -1;
  char total_result_str[1024] = {0,};
  char recv_buf[2048] = {0,};
  char para_arr[PARA_NUM][32] = DEF_OPT_ARR;
  bool all_ok = false;

  interval = normalize_retry_interval_ms(interval);
  max_try = normalize_max_try(max_try);

  DEBUG_LOG_IMPORTANT("run_signal_info start: ip=%s interval_ms=%d max_try=%d",
                      ip_addr, interval, max_try);
  for (attempt = 1; attempt <= max_try; attempt++) {
    int total_result_len = 0;

    memset(total_result_str, 0x00, sizeof(total_result_str));
    all_ok = true;
    DEBUG_LOG_IMPORTANT("signal_info attempt start: attempt=%d", attempt);

    for (para_idx = 0; para_idx < PARA_NUM; para_idx++) {
      char result_str[1024] = {0,};

      DEBUG_LOG_ALL("signal_info request: para=%s attempt=%d", para_arr[para_idx], attempt);
      len = send_srs_request(ip_addr, SIGNAL_INFO_COMMAND, para_arr[para_idx],
                             recv_buf, sizeof(recv_buf), enable_dump);
      if (len > 0
          && extract_response_payload(recv_buf, len, result_str, sizeof(result_str)) == 0) {
        DEBUG_LOG_ALL("signal_info response: para=%s value=\"%s\"", para_arr[para_idx], result_str);
        total_result_len += snprintf(&total_result_str[total_result_len],
                                     sizeof(total_result_str) - total_result_len - 1,
                                     "%s ", result_str);
        continue;
      }

      DEBUG_LOG_IMPORTANT("signal_info response unavailable: para=%s attempt=%d",
                          para_arr[para_idx], attempt);
      all_ok = false;
      break;
    }

    if (all_ok) {
      if (total_result_len > 0 && total_result_str[total_result_len - 1] == ' ')
        total_result_str[total_result_len - 1] = '\0';
      DEBUG_LOG_IMPORTANT("signal_info attempt done: attempt=%d success=1", attempt);
      break;
    }

    DEBUG_LOG_IMPORTANT("signal_info attempt done: attempt=%d success=0", attempt);

    if (attempt < max_try)
      sleep_retry_interval_ms(interval);
  }

  DEBUG_LOG_IMPORTANT("run_signal_info done: success=%d result=\"%s\"", all_ok, total_result_str);
  printf("%s\n", total_result_str);
  return 0;
}

static int run_dataon_request(const char *ip_addr, int interval, int max_try)
{
  int attempt = 0;
  int len = -1;
  char recv_buf[2048] = {0,};
  char result_str[1024] = {0,};
  char shell_result[1024] = {0,};

  interval = normalize_retry_interval_ms(interval);
  max_try = normalize_max_try(max_try);

  DEBUG_LOG_IMPORTANT("run_dataon_request start: ip=%s interval_ms=%d max_try=%d",
                      ip_addr, interval, max_try);
  for (attempt = 1; attempt <= max_try; attempt++) {
    DEBUG_LOG_IMPORTANT("dataon attempt start: attempt=%d", attempt);
    len = send_srs_request(ip_addr, SHELL_COMMAND, DATAON_FLAG_CHECK_COMMAND,
                           recv_buf, sizeof(recv_buf), 0);
    if (len > 0
        && extract_response_payload(recv_buf, len, shell_result, sizeof(shell_result)) == 0
        && strstr(shell_result, DATAON_FLAG_FILE) != NULL) {
      DEBUG_LOG_IMPORTANT("dataon attempt done: attempt=%d success=1 reason=flag_exists", attempt);
      return 0;
    }
    DEBUG_LOG_ALL("dataon flag not found: proceed Req_PDUSessConn");

    memset(recv_buf, 0x00, sizeof(recv_buf));
    memset(result_str, 0x00, sizeof(result_str));
    len = send_srs_request(ip_addr, DATAON_COMMAND, DATAON_AT_COMMAND,
                           recv_buf, sizeof(recv_buf), 0);
    if (len > 0
        && extract_response_payload(recv_buf, len, result_str, sizeof(result_str)) == 0
        && strstr(result_str, "OK") != NULL) {
      DEBUG_LOG_ALL("Req_PDUSessConn success");
      memset(recv_buf, 0x00, sizeof(recv_buf));
      len = send_srs_request(ip_addr, SHELL_COMMAND, DATAON_FLAG_TOUCH_COMMAND,
                             recv_buf, sizeof(recv_buf), 0);
      DEBUG_LOG_ALL("touch flag command sent: recv_len=%d", len);
      DEBUG_LOG_IMPORTANT("dataon attempt done: attempt=%d success=1 reason=req_pdusessconn", attempt);
      return 0;
    }

    DEBUG_LOG_IMPORTANT("dataon attempt done: attempt=%d success=0", attempt);

    if (attempt < max_try)
      sleep_retry_interval_ms(interval);
  }

  DEBUG_LOG_IMPORTANT("run_dataon_request failed after max retries");
  return -1;
}

static int spawn_dataon_worker(const dataon_thread_arg_type *dataon_arg)
{
  pid_t pid = 0;

  pid = fork();
  if (pid < 0) {
    fprintf(stderr, "fork failed: %s\n", strerror(errno));
    return -1;
  }

  if (pid > 0) {
    DEBUG_LOG_IMPORTANT("dataon worker spawned: pid=%ld", (long)pid);
    return 0;
  }

  DEBUG_LOG_IMPORTANT("dataon worker start: pid=%ld ip=%s interval_ms=%d max_try=%d",
                      (long)getpid(), dataon_arg->ip_addr, dataon_arg->interval,
                      dataon_arg->max_try);
  if (setsid() < 0)
    DEBUG_LOG_IMPORTANT("setsid failed: errno=%d", errno);
  detach_worker_streams();

  run_dataon_request(dataon_arg->ip_addr, dataon_arg->interval, dataon_arg->max_try);
  _exit(0);

  return 0;
}

int main(int argc, char **argv)
{
  const char *ip_addr = "192.168.225.1";
  dataon_thread_arg_type dataon_arg = {{0,}, DEFAULT_RETRY_INTERVAL_MS, DEFAULT_MAX_TRY};
  int dataon_worker_rc = 0;
  int signal_info_rc = 0;
  int opt = 0;

  while ((opt = getopt(argc, argv, "a:n:i:d:hv")) != -1) {
    switch (opt) {
      case 'a':
        ip_addr = optarg;
        break;
      case 'n':
        if (parse_int_arg("-n", optarg, &dataon_arg.max_try) != 0) {
          print_usage(argv[0]);
          return 1;
        }
        break;
      case 'i':
        if (parse_int_arg("-i", optarg, &dataon_arg.interval) != 0) {
          print_usage(argv[0]);
          return 1;
        }
        break;
      case 'd':
        if (parse_int_arg("-d", optarg, &g_debug_level) != 0) {
          print_usage(argv[0]);
          return 1;
        }
        break;
      case 'h':
        print_usage(argv[0]);
        return 0;
      case 'v':
        print_version();
        return 0;
      default:
        print_usage(argv[0]);
        return 1;
    }
  }

  if (optind < argc) {
    fprintf(stderr, "unexpected argument: %s\n", argv[optind]);
    print_usage(argv[0]);
    return 1;
  }

  dataon_arg.interval = normalize_retry_interval_ms(dataon_arg.interval);
  dataon_arg.max_try = normalize_max_try(dataon_arg.max_try);
  if (g_debug_level < DEBUG_LEVEL_DISABLE || g_debug_level > DEBUG_LEVEL_IMPORTANT) {
    fprintf(stderr, "invalid debug level: %d\n", g_debug_level);
    print_usage(argv[0]);
    return 1;
  }

  DEBUG_LOG_IMPORTANT("main start: ip=%s interval_ms=%d max_try=%d debug_level=%d",
                      ip_addr, dataon_arg.interval, dataon_arg.max_try,
                      g_debug_level
  );
  snprintf(dataon_arg.ip_addr, sizeof(dataon_arg.ip_addr), "%s", ip_addr);
  dataon_worker_rc = spawn_dataon_worker(&dataon_arg);

  signal_info_rc = run_signal_info(ip_addr, dataon_arg.interval, dataon_arg.max_try);

  DEBUG_LOG_IMPORTANT("main done: signal_info_rc=%d dataon_worker_rc=%d",
                      signal_info_rc, dataon_worker_rc);
  return signal_info_rc;
}
