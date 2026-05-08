#ifndef __STATUS_REPORT_CLIENT_H__
#define __STATUS_REPORT_CLIENT_H__
// ###########################################################################

#define SRSCLI_LOG(fmt,...) \
  do{ \
     printf("%d : " fmt "\n",__LINE__, ##__VA_ARGS__); \
  } while(0)

typedef struct {
  unsigned int size;
  char provider[16];
  char secure[16];
  unsigned short command;
  unsigned int payload_size;  
} __attribute((packed))srs_mdm_info_header_type;

#define RCV_TIMEOUT_S      1
#define RCV_TIMEOUT_US      500000

#endif /* __STATUS_REPORT_CLIENT_H__ */
