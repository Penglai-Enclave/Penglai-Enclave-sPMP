/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei Hifc PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 */
#ifndef __UNF_SCSI_COMMON__
#define __UNF_SCSI_COMMON__

#include "unf_log.h"
#include "hifc_knl_adp.h"

#define DRV_ISCSI_NAME 223

#define SCSI_SENSE_DATA_LEN 96

#define DRV_SCSI_CDB_LEN 16
#define DRV_SCSI_LUN_LEN 8
#define DRV_PORTID_NUM 32

#ifndef SUCCESS
#define SUCCESS 0x2002
#endif

#ifndef FAILED
#define FAILED 0x2003
#endif

#ifndef FC_PORTSPEED_32GBIT
#define FC_PORTSPEED_32GBIT 0x40
#endif

/*
 * FCTL defines (FrameHdr.Type_Fctl)
 */
#define FC_EXCHANGE_RESPONDER  0x00800000
#define FC_LAST_SEQUENCE       0x00100000
#define FC_END_SEQUENCE        0x00080000
#define FC_SEQUENCE_INITIATIVE 0x00010000

/*
 * FCTL common use defines
 */
#define FC_FCTL_RSP (FC_EXCHANGE_RESPONDER | FC_LAST_SEQUENCE |    \
	FC_END_SEQUENCE)

#define UNF_GID_PORT_CNT  2048
#define UNF_RSCN_PAGE_SUM 255

#define UNF_CPU_ENDIAN

#define UNF_NPORTID_MASK 0x00FFFFFF
#define UNF_DOMAIN_MASK  0x00FF0000
#define UNF_AREA_MASK    0x0000FF00
#define UNF_ALPA_MASK    0x000000FF

#define UNF_NPORTID_WELLKNOWN_MASK 0x00fffff0

#define UNF_SCSI_ABORT_SUCCESS SUCCESS
#define UNF_SCSI_ABORT_FAIL    FAILED

#define UNF_SCSI_STATUS(byte) (byte)
#define UNF_SCSI_MSG(byte)    ((byte) << 8)
#define UNF_SCSI_HOST(byte)   ((byte) << 16)
#define UNF_SCSI_DRIVER(byte) ((byte) << 24)

#define UNF_GET_SCSI_HOST_ID(scsi_host) ((scsi_host)->host_no)

struct unf_fchead_s {
	/* Routing control and Destination address of the seq */
	unsigned int rctl_did;
	/* Class control and Source address of the sequence */
	unsigned int csctl_sid;
	/* Data type and Initial frame control value of the seq */
	unsigned int type_fctl;
	/* Seq ID, Data Field and Initial seq count */
	unsigned int seq_id_dfctl_seq_cnt;
	/* Originator & Responder exchange IDs for the sequence */
	unsigned int oxid_rxid;
	/* Relative offset of the first frame of the sequence */
	unsigned int parameter;
};

#define UNF_FCPRSP_CTL_LEN   (24)
#define UNF_MAX_RSP_INFO_LEN (8)
#define UNF_RSP_LEN_VLD      (1 << 0)
#define UNF_SENSE_LEN_VLD    (1 << 1)
#define UNF_RESID_OVERRUN    (1 << 2)
#define UNF_RESID_UNDERRUN   (1 << 3)

/* T10: FCP2r.07 9.4.1 Overview and format of FCP_RSP IU */
struct unf_fcprsp_iu_s {
	unsigned int ui_reserved[2];
	unsigned char uc_reserved[2];
	unsigned char control;
	unsigned char fcp_status;
	unsigned int fcp_residual;
	unsigned int fcp_sense_len; /* Length of sense info field */
	/* Length of response info field in bytes 0,4 or 8 */
	unsigned int fcp_response_len;
	/* Buffer for response info */
	unsigned char fcp_rsp_info[UNF_MAX_RSP_INFO_LEN];
	/* Buffer for sense info */
	unsigned char fcp_sense_info[SCSI_SENSE_DATA_LEN];
} __attribute__((packed));

#define UNF_CMD_REF_MASK    0xFF000000
#define UNF_TASK_ATTR_MASK  0x00070000
#define UNF_TASK_MGMT_MASK  0x0000FF00
#define UNF_FCP_WR_DATA     0x00000001
#define UNF_FCP_RD_DATA     0x00000002
#define UNF_CDB_LEN_MASK    0x0000007C
#define UNF_FCP_CDB_LEN_16  (16)
#define UNF_FCP_CDB_LEN_32  (32)
#define UNF_FCP_LUNID_LEN_8 (8)

/* FCP-4 :Table 27 - RSP_CODE field */
#define UNF_FCP_TM_RSP_COMPLETE    (0)
#define UNF_FCP_TM_INVALID_CMND    (0x2)
#define UNF_FCP_TM_RSP_REJECT      (0x4)
#define UNF_FCP_TM_RSP_FAIL        (0x5)
#define UNF_FCP_TM_RSP_SUCCEED     (0x8)
#define UNF_FCP_TM_RSP_INCRECT_LUN (0x9)

#define UNF_SET_TASK_MGMT_FLAGS(v_fcp_tm_code) ((v_fcp_tm_code) << 8)
#define UNF_GET_TASK_MGMT_FLAGS(v_control)   \
	(((v_control) & UNF_TASK_MGMT_MASK) >> 8)

enum unf_task_mgmt_cmnd_e {
	UNF_FCP_TM_QUERY_TASK_SET = (1 << 0),
	UNF_FCP_TM_ABORT_TASK_SET = (1 << 1),
	UNF_FCP_TM_CLEAR_TASK_SET = (1 << 2),
	UNF_FCP_TM_QUERY_UNIT_ATTENTION = (1 << 3),
	UNF_FCP_TM_LOGICAL_UNIT_RESET = (1 << 4),
	UNF_FCP_TM_TARGET_RESET = (1 << 5),
	UNF_FCP_TM_CLEAR_ACA = (1 << 6),
	UNF_FCP_TM_TERMINATE_TASK = (1 << 7) /* obsolete */
};

struct unf_fcp_cmnd_s {
	unsigned char lun[UNF_FCP_LUNID_LEN_8]; /* Logical unit number */

	unsigned int control;  /* Control field  :
				* uint8_t  cmnd_ref;
				* uint8_t  task_attr:3;
				* uint8_t  reserved:5;
				* uint8_t  task_mgmt_flags;
				* uint8_t  wrdata:1;
				* uint8_t  rddata:1;
				* uint8_t  add_cdb_len:6;
				*/
	/* Payload data containing cdb info */
	unsigned char cdb[UNF_FCP_CDB_LEN_16];
	/* Number of bytes expected to be transferred */
	unsigned int data_length;
} __attribute__((packed));

struct unf_fcp_cmd_hdr_s {
	struct unf_fchead_s frame_hdr; /* FCHS structure */
	struct unf_fcp_cmnd_s fcp_cmnd; /* Fcp Cmnd struct */
};

/*
 * parameter struct
 */

/* Common Services Parameter used for returning Fabric
 * parameters. See FC-FS Rev. 1.90, FC-PH-3 Rev. 9.4 and see FC-DA 3.1.
 * This is the structure that is used to enquire Fabric parameters
 * after a Fabric login is successful. The fileds in this structure
 * are relevant for FLOGI ACC.
 */

/* FC-LS-2  Table 140  Common Service Parameter applicability */
struct unf_fabric_coparms_s {
#if defined(UNF_CPU_ENDIAN)
	unsigned int bb_credit : 16;      /* 0 [0-15] */
	unsigned int lowest_version : 8;  /* 0 [16-23] */
	unsigned int highest_version : 8; /* 0 [24-31] */
#else
	unsigned int highest_version : 8; /* 0 [24-31] */
	unsigned int lowest_version : 8;  /* 0 [16-23] */
	unsigned int bb_credit : 16;      /* 0 [0-15] */
#endif

	/* Word1 Common Features */
#if defined(UNF_CPU_ENDIAN)
	unsigned int bb_receive_data_field_size : 12; /* 1 [0-11] */
	unsigned int bb_scn : 4;                      /* 1 [12-15] */
	unsigned int payload_length : 1;              /* 1 [16] */
	unsigned int seq_cnt : 1;                     /* 1 [17] */
	unsigned int dynamic_half_duplex : 1;         /* 1 [18] */
	unsigned int r_t_tov : 1;                     /* 1 [19] */
	unsigned int reserved_co2 : 6;                /* 1 [20-25] */
	unsigned int e_d_tov_resolution : 1;          /* 1 [26] */
	unsigned int alternate_bb_credit_mgmt : 1;    /* 1 [27] */
	unsigned int n_port : 1;                      /* 1 [28] */
	unsigned int mnid_assignment : 1;             /* 1 [29] */
	unsigned int random_relative_offset : 1;      /* 1 [30] */
	unsigned int clean_address : 1;               /* 1 [31] */
#else
	unsigned int reserved_co22 : 2;               /* 1 [24-25] */
	unsigned int e_d_tov_resolution : 1;          /* 1 [26] */
	unsigned int alternate_bb_credit_mgmt : 1;    /* 1 [27] */
	unsigned int n_port : 1;                      /* 1 [28] */
	unsigned int mnid_assignment : 1;             /* 1 [29] */
	unsigned int random_relative_offset : 1;      /* 1 [30] */
	unsigned int clean_address : 1;               /* 1 [31] */

	unsigned int payload_length : 1;              /* 1 [16] */
	unsigned int seq_cnt : 1;                     /* 1 [17] */
	unsigned int dynamic_half_duplex : 1;         /* 1 [18] */
	unsigned int r_t_tov : 1;                     /* 1 [19] */
	unsigned int reserved_co25 : 4;               /* 1 [20-23] */

	unsigned int bb_receive_data_field_size : 12; /* 1 [0-11] */
	unsigned int bb_scn : 4;                      /* 1 [12-15] */
#endif
	unsigned int r_a_tov;                         /* 2 [0-31] */
	unsigned int e_d_tov;                         /* 3 [0-31] */
};

/*
 * Common Services Parameter 16 byte structure.
 * See FC-PH 4.3 Section 23.6.3, FC-PLDA Section 5.2 and
 * TachLite Users Manual 3.24.1
 * the structure does not need to be packed.
 */

/* FC-LS-2  Table 140 Common Service Parameter applicability */
/* Table 142 Common Service Parameters - PLOGI and PLOGI LS_ACC */
struct unf_lgn_port_coparms_s {
#if defined(UNF_CPU_ENDIAN)
	unsigned int bb_credit : 16;      /* 0 [0-15] */
	unsigned int lowest_version : 8;  /* 0 [16-23] */
	unsigned int highest_version : 8; /* 0 [24-31] */
#else
	unsigned int highest_version : 8; /* 0 [24-31] */
	unsigned int lowest_version : 8;  /* 0 [16-23] */
	unsigned int bb_credit : 16;      /* 0 [0-15] */
#endif

#if defined(UNF_CPU_ENDIAN)
	unsigned int bb_receive_data_field_size : 12;   /* 1 [0-11] */
	unsigned int bb_scn : 4;                        /* 1 [12-15] */
	unsigned int payload_length : 1;                /* 1 [16] */
	unsigned int seq_cnt : 1;                       /* 1 [17] */
	unsigned int dynamic_half_duplex : 1;           /* 1 [18] */
	unsigned int reserved_co2 : 7;                  /* 1 [19-25] */
	unsigned int e_d_tov_resolution : 1;            /* 1 [26] */
	unsigned int alternate_bb_credit_mgmt : 1;      /* 1 [27] */
	unsigned int n_port : 1;                        /* 1 [28] */
	unsigned int vendor_version_level : 1;          /* 1 [29] */
	unsigned int random_relative_offset : 1;        /* 1 [30] */
	unsigned int continuously_increasing : 1;       /* 1 [31] */
#else
	unsigned int reserved_co22 : 2;                 /* 1 [24-25] */
	unsigned int e_d_tov_resolution : 1;            /* 1 [26] */
	unsigned int alternate_bb_credit_mgmt : 1;      /* 1 [27] */
	unsigned int n_port : 1;                        /* 1 [28] */
	unsigned int vendor_version_level : 1;          /* 1 [29] */
	unsigned int random_relative_offset : 1;        /* 1 [30] */
	unsigned int continuously_increasing : 1;       /* 1 [31] */

	unsigned int payload_length : 1;                /* 1 [16] */
	unsigned int seq_cnt : 1;                       /* 1 [17] */
	unsigned int dynamic_half_duplex : 1;           /* 1 [18] */
	unsigned int reserved_co25 : 5;                 /* 1 [19-23] */

	unsigned int bb_receive_data_field_size : 12;   /* 1 [0-11] */
	unsigned int reserved_co1 : 4;                  /* 1 [12-15] */
#endif

#if defined(UNF_CPU_ENDIAN)
	unsigned int relative_offset : 16;                  /* 2 [0-15] */
	unsigned int nport_total_concurrent_sequences : 16; /* 2 [16-31] */
#else
	unsigned int nport_total_concurrent_sequences : 16; /* 2 [16-31] */
	unsigned int relative_offset : 16;                  /* 2 [0-15] */
#endif

	unsigned int e_d_tov;
};

/*
 * Class services  16 byte structure. See FC-PH 4.3 Section 23.6.8 and
 * FC-PLDA Section 5.3
 * the structure does not need to be packed
 */

/* FC-LS-2 Table 145 Class Service Parameters Applicability */
struct unf_lgn_port_clparms_s {
#if defined(UNF_CPU_ENDIAN)
	unsigned int reserved_cl1 : 6;                            /* 0 [0-5] */
	unsigned int ic_data_compression_history_buffer_size : 2; /* 0 [6-7] */
	unsigned int ic_data_compression_capable : 1;             /* 0 [8] */

	unsigned int ic_ack_generation_assistance : 1;            /* 0 [9] */
	unsigned int ic_ack_n_capable : 1;                        /* 0 [10] */
	unsigned int ic_ack_o_capable : 1;                        /* 0 [11] */
	/* 0 [12-13] */
	unsigned int ic_initial_responder_processes_accociator : 2;
	unsigned int ic_x_id_reassignment : 2;    /* 0 [14-15] */

	unsigned int reserved_cl2 : 7;            /* 0 [16-22] */
	unsigned int priority : 1;                /* 0 [23] */
	unsigned int buffered_class : 1;          /* 0 [24] */
	unsigned int camp_on : 1;                 /* 0 [25] */
	unsigned int dedicated_simplex : 1;       /* 0 [26] */
	unsigned int sequential_delivery : 1;     /* 0 [27] */
	unsigned int stacked_connect_request : 2; /* 0 [28-29] */
	unsigned int intermix_mode : 1;           /* 0 [30] */
	unsigned int valid : 1;                   /* 0 [31] */
#else
	unsigned int buffered_class : 1;                   /* 0 [24] */
	unsigned int camp_on : 1;                          /* 0 [25] */
	unsigned int dedicated_simplex : 1;                /* 0 [26] */
	unsigned int sequential_delivery : 1;              /* 0 [27] */
	unsigned int stacked_connect_request : 2;          /* 0 [28-29] */
	unsigned int intermix_mode : 1;                    /* 0 [30] */
	unsigned int valid : 1;                            /* 0 [31] */
	unsigned int reserved_cl2 : 7;                     /* 0 [16-22] */
	unsigned int priority : 1;                         /* 0 [23] */
	unsigned int ic_data_compression_capable : 1;      /* 0 [8] */
	unsigned int ic_ack_generation_assistance : 1;     /* 0 [9] */
	unsigned int ic_ack_n_capable : 1;                 /* 0 [10] */
	unsigned int ic_ack_o_capable : 1;                 /* 0 [11] */
	/* 0 [12-13] */
	unsigned int ic_initial_responder_processes_accociator : 2;
	unsigned int ic_x_id_reassignment : 2;             /* 0 [14-15] */

	unsigned int reserved_cl1 : 6;                     /* 0 [0-5] */
	/* 0 [6-7] */
	unsigned int ic_data_compression_history_buffer_size : 2;
#endif

#if defined(UNF_CPU_ENDIAN)
	unsigned int received_data_field_size : 16;   /* 1 [0-15] */

	unsigned int reserved_cl3 : 5;                /* 1 [16-20] */
	/* 1 [21-22] */
	unsigned int rc_data_compression_history_buffer_size : 2;
	unsigned int rc_data_compression_capable : 1; /* 1 [23] */

	unsigned int rc_categories_per_sequence : 2;  /* 1 [24-25] */
	unsigned int reserved_cl4 : 1;                /* 1 [26] */
	unsigned int rc_error_policy_supported : 2;   /* 1 [27-28] */
	unsigned int rc_x_id_interlock : 1;           /* 1 [29] */
	unsigned int rc_ack_n_capable : 1;            /* 1 [30] */
	unsigned int rc_ack_o_capable : 1;            /* 1 [31] */
#else
	unsigned int rc_categories_per_sequence : 2;  /* 1 [24-25] */
	unsigned int reserved_cl4 : 1;                /* 1 [26] */
	unsigned int rc_error_policy_supported : 2;   /* 1 [27-28] */
	unsigned int rc_x_id_interlock : 1;           /* 1 [29] */
	unsigned int rc_ack_n_capable : 1;            /* 1 [30] */
	unsigned int rc_ack_o_capable : 1;            /* 1 [31] */

	unsigned int reserved_cl3 : 5;                /* 1 [16-20] */
	/* 1 [21-22] */
	unsigned int rc_data_compression_history_buffer_size : 2;
	unsigned int rc_data_compression_capable : 1; /* 1 [23] */

	unsigned int received_data_field_size : 16;   /* 1 [0-15] */
#endif

#if defined(UNF_CPU_ENDIAN)
	unsigned int n_port_end_to_end_credit : 15;   /* 2 [0-14] */
	unsigned int reserved_cl5 : 1;                /* 2 [15] */

	unsigned int concurrent_sequences : 16;       /* 2 [16-31] */
#else
	unsigned int concurrent_sequences : 16;       /* 2 [16-31] */

	unsigned int n_port_end_to_end_credit : 15;   /* 2 [0-14] */
	unsigned int reserved_cl5 : 1;                /* 2 [15] */
#endif

#if defined(UNF_CPU_ENDIAN)
	unsigned int reserved_cl6 : 16;                /* 3 [0-15] */
	unsigned int open_sequences_per_exchange : 16; /* 3 [16-31] */
#else
	unsigned int open_sequences_per_exchange : 16; /* 3 [16-31] */
	unsigned int reserved_cl6 : 16;                /* 3 [0-15] */
#endif
};

struct unf_fabric_parms_s {
	struct unf_fabric_coparms_s co_parms;
	unsigned int high_port_name;
	unsigned int low_port_name;
	unsigned int high_node_name;
	unsigned int low_node_name;
	struct unf_lgn_port_clparms_s cl_parms[3];
	unsigned int reserved_1[4];
	unsigned int vendor_version_level[4];
};

struct unf_lgn_parms_s {
	struct unf_lgn_port_coparms_s co_parms;
	unsigned int high_port_name;
	unsigned int low_port_name;
	unsigned int high_node_name;
	unsigned int low_node_name;
	struct unf_lgn_port_clparms_s cl_parms[3];
	unsigned int reserved_1[4];
	unsigned int vendor_version_level[4];
};

#define ELS_RJT   0x1
#define ELS_ACC   0x2
#define ELS_PLOGI 0x3
#define ELS_FLOGI 0x4
#define ELS_LOGO  0x5
#define ELS_RLS   0xf
#define ELS_ECHO  0x10
#define ELS_RRQ   0x12
#define ELS_REC   0x13
#define ELS_PRLI  0x20
#define ELS_PRLO  0x21
#define ELS_TPRLO 0x24
#define ELS_PDISC 0x50
#define ELS_FDISC 0x51
#define ELS_ADISC 0x52
#define ELS_RSCN  0x61 /* registered state change notification */
#define ELS_SCR   0x62 /* state change registration */

#define NS_GIEL   0X0101
#define NS_GA_NXT 0X0100
#define NS_GPN_ID 0x0112 /* get port name by ID */
#define NS_GNN_ID 0x0113 /* get node name by ID */
#define NS_GFF_ID 0x011f /* get FC-4 features by ID */
#define NS_GID_PN 0x0121 /* get ID for port name */
#define NS_GID_NN 0x0131 /* get IDs for node name */
#define NS_GID_FT 0x0171 /* get IDs by FC4 type */
#define NS_GPN_FT 0x0172 /* get port names by FC4 type */
#define NS_GID_PT 0x01a1 /* get IDs by port type */
#define NS_RFT_ID 0x0217 /* reg FC4 type for ID */
#define NS_RPN_ID 0x0212 /* reg port name for ID */
#define NS_RNN_ID 0x0213 /* reg node name for ID */
#define NS_RSNPN  0x0218 /* reg symbolic port name */
#define NS_RFF_ID 0x021f /* reg FC4 Features for ID */
#define NS_RSNN   0x0239 /* reg symbolic node name */
#define ST_NULL   0xffff /* reg symbolic node name */

#define BLS_ABTS 0xA001  /* ABTS */

#define FCP_SRR 0x14     /* Sequence Retransmission Request */

#define UNF_FC_FID_DOM_MGR 0xfffc00      /* domain manager base */
enum unf_fc_well_known_fabric_id {
	UNF_FC_FID_NONE = 0x000000,      /* No destination */
	UNF_FC_FID_DOM_CTRL = 0xfffc01,  /* domain controller */
	UNF_FC_FID_BCAST = 0xffffff,     /* broadcast */
	UNF_FC_FID_FLOGI = 0xfffffe,     /* fabric login */
	UNF_FC_FID_FCTRL = 0xfffffd,     /* fabric controller */
	UNF_FC_FID_DIR_SERV = 0xfffffc,  /* directory server */
	UNF_FC_FID_TIME_SERV = 0xfffffb, /* time server */
	UNF_FC_FID_MGMT_SERV = 0xfffffa, /* management server */
	UNF_FC_FID_QOS = 0xfffff9,       /* QoS Facilitator */
	UNF_FC_FID_ALIASES = 0xfffff8,   /* alias server (FC-PH2) */
	UNF_FC_FID_SEC_KEY = 0xfffff7,   /* Security key dist. server */
	UNF_FC_FID_CLOCK = 0xfffff6,     /* clock synch server */
	UNF_FC_FID_MCAST_SERV = 0xfffff5 /* multicast server */
};

#define DRV_ENTRY_PER_SGL 64 /* Size of an entry array in a hash table */
#define DRV_DATA_PROTECTION_LEN 8

struct dif_result_info_s {
	unsigned char actual_dif[DRV_DATA_PROTECTION_LEN];
	unsigned char expected_dif[DRV_DATA_PROTECTION_LEN];
};

struct drv_sge {
	char *buf;
	void *page_ctrl;
	unsigned int length;
	unsigned int offset;
};

/*
 * @enum drv_io_direction
 * SCSI data direction
 */
enum drv_io_direction {
	DRV_IO_BIDIRECTIONAL = 0,
	DRV_IO_DIRECTION_WRITE = 1,
	DRV_IO_DIRECTION_READ = 2,
	DRV_IO_DIRECTION_NONE = 3,
};

/*
 * Hash table data structure
 */
struct drv_sgl {
	struct drv_sgl *next_sgl; /* poin to SGL,SGL list */
	unsigned short num_sges_in_chain;
	unsigned short num_sges_in_sgl;
	unsigned int flag;
	unsigned long long serial_num;
	struct drv_sge sge[DRV_ENTRY_PER_SGL];
	struct list_head node;
	unsigned int cpu_id;
};

struct dif_info_s {
	/* Indicates the result returned when the data
	 * protection information is inconsistent,add by pangea
	 */
	struct dif_result_info_s dif_result;
	/* Data protection information operation code
	 * bit[31-24] other operation code
	 * bit[23-16] Data Protection Information Operation
	 * bit[15-8] Data protection information verification
	 * bit[7-0] Data protection information replace
	 */
	unsigned int protect_opcode;
	unsigned short app_tag;
	unsigned long long start_lba; /* IO start LBA */
	struct drv_sgl *protection_sgl;
};

typedef struct Scsi_Host unf_scsi_host_s;

struct unf_ini_error_code_s {
	unsigned int drv_err_code; /* driver error code */
	unsigned int ap_err_code;  /* up level error code */
};

typedef unsigned int (*ini_get_sgl_entry_buf)(void *v_upper_cmnd,
					      void *v_driver_sgl,
					      void **v_upper_sgl,
					      unsigned int *v_req_index,
					      unsigned int *v_index,
					      char **v_buf,
					      unsigned int *v_buf_len);

struct unf_host_param_s {
	int can_queue;
	unsigned short sg_table_size;
	short cmnd_per_lun;
	unsigned int max_id;
	unsigned int max_lun;
	unsigned int max_channel;
	unsigned short max_cmnd_len;
	unsigned short max_sectors;
	unsigned long long dma_boundary;
	unsigned int port_id;
	void *lport;
	struct device *pdev;
};

#define UNF_DIF_AREA_SIZE 8

struct unf_dif_control_info_s {
	unsigned short app_tag;
	unsigned short flags;
	unsigned int protect_opcode;
	unsigned int fcp_dl;
	unsigned int start_lba;
	unsigned char actual_dif[UNF_DIF_AREA_SIZE];
	unsigned char expected_dif[UNF_DIF_AREA_SIZE];
	unsigned int dif_sge_count;
	void *dif_sgl;
};

struct unf_scsi_cmd_s {
	unsigned int scsi_host_id;
	unsigned int scsi_id;             /* cmd->dev->id */
	unsigned long long lun_id;
	unsigned long long port_id;
	unsigned int underflow;           /* Underflow */
	unsigned int transfer_len;        /* Transfer Length */
	unsigned int resid;               /* Resid */
	unsigned int sense_buf_len;
	int result;
	unsigned int entry_count;         /* IO Buffer counter */
	unsigned int abort;
	unsigned int err_code_table_cout; /* error code size */
	unsigned long long cmnd_sn;
	unsigned long time_out;           /* EPL driver add timer */
	unsigned short cmnd_len;          /* Cdb length */
	unsigned char data_direction;     /* data direction */
	unsigned char *pcmnd;             /* SCSI CDB */
	unsigned char *sense_buf;
	void *drv_private;                /* driver host pionter */
	void *driver_scribble;            /* Xchg pionter */
	void *upper_cmnd;                 /* UpperCmnd pointer by driver */
	unsigned char *pc_lun_id;         /* new lunid */
	unsigned int world_id;
	struct unf_dif_control_info_s dif_control;   /* DIF control */
	struct unf_ini_error_code_s *err_code_table; /* error code table */
	void *sgl;                        /* Sgl pointer */
	ini_get_sgl_entry_buf pfn_unf_ini_get_sgl_entry;
	void (*pfn_done)(struct unf_scsi_cmd_s *);
	struct dif_info_s dif_info;
};

/*
 * R_CTL Basic Link Data defines
 */
#define FC_RCTL_BLS 0x80000000
#define FC_RCTL_BLS_ACC (FC_RCTL_BLS | 0x04000000)
#define FC_RCTL_BLS_RJT (FC_RCTL_BLS | 0x05000000)

/*
 * BA_RJT reason code defines
 */
#define FCXLS_BA_OK                  0x00000000
#define FCXLS_BA_RJT_INVALID_COMMAND 0x00010000
#define FCXLS_BA_RJT_LOGICAL_ERROR   0x00030000

/*
 * BA_RJT code explanation
 */

#define FCXLS_BA_RJT_INV_OXID_RXID     0x00000300
#define FCXLS_LS_RJT_INVALID_OXID_RXID 0x00001700

/*
 * Types (word)
 */
#define FC_TYPE_WORD_BLS 0x00000000

/*
 * SFS structures
 */
struct unf_ba_rjt_s {
	unsigned int reason_code; /* BLS reason code and Reason Explanation */
};

#define FC_ABTS_ACC_SEQ_CNT 0x0000ffff
struct unf_ba_acc_s {
	unsigned int seq_id;
	unsigned int oxid_rxid;
	unsigned int seq_cnt;
};

union unf_ba_pld_u {
	struct unf_ba_rjt_s ba_rjt;
	struct unf_ba_acc_s ba_acc;
};

struct unf_abts_rsps_s {
	struct unf_fchead_s frame_hdr;
	union unf_ba_pld_u ba_pld;
};

/*
 * BLS RJT structure header and payload
 */
struct unf_bls_rjt_s {
	struct unf_fchead_s frame_hdr;
	/* BLS reason code and Reason Explanation */
	unsigned int reason_code;
};

/*
 * ELS ACC
 */
struct unf_els_acc_s {
	struct unf_fchead_s frame_hdr;
	unsigned int cmnd;
};

/*
 * ELS RJT
 */
struct unf_els_rjt_s {
	struct unf_fchead_s frame_hdr;
	unsigned int cmnd;
	unsigned int reason_code;
};

/*
 * FLOGI payload,
 * FC-LS-2 Table 139 FLOGI, PLOGI, FDISC or LS_ACC Payload
 */
struct unf_flogi_payload_s {
	unsigned int cmnd;
	struct unf_fabric_parms_s fabric_parms;
};

/*
 * Flogi and Flogi accept frames.  They are the same structure
 */
struct unf_flogi_fdisc_acc_s {
	struct unf_fchead_s frame_hdr;
	struct unf_flogi_payload_s flogi_payload;
};

/*
 * Fdisc and Fdisc accept frames.  They are the same structure
 */
struct unf_fdisc_acc_s {
	struct unf_fchead_s frame_hdr;
	struct unf_flogi_payload_s fdisc_payload;
};

/*
 * PLOGI payload
 */
struct unf_plogi_payload_s {
	unsigned int cmnd;
	struct unf_lgn_parms_s parms;
};

/*
 * Plogi, Plogi accept, Pdisc and Pdisc accept frames.
 * They are all the same structure.
 */
struct unf_plogi_pdisc_s {
	struct unf_fchead_s frame_hdr;
	struct unf_plogi_payload_s payload;
};

/*
 * LOGO logout link service requests invalidation of service parameters and
 * port name.
 * see FC-PH 4.3 Section 21.4.8
 */

/* FC-LS-2  Table 12 LOGO Payload */
struct unf_logo_payload_s {
	unsigned int cmnd;
	unsigned int nport_id;
	unsigned int high_port_name;
	unsigned int low_port_name;
};

/*
 * payload to hold LOGO command
 */
struct unf_logo_s {
	struct unf_fchead_s frame_hdr;
	struct unf_logo_payload_s payload;
};

/*
 * payload for ECHO command, refer to FC-LS-2 4.2.4
 */
struct unf_echo_payload_s {
	unsigned int cmnd;
#define UNF_FC_ECHO_PAYLOAD_LENGTH 255 /* Length in words */
	unsigned int data[UNF_FC_ECHO_PAYLOAD_LENGTH];
};

struct unf_echo_s {
	struct unf_fchead_s frame_hdr;
	struct unf_echo_payload_s *echo_pld;
	dma_addr_t phy_echo_addr;
};

#define UNF_PRLI_SIRT_EXTRA_SIZE 12
/*
 * payload for PRLI and PRLO
 */
struct unf_pril_payload_s {
	unsigned int cmnd;
#define UNF_FC_PRLI_PAYLOAD_LENGTH 7 /* Length in words */
	unsigned int parms[UNF_FC_PRLI_PAYLOAD_LENGTH];
};

/*
 * FCHS structure with payload
 */
struct unf_prli_prlo_s {
	struct unf_fchead_s frame_hdr;
	struct unf_pril_payload_s payload;
};

/*
 * ADISC payload
 */

/* FC-LS-2  Table 75  ADISC Request payload */
struct unf_adisc_payload_s {
	unsigned int cmnd;
	unsigned int hard_address;
	unsigned int high_port_name;
	unsigned int low_port_name;
	unsigned int high_node_name;
	unsigned int low_node_name;
	unsigned int nport_id;
};

/*
 * FCHS structure with payload
 */
struct unf_adisc_s {
	/* FCHS structure */
	struct unf_fchead_s frame_hdr;
	/* Payload data containing ADISC info */
	struct unf_adisc_payload_s adisc_payl;
};

/*
 * RLS payload
 */
struct unf_rls_payload_s {
	unsigned int cmnd;
	unsigned int nport_id; /* in litle endian format */
};

/*
 * RLS
 */
struct unf_rls_s {
	struct unf_fchead_s frame_hdr; /* FCHS structure */
	/* payload data containing the RLS info */
	struct unf_rls_payload_s rls;
};

/*
 * RLS accept payload
 */
struct unf_rls_acc_payload_s {
	unsigned int cmnd;
	unsigned int link_failure_count;
	unsigned int loss_of_sync_count;
	unsigned int loss_of_signal_count;
	unsigned int primitive_seq_count;
	unsigned int invalid_trans_word_count;
	unsigned int invalid_crc_count;
};

/*
 * RLS accept
 */
struct unf_rls_acc_s {
	struct unf_fchead_s frame_hdr; /* FCHS structure */
	/* payload data containing the RLS ACC info */
	struct unf_rls_acc_payload_s rls;
};

/*
 * FCHS structure with payload
 */
struct unf_rrq_s {
	struct unf_fchead_s frame_hdr;
	unsigned int cmnd;
	unsigned int sid;
	unsigned int oxid_rxid;
};

/*
 * ABTA accept
 */
struct unf_abts_acc_s {
	struct unf_fchead_s frame_hdr;
	unsigned int seq_id;
	unsigned int oxid_rxid;
	unsigned int seq_cnt;
};

struct unf_scr_s {
	struct unf_fchead_s frame_hdr;
	unsigned int payload[2];
};

struct unf_ctiu_prem_s {
	unsigned int rev_inid;
	unsigned int gstype_gssub_options;
	unsigned int cmnd_rsp_size;
	unsigned int frag_reason_exp_vend;
};

struct unf_rftid_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ctiu_prem_s ctiu_pream;
	unsigned int nport_id;
	unsigned int fc_4_types[8];
};

struct unf_rffid_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ctiu_prem_s ctiu_pream;
	unsigned int nport_id;
	unsigned int fc_4_feature;
};

struct unf_rffid_rsp_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ctiu_prem_s ctiu_pream;
};

struct unf_gffid_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ctiu_prem_s ctiu_pream;
	unsigned int nport_id;
};

struct unf_gffid_rsp_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ctiu_prem_s ctiu_pream;
	unsigned int fc_4_feature[32];
};

struct unf_gnnid_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ctiu_prem_s ctiu_pream;
	unsigned int nport_id;
};

struct unf_gnnid_rsp_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ctiu_prem_s ctiu_pream;
	unsigned int node_name[2];
};

struct unf_gpnid_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ctiu_prem_s ctiu_pream;
	unsigned int nport_id;
};

struct unf_gpnid_rsp_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ctiu_prem_s ctiu_pream;
	unsigned int port_name[2];
};

struct unf_rft_rsp_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ctiu_prem_s ctiu_pream;
};

struct unf_srr_payload_s {
	unsigned int srr_op;
	unsigned short rx_id;
	unsigned short ox_id;
	unsigned int rel_offset;
	unsigned char reserved[3];
	unsigned char rctl_for_iu;
};

struct unf_srr_s {
	struct unf_fchead_s frame_hdr;
	struct unf_srr_payload_s pld;
};

struct unf_srr_acc_pld_s {
	unsigned int srr_op; /* 02000000h */
};

struct unf_srr_acc_s {
	struct unf_fchead_s frame_hdr;
	struct unf_srr_acc_pld_s pld;
};

struct unf_ls_rjt_pld_s {
	unsigned int srr_op; /* 01000000h */
	unsigned char vandor;
	unsigned char reason_exp;
	unsigned char reason;
	unsigned char reserved;
};

struct unf_ls_rjt_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ls_rjt_pld_s pld;
};

struct unf_rec_pld_s {
	unsigned int rec_cmnd;
	unsigned int xchg_org_sid; /* bit0-bit23 */
	unsigned short rx_id;
	unsigned short ox_id;
};

struct unf_rec_s {
	struct unf_fchead_s frame_hdr;
	struct unf_rec_pld_s rec_pld;
};

struct unf_rec_acc_pld_s {
	unsigned int cmnd;
	unsigned short rx_id;
	unsigned short ox_id;
	unsigned int org_addr_id; /* bit0-bit23 */
	unsigned int rsp_addr_id; /* bit0-bit23 */
};

struct unf_rec_acc_s {
	struct unf_fchead_s frame_hdr;
	struct unf_rec_acc_pld_s payload;
};

struct unf_gid_s {
	struct unf_ctiu_prem_s ctiu_pream;
	unsigned int scope_type;
};

struct unf_gid_acc_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ctiu_prem_s ctiu_pream;
};

#define UNF_LOOPMAP_COUNT 128
struct unf_loop_init_s {
	struct unf_fchead_s frame_hdr;
	unsigned int cmnd;
#define UNF_FC_ALPA_BIT_MAP_SIZE 4
	unsigned int alpa_bit_map[UNF_FC_ALPA_BIT_MAP_SIZE];
};

struct unf_loop_map_s {
	struct unf_fchead_s frame_hdr;
	unsigned int cmnd;
	unsigned int loop_map[32];
};

struct unf_ctiu_rjt_s {
	struct unf_fchead_s frame_hdr;
	struct unf_ctiu_prem_s ctiu_pream;
};

struct unf_gif_acc_pld_s {
	struct unf_ctiu_prem_s ctiu_pream;

	unsigned int gid_port_id[UNF_GID_PORT_CNT];
};

struct unf_gid_rsp_s {
	struct unf_gif_acc_pld_s *gid_acc_pld;
};

struct unf_gid_req_rsp_s {
	struct unf_fchead_s frame_hdr;
	struct unf_gid_s gid_req;
	struct unf_gid_rsp_s gid_rsp;
};

/* Added by fangtao   FC-LS-2 Table 31 RSCN Payload */
struct unf_rscn_port_id_page_s {
	unsigned char port_id_port;
	unsigned char port_id_area;
	unsigned char port_id_domain;

	unsigned char addr_format : 2;
	unsigned char event_qualifier : 4;
	unsigned char reserved : 2;
};

struct unf_rscn_pld_s {
	unsigned int cmnd;
	struct unf_rscn_port_id_page_s port_id_page[UNF_RSCN_PAGE_SUM];
};

struct unf_rscn_s {
	struct unf_fchead_s frame_hdr;
	struct unf_rscn_pld_s *rscn_pld;
};

union unf_sfs_u {
	struct {
		struct unf_fchead_s frame_head;
		unsigned char data[0];
	} sfs_common;
	struct unf_abts_rsps_s abts_rsps;
	struct unf_els_acc_s els_acc;
	struct unf_els_rjt_s els_rjt;
	struct unf_plogi_pdisc_s plogi;
	struct unf_logo_s logo;
	struct unf_echo_s echo;
	struct unf_echo_s echo_acc;
	struct unf_prli_prlo_s prli;
	struct unf_prli_prlo_s prlo;
	struct unf_rls_s rls;
	struct unf_rls_acc_s rls_acc;
	struct unf_plogi_pdisc_s pdisc;
	struct unf_adisc_s adisc;
	struct unf_rrq_s rrq;
	struct unf_flogi_fdisc_acc_s flogi;
	struct unf_fdisc_acc_s fdisc;
	struct unf_scr_s scr;
	struct unf_rec_s rec;
	struct unf_rec_acc_s rec_acc;
	struct unf_srr_s srr;
	struct unf_srr_acc_s srr_acc;
	struct unf_ls_rjt_s ls_rjt;
	struct unf_rscn_s rscn;
	struct unf_gid_req_rsp_s get_id;
	struct unf_rftid_s rft_id;
	struct unf_rft_rsp_s rft_id_rsp;
	struct unf_rffid_s rff_id;
	struct unf_rffid_rsp_s rff_id_rsp;
	struct unf_gffid_s gff_id;
	struct unf_gffid_rsp_s gff_id_rsp;
	struct unf_gnnid_s gnn_id;
	struct unf_gnnid_rsp_s gnn_id_rsp;
	struct unf_gpnid_s gpn_id;
	struct unf_gpnid_rsp_s gpn_id_rsp;
	struct unf_plogi_pdisc_s plogi_acc;
	struct unf_plogi_pdisc_s pdisc_acc;
	struct unf_adisc_s adisc_acc;
	struct unf_prli_prlo_s prli_acc;
	struct unf_prli_prlo_s prlo_acc;
	struct unf_flogi_fdisc_acc_s flogi_acc;
	struct unf_fdisc_acc_s fdisc_acc;
	struct unf_loop_init_s lpi;
	struct unf_loop_map_s loopmap;
	struct unf_ctiu_rjt_s ctiu_rjt;
};

struct unf_sfs_entry_s {
	/* Virtual addr of SFS buffer */
	union unf_sfs_u *fc_sfs_entry_ptr;
	/* Physical addr of SFS buffer */
	unsigned long long sfs_buff_phy_addr;
	/* Length of bytes in SFS buffer */
	unsigned int sfs_buff_len;
	unsigned int cur_offset;
};

struct unf_fcp_rsp_iu_entry_s {
	struct unf_fcprsp_iu_s *fcp_rsp_iu;
	dma_addr_t fcp_rsp_iu_phy_addr;
};

struct unf_rjt_info_s {
	unsigned int els_cmnd_code;
	unsigned int reason_code;
	unsigned int reason_explanation;
};

int unf_alloc_scsi_host(unf_scsi_host_s **v_scsi_host,
			struct unf_host_param_s *v_host_param);
void unf_free_scsi_host(unf_scsi_host_s *v_scsi_host);
unsigned int unf_register_ini_transport(void);
void unf_unregister_ini_transport(void);
void unf_report_io_dm_event(void *v_lport, unsigned int type,
			    unsigned int value);
void unf_save_sense_data(void *scsicmd, const char *sense, int senslen);

#endif
