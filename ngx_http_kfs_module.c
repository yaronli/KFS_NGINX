/*
 * Author: liyangguang <liyangguang@software.ict.ac.cn>
 * http://www.yaronspace.cn/blog
 *
 * File: ngx_http_kfs_module.c
 * Create Date: 2011-11-21 14:29:43
 *
 * nginx kfs upload download module
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>

#include "kfs_api.h"

#define OUTPUT_BUFFER_SIZE (64*1024)

typedef struct kfs_http_range {

    int64_t start;
    int64_t end;

} kfs_http_range_t;


typedef struct {
    ngx_uint_t kfs_enable;
    ngx_str_t  kfs_host;
    ngx_uint_t kfs_port;
    ngx_str_t  kfs_user;
    ngx_str_t  kfs_pwd;
    ngx_str_t  kfs_base_dir;
    ngx_uint_t kfs_is_connected;

} ngx_http_kfs_loc_conf_t;


static char *ngx_http_kfs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_kfs_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_kfs_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);

static int kfs_strtoll(const char *s, int64_t *value);
static int kfs_parse_range(const char *value, kfs_http_range_t *range);

/** kfs http handler function */
static ngx_int_t ngx_http_kfs_handler(ngx_http_request_t *r);

/** kfs client init */
static ngx_int_t ngx_http_kfs_init(ngx_http_kfs_loc_conf_t *lcf);


/** following function about HTTP Range Handler */
static int 
kfs_format_content_range(const kfs_http_range_t *range, \
	const int64_t file_size, char *content_range);


static ngx_int_t 
kfs_set_content_range(ngx_http_request_t *r, char *content_range, const int content_range_len);

static ngx_int_t 
kfs_set_header(ngx_http_request_t *r, \
	const char *key, const char *low_key, const int key_len, \
	char *value, const int value_len);

static ngx_int_t
kfs_set_accept_ranges(ngx_http_request_t *r);

/** format readdir result to json */
static int
kfs_gen_json_content(const char filename_list[][KFS_FILENAME_MAX_LEN], const char filetype_list[][5], const int file_cnt, char *json_content);


/** format time */
static int kfs_format_http_datetime(time_t t, char *buff, const int buff_size);

static ngx_command_t ngx_http_kfs_commands[] = {
    {
        ngx_string("kfs_enable"),
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_http_kfs,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL 
    },

    {
        ngx_string("kfs_host"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_kfs_loc_conf_t, kfs_host),
        NULL
    },

    {
        ngx_string("kfs_port"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_kfs_loc_conf_t, kfs_port),
        NULL
    },

    {
        ngx_string("kfs_user"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_kfs_loc_conf_t, kfs_user),
        NULL
    },
    {
        ngx_string("kfs_pwd"), 
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_kfs_loc_conf_t, kfs_pwd),
        NULL
    },
    {
        ngx_string("kfs_base_dir"), 
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_kfs_loc_conf_t, kfs_base_dir),
        NULL
    },

    ngx_null_command

};


static ngx_http_module_t  ngx_http_kfs_module_ctx = {
    NULL,                           /* preconfiguration */
    NULL,                           /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_kfs_create_loc_conf  /* create location configuration */
    //ngx_http_kfs_merge_loc_conf /* merge location configuration */
};

ngx_module_t  ngx_http_kfs_module = {
    NGX_MODULE_V1,
    &ngx_http_kfs_module_ctx,      /* module context */
    ngx_http_kfs_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_kfs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf = NULL;    
    ngx_http_kfs_loc_conf_t  *klcf = conf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_kfs_handler;
    
    klcf->kfs_enable = 1;
    klcf->kfs_is_connected = 0;
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "set ngx_http_kfs handler.");



    return NGX_CONF_OK;
}

static void *
ngx_http_kfs_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_kfs_loc_conf_t *klcf = NULL;

    klcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_kfs_loc_conf_t));

    if (klcf == NULL) {
        return NGX_CONF_ERROR;
    }
    klcf->kfs_port = NGX_CONF_UNSET_UINT;

    return klcf;
}


static char *
ngx_http_kfs_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_kfs_loc_conf_t *prev = parent;
    ngx_http_kfs_loc_conf_t *conf = child;
    ngx_conf_merge_str_value(conf->kfs_host, prev->kfs_host, "");
    ngx_conf_merge_uint_value(conf->kfs_port, prev->kfs_port, 0);
    ngx_conf_merge_str_value(conf->kfs_user, prev->kfs_user, "");
    ngx_conf_merge_str_value(conf->kfs_pwd, prev->kfs_pwd, "");
    ngx_conf_merge_str_value(conf->kfs_base_dir, prev->kfs_base_dir, "");

    if (conf->kfs_host.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "kfs_host is null.");
        return NGX_CONF_ERROR;
    }

    if (conf->kfs_port ==0 || conf->kfs_port > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "kfs_port is not valid.");
        return NGX_CONF_ERROR;
    }

    if (conf->kfs_user.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "kfs_user is null.");
        return NGX_CONF_ERROR;
    }

    if (conf->kfs_pwd.len ==0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "kfs_pwd is null.");
        return NGX_CONF_ERROR;
    }

    if (conf->kfs_base_dir.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "kfs_base_dir is null."); 
        return NGX_CONF_ERROR;
    }
    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "merge config. [kfs_host:%s] [kfs_port:%u] [kfs_user:%s][kfs_pwd:%s] [kfs_base_dir:%s]",
        conf->kfs_host.data, conf->kfs_port, conf->kfs_user.data, conf->kfs_pwd.data, conf->kfs_base_dir.data);


    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_kfs_handler(ngx_http_request_t *r)
{
    ngx_int_t      rc;
    ngx_buf_t      *buffer = NULL;
    ngx_chain_t    out;
    ngx_str_t      uri_path;
    int            if_range = 0;
#define KFS_PATH_MAX_LEN 1024
    char kfs_path[KFS_PATH_MAX_LEN];
    char new_kfs_path[KFS_PATH_MAX_LEN];
    char content_range[KFS_PATH_MAX_LEN];
    int  content_range_len = 0;
    memset(kfs_path, 0, sizeof(kfs_path));
    memset(new_kfs_path, 0, sizeof(new_kfs_path));
    memset(content_range, 0, sizeof(content_range));

    const char *output_content_type = "application/octet-stream";
    char * chunk_data;
    kfs_http_range_t range;
    ngx_http_kfs_loc_conf_t *klcf = NULL; 
    ngx_http_core_loc_conf_t *clcf = NULL;
    struct stat st;    
    int i = 0, len = 0, idx = 0;
    int all_recv_cnt = 0;
    int recv_cnt;
    int ret = 0;
    int chunks_cnt = 0, fd = 0, last_chunk_size = 0, once_read_size = 0;
    
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    klcf = ngx_http_get_module_loc_conf(r, ngx_http_kfs_module);
    if (klcf->kfs_is_connected != 1) {
            
        ret = kfs_init(klcf->kfs_host.data, klcf->kfs_port, klcf->kfs_user.data, klcf->kfs_pwd.data);
        if (ret == 0) {

            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Kfs MetaServer Connect Failed."); 

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        klcf->kfs_is_connected = 1;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }

    uri_path = r->uri;
    memcpy(kfs_path, klcf->kfs_base_dir.data, klcf->kfs_base_dir.len);
    memcpy(kfs_path + klcf->kfs_base_dir.len, "/", 1);
    //if (uri_path.len - clcf->name.len < 1) {
    //    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
    //        "url path error.[uri_path:%s]", uri_path.data);

    //    return NGX_HTTP_BAD_REQUEST;
    //    
    //}
    memcpy(kfs_path + klcf->kfs_base_dir.len + 1, uri_path.data + clcf->name.len, uri_path.len - clcf->name.len);
    //过滤path 路径
    len = strlen(kfs_path);
    idx = 0;
    for (i = 0; i < len; ++i) {
        if (i > 0 && kfs_path[i] == '/') {
            if (new_kfs_path[idx-1] != '/') {
                new_kfs_path[idx++] = kfs_path[i];
            }
        }
        else {
            new_kfs_path[idx++] = kfs_path[i];
        }
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "parse uri path.[uri_path:%s] [kfs_path:%s]",
            uri_path.data, new_kfs_path);
    ret = kfs_stat(new_kfs_path, &st);
    if (ret != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "kfs_stat error. [kfs_path:%s]", new_kfs_path);

        return NGX_HTTP_NOT_FOUND;
    }
    if (S_ISDIR(st.st_mode)) {
        //TODO:need to readdir
        char filename_list[KFS_FILE_MAX_CNT][KFS_FILENAME_MAX_LEN];
        char filetype_list[KFS_FILE_MAX_CNT][5];
        int file_cnt = 0;
        ret = kfs_readdir(new_kfs_path, filename_list, filetype_list, &file_cnt);
        if (ret < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                "readdir error.. [kfs_path:%s]", new_kfs_path);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        buffer = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        chunk_data = ngx_pcalloc(r->pool, OUTPUT_BUFFER_SIZE);            
        /** SEND　HEADERs */
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = kfs_gen_json_content(filename_list, filetype_list, file_cnt, chunk_data);

        r->headers_out.content_type.len = strlen("application/json");
        r->headers_out.content_type.data = (u_char *)"application/json";

        rc = ngx_http_send_header(r);

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_send_header() error.");
            return NGX_HTTP_BAD_REQUEST;
        }
        buffer->pos = (u_char *)chunk_data;
        buffer->last = (u_char *)chunk_data + r->headers_out.content_length_n;
        buffer->memory = 1;
        buffer->last_buf = 1;
        out.buf = buffer;
        out.next = NULL;

        /* Send the Chunk */
        rc = ngx_http_output_filter(r, &out);
        return rc;
    }//end if ISDIR
    

    char modified_time[1024];
    kfs_format_http_datetime(st.st_mtime, modified_time, 1024);
    kfs_set_header(r, "Last-Modified", "last-modified", \
            sizeof("Last-Modified") - 1, modified_time, strlen(modified_time));

    if (r->headers_in.if_modified_since != NULL)
    {
        if (strlen(r->headers_in.if_modified_since) > 0
            && strcmp(r->headers_in.if_modified_since, modified_time) == 0) 
        {
            r->headers_out.status = NGX_HTTP_NOT_MODIFIED;
            rc = ngx_http_send_header(r);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_send_header() error.");
                return NGX_HTTP_BAD_REQUEST;
            }

            return NGX_OK;
        }
    }
    
	if (r->headers_in.range != NULL)
	{
		char buff[64];
		if (r->headers_in.range->value.len >= sizeof(buff))
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, \
				"bad request, range length: %d exceeds buff " \
				"size: %d, range: %*s", \
				r->headers_in.range->value.len, \
				(int)sizeof(buff), \
				r->headers_in.range->value.len, \
				r->headers_in.range->value.data);
			return NGX_HTTP_BAD_REQUEST;
		}

		memcpy(buff, r->headers_in.range->value.data, \
				r->headers_in.range->value.len);
		*(buff + r->headers_in.range->value.len) = '\0';
		if (kfs_parse_range(buff, &range) != 0)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, \
				"bad request, invalid range: %s", buff);
			return NGX_HTTP_BAD_REQUEST;
		}
		if_range = 1;
	}
#if 1 
    //SEND THE HEADERS
    r->headers_out.status = NGX_HTTP_OK;
    if (!if_range) {
        r->headers_out.content_length_n = st.st_size; 
    }
    else {
        //bytes=-500
        if (range.start < 0) {
            r->headers_out.content_length_n = 0 - range.start;
            range.start = st.st_size + range.start;
            range.end = st.st_size - 1;
        }
        //bytes=500-
        else if (range.end == 0) {
            r->headers_out.content_length_n = st.st_size - range.start;
            range.end = st.st_size - 1;
        }
        //bytes=500-999
        else {
            r->headers_out.content_length_n = range.end - range.start + 1;
        }
    }
    r->headers_out.content_type.len = strlen(output_content_type);
    r->headers_out.content_type.data = (u_char *)output_content_type;

    rc = kfs_set_accept_ranges(r);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "kfs_set_accept_ranges() error.");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (if_range) {
        content_range_len = kfs_format_content_range(&range, st.st_size, content_range);
        rc = kfs_set_content_range(r, content_range, content_range_len);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_set_content_range() error.");
            return NGX_HTTP_BAD_REQUEST;
            
        }
    }

    rc = ngx_http_send_header(r);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_send_header() error.");
        return NGX_HTTP_BAD_REQUEST;
    }


    //SEND THE BODY
    fd = kfs_open(new_kfs_path, O_RDONLY); 
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "open kfs file error.[kfs_path:%s]",
                new_kfs_path);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (if_range) {
        ret = kfs_lseek(fd, range.start, SEEK_SET);
        if (ret < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "lseek kfs file error.[kfs_path:%s] [offset:%lld]",
                new_kfs_path, range.start);
            kfs_close(fd);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
            
        }
    }


    chunks_cnt = r->headers_out.content_length_n / OUTPUT_BUFFER_SIZE;
    if (r->headers_out.content_length_n % OUTPUT_BUFFER_SIZE != 0) {
        chunks_cnt += 1;
        last_chunk_size = r->headers_out.content_length_n % OUTPUT_BUFFER_SIZE;
    }
    else {
        last_chunk_size = OUTPUT_BUFFER_SIZE;
    }
    for (i = 0;i < chunks_cnt; ++i) {
        buffer = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        chunk_data = ngx_pcalloc(r->pool, OUTPUT_BUFFER_SIZE);            
        if (chunk_data == NULL || buffer == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "Failed to allocate response buffer");
            kfs_close(fd);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        once_read_size = (i == chunks_cnt -1) ? last_chunk_size : OUTPUT_BUFFER_SIZE;
        do{
            recv_cnt = kfs_read(fd, chunk_data, once_read_size);
            if (recv_cnt < 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "kfs_read error.");

                kfs_close(fd);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            all_recv_cnt += recv_cnt;

        }while (all_recv_cnt < once_read_size);

        buffer->pos = (u_char *)chunk_data;
        buffer->last = (u_char *)chunk_data + once_read_size;
        buffer->memory = 1;
        buffer->last_buf = (i == chunks_cnt - 1);
        out.buf = buffer;
        out.next = NULL;

        /* Serve the Chunk */
        rc = ngx_http_output_filter(r, &out);

        /* TODO: More Codes to Catch? */
        if (rc == NGX_ERROR) {
            kfs_close(fd);
            return NGX_ERROR;
        }
    } 
    kfs_close(fd);
#endif
    return rc;

}



static int kfs_strtoll(const char *s, int64_t *value)
{
	char *end = NULL;
	*value = strtoll(s, &end, 10);
	if (end != NULL && *end != '\0')
	{
		return EINVAL;
	}

	return 0;
}

static int 
kfs_parse_range(const char *value, kfs_http_range_t *range)
{
/*
range format:
bytes=500-999
bytes=-500
bytes=9500-
*/
#define RANGE_PREFIX_STR  "bytes="
#define RANGE_PREFIX_LEN   (int)(sizeof(RANGE_PREFIX_STR) - 1)

	int len;
	int result;
	const char *p;
	const char *pEndPos;
	char buff[32];

	len = strlen(value);
	if (len <= RANGE_PREFIX_LEN + 1)
	{
		return EINVAL;
	}

	p = value + RANGE_PREFIX_LEN;
	if (*p == '-')
	{
		if ((result=kfs_strtoll(p, &(range->start))) != 0)
		{
			return result;
		}
		range->end = 0;
		return 0;
	}

	pEndPos = strchr(p, '-');
	if (pEndPos == NULL)
	{
		return EINVAL;
	}

	len = pEndPos - p;
	if (len >= (int)sizeof(buff))
	{
		return EINVAL;
	}
	memcpy(buff, p, len);
	*(buff + len) = '\0';
	if ((result=kfs_strtoll(buff, &(range->start))) != 0)
	{
		return result;
	}

	pEndPos++; //skip -
	if (*pEndPos == '\0')
	{
		range->end = 0;
	}
	else
	{
		if ((result=kfs_strtoll(pEndPos, &(range->end))) != 0)
		{
			return result;
		}
	}

	return 0;
}



static ngx_int_t 
kfs_set_header(ngx_http_request_t *r, \
	const char *key, const char *low_key, const int key_len, \
	char *value, const int value_len)
{
	ngx_table_elt_t  *cc;

	cc = ngx_list_push(&r->headers_out.headers);
	if (cc == NULL)
	{
		return NGX_ERROR;
    }

	cc->hash = 1;
	cc->key.len = key_len;
	cc->key.data = (u_char *)key;
	cc->lowcase_key = (u_char *)low_key;
	cc->value.len = value_len;
	cc->value.data = (u_char *)value;

	return NGX_OK;
}


static ngx_int_t 
kfs_set_content_range(ngx_http_request_t *r, char *content_range, const int content_range_len)
{
	return kfs_set_header(r, "Content-Range", "content-range", \
		sizeof("Content-Range") - 1, content_range, \
		content_range_len);
}

static int
kfs_format_content_range(const kfs_http_range_t *range, \
	const int64_t file_size, char *content_range)
{
#ifndef INT64_PRINTF_FORMAT
#define INT64_PRINTF_FORMAT "%lld"
#endif

	return sprintf(content_range, \
		"bytes "INT64_PRINTF_FORMAT"-"INT64_PRINTF_FORMAT \
		"/"INT64_PRINTF_FORMAT, range->start, range->end, file_size);
}



static ngx_int_t 
kfs_set_accept_ranges(ngx_http_request_t *r)
{
	return kfs_set_header(r, "Accept-Ranges", "accept-ranges", \
		sizeof("Accept-Ranges") - 1, "bytes", sizeof("bytes") - 1);
}




static int
kfs_gen_json_content(const char filename_list[][KFS_FILENAME_MAX_LEN], const char filetype_list[][5], const int file_cnt, char *json_content)
{
    int i = 0, idx = 0;
    json_content[idx++] = '[';
    for (i = 0; i< file_cnt; ++i) {
        json_content[idx++] = '{';
        memcpy(json_content + idx, "\"name\":\"", 8); 
        idx += 8;
        memcpy(json_content + idx, filename_list[i], strlen(filename_list[i]));
        idx += strlen(filename_list[i]);
        json_content[idx++] = '\"';
        json_content[idx++] = ',';

        memcpy(json_content + idx, "\"type\":\"", 8); 
        idx += 8;
        memcpy(json_content + idx, filetype_list[i], strlen(filetype_list[i]));
        idx += strlen(filetype_list[i]);
        json_content[idx++] = '\"';
        json_content[idx++] = '}';
        json_content[idx++] = ',';
    }
    if (file_cnt > 0) {
        //Romove last comma
        json_content[idx-1] = ']';
    }
    else {
        json_content[idx++] = ']';
    }
    return idx;
}


static int kfs_format_http_datetime(time_t t, char *buff, const int buff_size)
{
	struct tm tm;
	struct tm *ptm;

	*buff = '\0';
	if ((ptm=gmtime_r(&t, &tm)) == NULL)
	{
		return errno != 0 ? errno : EFAULT;
	}

	strftime(buff, buff_size, "%a, %d %b %Y %H:%M:%S GMT", ptm);
	return 0;
}






/* vim: set ts=4 sw=4: */

