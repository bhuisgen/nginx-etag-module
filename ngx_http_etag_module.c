/*
 * ngx_http_etag_module.c
 *
 *  Created on: 15 juil. 2010
 *      Author: bhuisgen
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
	ngx_uint_t enable;
	ngx_str_t file;
} ngx_http_etag_loc_conf_t;


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
//static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static void * ngx_http_etag_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_etag_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_etag_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_etag_header_filter(ngx_http_request_t *r);

static ngx_command_t  ngx_http_etag_commands[] = {
		{
				ngx_string( "etag" ),
				NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
				ngx_conf_set_flag_slot,
				NGX_HTTP_LOC_CONF_OFFSET,
				offsetof(ngx_http_etag_loc_conf_t, enable),
				NULL },
		{
				ngx_string( "etag_file"),
				NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
				ngx_conf_set_str_slot,
				NGX_HTTP_LOC_CONF_OFFSET,
				offsetof(ngx_http_etag_loc_conf_t, file),
				NULL },
		ngx_null_command
};

static ngx_http_module_t  ngx_http_etag_module_ctx = {
		NULL,							/* preconfiguration */
		ngx_http_etag_init,				/* postconfiguration */
		NULL,							/* create main configuration */
		NULL,							/* init main configuration */
		NULL,							/* create server configuration */
		NULL,							/* merge server configuration */
		ngx_http_etag_create_loc_conf,	/* create location configuration */
		ngx_http_etag_merge_loc_conf,	/* merge location configuration */
};

ngx_module_t  ngx_http_etag_module = {
		NGX_MODULE_V1,
		&ngx_http_etag_module_ctx,		/* module context */
		ngx_http_etag_commands,			/* module directives */
		NGX_HTTP_MODULE,				/* module type */
		NULL,							/* init master */
		NULL,							/* init module */
		NULL,							/* init process */
		NULL,							/* init thread */
		NULL,							/* exit thread */
		NULL,							/* exit process */
		NULL,							/* exit master */
		NGX_MODULE_V1_PADDING
};

static void * ngx_http_etag_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_etag_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_etag_loc_conf_t));
    if (conf == NULL) {
    	return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET_UINT;

    return conf;
}

static char * ngx_http_etag_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_etag_loc_conf_t *prev = parent;
    ngx_http_etag_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->enable, prev->enable, 0);
    if ((conf->enable != 0) && (conf->enable != 1)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "etag must be 'on' or 'off'");

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_str_value(conf->file, prev->file, "");

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_etag_init(ngx_conf_t *cf) {
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_etag_header_filter;

    return NGX_OK;
}

static ngx_int_t ngx_http_etag_header_filter(ngx_http_request_t *r) {
	ngx_http_etag_loc_conf_t *loc_conf;
	ngx_log_t *log;

	loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_etag_module);
	log = r->connection->log;

	if (loc_conf->enable == 1) {
		ngx_http_core_loc_conf_t *clcf;
		ngx_str_t path;
		ngx_open_file_info_t of;

		if (loc_conf->file.len > 0) {
			path.data = loc_conf->file.data;
			path.len = loc_conf->file.len;
		} else {
			size_t root;
			u_char *p;

			p = ngx_http_map_uri_to_path(r, &path, &root, 0);
			if (p == NULL) {
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
		}

		clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
		of.test_dir = 0;
		of.valid = clcf->open_file_cache_valid;
		of.min_uses = clcf->open_file_cache_min_uses;
		of.errors = clcf->open_file_cache_errors;
		of.events = clcf->open_file_cache_events;

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "etag file: %V", &path);

		if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
				== NGX_OK) {
			ngx_str_t etag;

			etag.data = ngx_palloc(r->pool, sizeof(of.size) + sizeof(of.mtime)
					+ 1);
			if (etag.data == NULL) {
				ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
						"[etag] failed to allocate memory");

				return NGX_ERROR;
			}

			etag.len = ngx_sprintf(etag.data, "%T%z", of.mtime, of.size)
							- etag.data;
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http etag file: %V", &path); ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http etag generated: %V", &etag);

			r->headers_out.etag = ngx_list_push(&r->headers_out.headers);
			if (r->headers_out.etag == NULL) {
				return NGX_ERROR;
			}

			r->headers_out.etag->hash = 1;
			r->headers_out.etag->key.data = (u_char *) "Etag";
			r->headers_out.etag->key.len = sizeof("Etag") - 1;
			r->headers_out.etag->value.data = etag.data;
			r->headers_out.etag->value.len = etag.len;

			r->headers_out.last_modified_time = of.mtime;

			ngx_list_part_t *part;
			ngx_table_elt_t *header;
			ngx_uint_t i;

			part = &r->headers_in.headers.part;
			header = part->elts;

			for (i = 0;; i++) {
				if (i >= part->nelts) {
					if (part->next == NULL) {
						break;
					}

					part = part->next;
					header = part->elts;
					i = 0;
				}

				if (ngx_strcmp(header[i].key.data, "If-None-Match") == 0) {
					if (ngx_strncmp(r->headers_out.etag->value.data,
							header[i].value.data,
							r->headers_out.etag->value.len) == 0) {
						r->headers_out.status = NGX_HTTP_NOT_MODIFIED;
						r->headers_out.content_type.len = 0;

						ngx_http_clear_content_length(r);
						ngx_http_clear_accept_ranges(r);
					}

					break;
				}
			}
		}
	}

    return ngx_http_next_header_filter(r);
}
