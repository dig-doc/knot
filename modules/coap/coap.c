#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <coap3/coap.h>
#include <ldns/ldns.h>
#include "lib/module.h"
#include "daemon/engine.h"
#include <ccan/json/json.h>


int resolveQuestion(char *qname, ldns_rr_type rr_type, ldns_rr_class rr_class, coap_session_t *session, coap_pdu_t *response) {
    printf("[DEBUG] Starting resolveQuestion()\n");

    ldns_resolver *res = NULL;
    ldns_rdf *ns = NULL;
    ldns_buffer *buf = NULL;

    // point to knot-resolver
    ns = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "127.0.0.1");
    res = ldns_resolver_new();
    ldns_resolver_push_nameserver(res, ns);
    ldns_resolver_set_port(res, 53);

    // check if resolver is set
    if(!res) {
        printf("[ERROR] Failed to create resolver\n");
        ldns_resolver_deep_free(res);
        ldns_rdf_deep_free(ns);
        return kr_ok();
    }

    // dns paket
    ldns_rdf *domain = ldns_dname_new_frm_str(qname);
    ldns_pkt *q = ldns_pkt_query_new(domain, rr_type, rr_class, LDNS_RD);
    buf = ldns_buffer_new(512);
    ldns_pkt2buffer_wire(buf, q);

    // dns answer
    ldns_pkt *answer;
    ldns_status s = ldns_resolver_send_pkt(&answer, res, q);
    if (s != LDNS_STATUS_OK) {
        printf("Error: %s\n", ldns_get_errorstr_by_id(s));
        ldns_resolver_deep_free(res);
        ldns_rdf_deep_free(ns);
        ldns_rdf_deep_free(domain);
        ldns_pkt_free(q);
        ldns_buffer_free(buf);
        return kr_ok();
    }

    // create new empty buffer
    ldns_buffer *bufdns = ldns_buffer_new(512); 

    // copy answer-data to buffer
    ldns_pkt2buffer_wire(bufdns, answer); 
    uint8_t *data = ldns_buffer_begin(bufdns);
    size_t len = ldns_buffer_position(bufdns);

    // add data befor headers - to improve speed
    coap_add_data(response, len, data);
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);

    // add coap related headers    
    coap_optlist_t *optlist = NULL;
    unsigned char buffer_coap[512];
    len = coap_encode_var_safe(buffer_coap, 512, 553);
    coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_CONTENT_FORMAT, len, buffer_coap));
    coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_ACCEPT, len, buffer_coap));
    coap_add_optlist_pdu(response, &optlist);
    
    // print answer
    ldns_pkt_print(stdout, answer);
    printf("\n");

    // free memory
    ldns_resolver_deep_free(res);
    ldns_rdf_deep_free(ns);
    ldns_rdf_deep_free(domain);
    ldns_pkt_free(q);
    ldns_buffer_free(buf);
    ldns_pkt_free(answer);
    ldns_buffer_free(bufdns);
    coap_delete_optlist(optlist);
    return kr_ok();
}

static void handler_coap_request(coap_resource_t *resource, coap_session_t *session, const coap_pdu_t *receivedPdu, const coap_string_t *query, coap_pdu_t *response) {
    printf("\n--- New CoAP-Request ---\n");
    const uint8_t *buffer = NULL;
    size_t len, off, total;

    // no data in pdu - do nothing
    if (!coap_get_data_large(receivedPdu, &len, &buffer, &off, &total)) {
        return;
    }

    // printf("PDU\n");
    // coap_show_pdu(LOG_INFO, receivedPdu);
    
    // convert pdu to ldns packet
    const uint16_t* data = (const uint16_t*)buffer;
    ldns_buffer *ldnsBuffer = NULL;
    ldns_pkt *pkt = NULL;
    ldnsBuffer = ldns_buffer_new(512);
    ldns_buffer_write(ldnsBuffer, data, len);
    ldns_buffer2pkt_wire(&pkt, ldnsBuffer);
    ldns_rr_list *rrList = ldns_pkt_question(pkt);
    
    // no question-section in packet -> nothing todo
    if(rrList->_rr_count <= 0){
        ldns_pkt_free(pkt);
        ldns_buffer_free(ldnsBuffer);
        return;
    }
    
    // extract domain name, record/class type from question
    ldns_rr *question = ldns_rr_list_rr(rrList, 0);
    char* domain_str = ldns_rdf2str(ldns_rr_owner(question));
    ldns_rr_type rr_type = ldns_rr_get_type(question);
    ldns_rr_class rr_class = ldns_rr_get_class(question);
    
    resolveQuestion(domain_str, rr_type, rr_class, session, response);

    free(domain_str); 
    ldns_pkt_free(pkt);
    ldns_buffer_free(ldnsBuffer);

}

static void* run_coap_server(void *arg) {
    coap_context_t  *ctx = NULL;
    coap_endpoint_t *endpoint = NULL;
    coap_resource_t *resource = NULL;
    coap_address_t serv_addr;
    int result;

    coap_startup();
    coap_address_init(&serv_addr);

    serv_addr.addr.sin.sin_family      = AF_INET;
    serv_addr.addr.sin.sin_addr.s_addr = INADDR_ANY;
    serv_addr.addr.sin.sin_port        = htons(5683);

    coap_set_log_level(LOG_DEBUG);

    ctx = coap_new_context(NULL);
    if (!ctx) {
        printf("[ERROR] Failed to create CoAP context\n");
        return;
    }

    endpoint = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_UDP);
    if (!endpoint) {
        printf("[ERROR] Failed to create endpoint\n");
        coap_free_context(ctx);
        return;
    }

    // uri-format: coap://localhost/dns
    resource = coap_resource_init(coap_make_str_const("dns"), 0);
    if (!resource) {
        printf("[ERROR] Failed to create resource\n");
        coap_free_context(ctx);
        return;
    }

    coap_register_handler(resource, COAP_REQUEST_FETCH, handler_coap_request);
    coap_resource_set_get_observable(resource, 1);
    coap_add_resource(ctx, resource);

    printf("[COAP] Server ready on port 5683!\n");

    while (1) {
        result = coap_io_process(ctx, 1000);
        if (result < 0) {
            break;
        }
    }

    coap_free_context(ctx);
    coap_cleanup();

    return;
}

// CONFIG BEGIN
struct kr_coap_settings {
    char* host;
    int port;
};

struct kr_coap_ctx {
    struct kr_coap_settings config;
};

static void kr_coap_ctx_init(struct kr_coap_ctx *ctx)
{
    if (!ctx) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));

    ctx->config.host = "127.0.0.1";
    ctx->config.port = 53;
}

int config_init(struct kr_coap_ctx *ctx)
{
    if (!ctx) {
        return kr_error(EINVAL);
    }

    kr_coap_ctx_init(ctx);

    return kr_ok();
}

void config_deinit(struct kr_coap_ctx *ctx)
{
    if (!ctx) {
        return;
    }

    free(ctx->config.host);
    ctx->config.host = NULL;

    free(ctx->config.port);
    ctx->config.port = NULL;
}

static void apply_changes(const JsonNode *host,
                          const JsonNode *port)
{
    if (kr_fails_assert(host && port)) {
        return;
    }

    kr_assert(host->tag == JSON_STRING);
    kr_assert(port->tag == JSON_NUMBER);

    // TODO: Apply to running process
    //host->string_;
    //(int) host->number_;
    printf(host->string_);
}

static bool config_apply_json(JsonNode *root_node)
{
    if (kr_fails_assert(root_node)) {
        return false;
    }

    const JsonNode *host = json_find_member(root_node, "host");
    const JsonNode *port = json_find_member(root_node, "port");

    apply_changes(host, port);

    return true;
}

bool config_apply(struct kr_coap_ctx *ctx, const char *args)
{
    if (!ctx) {
        return false;
    }

    if (!args || !strlen(args)) {
        return true;
    }

    if (!args || !strlen(args)) {
        return true;
    }

    JsonNode *root_node = json_decode(args);
    if (!root_node) {
        return false;
    }

    bool success = config_apply_json(root_node);

    json_delete(root_node);

    return success;
}

char *config_read(struct kr_coap_ctx *ctx)
{
    if (!ctx) {
        return NULL;
    }

    JsonNode *root_node = json_mkobject();
    if (!root_node) {
        return NULL;
    }

    json_append_member(root_node, "host", json_mkstring(ctx->config.host));
    json_append_member(root_node, "port", json_mknumber(ctx->config.port));

    char *result = json_encode(root_node);
    json_delete(root_node);
    return result;
}

static char *coap_config(void *env, struct kr_module *module, const char *args)
{
    struct kr_coap_ctx *coap_ctx = module->data;
    if (kr_fails_assert(coap_ctx)) {
        return NULL;
    }

    config_apply(coap_ctx, args);

    return config_read(coap_ctx);
}

// CONFIG END

KR_EXPORT int coap_init(struct kr_module *module) {
	/* Create a thread and start it in the background. */
	pthread_t thr_id;
	int ret = pthread_create(&thr_id, NULL, &run_coap_server, NULL);
	if (ret != 0) {
        printf("[ERROR] Failed to create thread: %s\n", strerror(errno));
		return kr_error(errno);
	}

	/* Keep it in the thread */
    // TODO: Fix
	//module->data = (void*) thr_id;

    struct engine *engine = module->data;
    struct kr_coap_ctx *coap_ctx = &engine->resolver.coap_ctx;

    int config_ret = config_init(coap_ctx);
    if (config_ret != kr_ok()) {
        return config_ret;
    }

    /* Replace engine pointer. */
    module->data = coap_ctx;

    return kr_ok();
}

KR_EXPORT int coap_deinit(struct kr_module *module) {
	/* ... signalize cancellation ... */
	void *res = NULL;
	pthread_t thr_id = (pthread_t) module->data;
	int ret = pthread_join(thr_id, &res);
	if (ret != 0) {
        printf("[ERROR] Failed to join thread: %s\n", strerror(errno));
		return kr_error(errno);
	}
	return kr_ok();
}


/* Convenience macro to declare module ABI. */
KR_MODULE_EXPORT(coap)
