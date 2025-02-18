#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ccan/json/json.h>
#include <coap3/coap.h>
#include <ldns/ldns.h>
#include "lib/module.h"
#include "lib/defines.h"


static ldns_resolver *g_resolver = NULL;
static ldns_rdf *g_ns = NULL;

typedef struct {
    char* host;
    u_int16_t port;
} coap_config_t;

static coap_config_t config = {
    .host = "127.0.0.1",
    .port = 53
};

int resolveQuestion(char *qname, ldns_rr_type rr_type, ldns_rr_class rr_class, coap_session_t *session, coap_pdu_t *response) {
                    
    printf("[DEBUG] resolveQuestion(%s)", qname);

    if (!g_resolver) {
        printf("[ERROR] Resolver nicht initialisiert\n");
        return kr_ok();
    }

    ldns_rdf *domain = ldns_dname_new_frm_str(qname);

    if (!domain) {
        printf("[ERROR] ldns_rdf fehlgeschlagen\n");
        return kr_ok();
    }

    ldns_pkt *q = ldns_pkt_query_new(domain, rr_type, rr_class, LDNS_RD);

    if (!q) {
        printf("[ERROR] *q fehlgeschlagen\n");
        ldns_rdf_deep_free(domain);
        return kr_ok();
    }

    ldns_buffer *buf = ldns_buffer_new(512);
    if (!buf) {
        printf("[ERROR] ldns_buffer_new() fehlgeschlagen\n");
        ldns_pkt_free(q);
        ldns_rdf_deep_free(domain);
        return kr_ok();
    }

    ldns_pkt2buffer_wire(buf, q);
    ldns_pkt *answer = NULL;
    ldns_status s = ldns_resolver_send_pkt(&answer, g_resolver, q);

    if (s != LDNS_STATUS_OK) {
        printf("[ERROR] ldns_resolver_send_pkt() fehlgeschlagen: %s\n", ldns_get_errorstr_by_id(s));
        ldns_rdf_deep_free(domain);
        ldns_pkt_free(q);
        ldns_buffer_free(buf);
        return kr_ok();
    }
    ldns_buffer *bufdns = ldns_buffer_new(512);

    if (!bufdns) {
        printf("[ERROR] ldns_buffer_new() fehlgeschlagen\n");
        ldns_pkt_free(answer);
        ldns_rdf_deep_free(domain);
        ldns_pkt_free(q);
        ldns_buffer_free(buf);
        return kr_ok();
    }

    ldns_pkt2buffer_wire(bufdns, answer);
    uint8_t *data = ldns_buffer_begin(bufdns);
    size_t len = ldns_buffer_position(bufdns);
    
    // optlist
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_optlist_t *optlist = NULL;
    unsigned char buffer_coap[512];
    size_t opt_len = coap_encode_var_safe(buffer_coap, sizeof(buffer_coap), 553);
    coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_CONTENT_FORMAT, opt_len, buffer_coap));
    coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_ACCEPT, opt_len, buffer_coap));
    coap_add_optlist_pdu(response, &optlist);
    // payload
    coap_add_data(response, len, data);

    // debug:
    ldns_pkt_print(stdout, answer);

    ldns_rdf_deep_free(domain);
    ldns_pkt_free(answer);

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
    ldns_buffer *ldnsBuffer = ldns_buffer_new(512);

    if (!ldnsBuffer) {
        return;
    }

    ldns_buffer_write(ldnsBuffer, buffer, len);
    ldns_pkt *pkt = NULL;
    ldns_buffer2pkt_wire(&pkt, ldnsBuffer);

    if (!pkt) {
        ldns_buffer_free(ldnsBuffer);
        return;
    }

    ldns_rr_list *rrList = ldns_pkt_question(pkt);
    if (!rrList) {
        ldns_pkt_free(pkt);
        ldns_buffer_free(ldnsBuffer);
        return;
    }

    // no question-section in packet -> nothing todo
    if(rrList->_rr_count <= 0){
        ldns_pkt_free(pkt);
        ldns_buffer_free(ldnsBuffer);
        return;
    }

    // extract domain name, record/class type from question
    ldns_rr *question = ldns_rr_list_rr(rrList, 0);

    if (!question) {
        ldns_pkt_free(pkt);
        ldns_buffer_free(ldnsBuffer);
        return;
    }

    char *domain_str = ldns_rdf2str(ldns_rr_owner(question));
    if (!domain_str) {
        ldns_pkt_free(pkt);
        ldns_buffer_free(ldnsBuffer);
        return;
    }

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
        return NULL;
    }

    endpoint = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_UDP);
    if (!endpoint) {
        printf("[ERROR] Failed to create endpoint\n");
        coap_free_context(ctx);
        return NULL;
    }

    // uri-format: coap://localhost/dns
    resource = coap_resource_init(coap_make_str_const("dns"), 0);
    if (!resource) {
        printf("[ERROR] Failed to create resource\n");
        coap_free_context(ctx);
        return NULL;
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

    return NULL;
}


KR_EXPORT int coap_init(struct kr_module *module) {
	
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

    if (g_resolver) {
        ldns_resolver_deep_free(g_resolver);
        g_resolver = NULL;
    }

    return kr_ok();
}

static int find_string(const JsonNode *node, char **val, size_t len) {
    if (!node || !node->key || kr_fails_assert(node->tag == JSON_STRING)) {
	return kr_error(EINVAL);
    }
    *val = strndup(node->string_, len);
    if (kr_fails_assert(*val != NULL)) {
        return kr_error(errno);
    }
    return kr_ok();
}

static int find_int(const JsonNode *node, u_int16_t **val) {
    if (!node || !node->key || kr_fails_assert(node->tag == JSON_NUMBER)) {
        return kr_error(EINVAL);
    }
    if (node->number_ < 0 || node->number_ > USHRT_MAX) {
        return kr_error(ERANGE);
    }
    if (kr_fails_assert(*val != NULL)) {
        return kr_error(errno);
    }

    u_int16_t int_val = (u_int16_t) node->number_;
    **val = int_val;
    return kr_ok();
}

KR_EXPORT int coap_config(struct kr_module *module, const char *conf) {
    char* host = "127.0.0.1";
    u_int16_t default_port = KR_DNS_PORT;
    u_int16_t* port = &default_port;

    if (!conf || strlen(conf) < 1) {
        config.host = strdup(host);
        config.port = *port;
    } else {
        JsonNode *root_node = json_decode(conf);
        if (!root_node) {
            return kr_error(EINVAL);
        }

        JsonNode *node;
        node = json_find_member(root_node, "host");
        if (!node || find_string(node, &host, PATH_MAX) == kr_ok()) {
            config.host = strdup(host);
        }

        node = json_find_member(root_node, "port");
        if (!node || find_int(node, &port) == kr_ok()) {
            config.port = *port;
        }

        json_delete(root_node);
    }

    g_ns = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, config.host);
    if (!g_ns) {
        return kr_error(errno);
    }
    g_resolver = ldns_resolver_new();
    if (!g_resolver) {
        ldns_rdf_deep_free(g_ns);
        return kr_error(errno);
    }
    ldns_resolver_push_nameserver(g_resolver, g_ns);
    ldns_resolver_set_port(g_resolver, config.port);
    printf("[DEBUG] ldns-Resolver: host=%s, port=%u\n", config.host, config.port);

    pthread_t thr_id;
    int ret = pthread_create(&thr_id, NULL, &run_coap_server, NULL);
    if (ret != 0) {
        return kr_error(errno);
    }
    module->data = (void*) thr_id;
    return kr_ok();
}

KR_MODULE_EXPORT(coap)