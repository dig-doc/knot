#include <pthread.h>
#include <errno.h> 
#include <stdio.h>
#include <string.h>
#include <ccan/json/json.h>
#include <coap3/coap.h>
#include <ldns/ldns.h>
#include "lib/module.h"
#include "lib/defines.h"

typedef struct {
    char* host;
    uint16_t port;
} coap_config_t;

static coap_config_t config = {
    .host = "127.0.0.1",
    .port = 53
};


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


KR_EXPORT int coap_init(struct kr_module *module) {
	/* Create a thread and start it in the background. */
    printf("HIER IST DIE INIT FUNKTION\n");
	pthread_t thr_id;
	int ret = pthread_create(&thr_id, NULL, &run_coap_server, NULL);
	if (ret != 0) {
        printf("[ERROR] Failed to create thread: %s\n", strerror(errno));
		return kr_error(errno);
	}
	/* Keep it in the thread */
	module->data = (void*) thr_id;
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

static int find_int(const JsonNode *node, int **val) {
    if (!node || !node->key || kr_fails_assert(node->tag == JSON_NUMBER)) {
        return kr_error(EINVAL);
    }
    if (node->number_ < INT_MIN || node->number_ > INT_MAX) {
        return kr_error(ERANGE);
    }
    if (kr_fails_assert(*val != NULL)) {
        return kr_error(errno);
    }

    int int_val = (int) node->number_;
    *val = &int_val;
    return kr_ok();
}

KR_EXPORT int coap_config(struct kr_module *module, const char *conf) {
    printf("HIER IST DIE CONFIG");
    if (!conf) {
        return kr_ok();
    }

    char* host = "127.0.0.1";
    int default_port = KR_DNS_PORT;
    int* port = &default_port;

    if (strlen(conf) < 1) {
        config.host = strdup(host);
        config.port = port;
    } else {
        JsonNode *root_node = json_decode(conf);
        if (!root_node) {
            return kr_error(EINVAL);
        }

        JsonNode *node;
        node = json_find_member(root_node, "host");
        if (!node || find_string(node, &host, PATH_MAX) != kr_ok()) {
            config.host = strdup(host);
        }

        node = json_find_member(root_node, "port");
        if (!node || find_int(node, &port) != kr_ok()) {
            config.port = port;
        }

        json_delete(root_node);
    }

    // Config apply

    return kr_ok();
}

/* Convenience macro to declare module ABI. */
KR_MODULE_EXPORT(coap)