#include <pthread.h>
#include <errno.h> 
#include <stdio.h>
#include <string.h>
#include <coap3/coap.h>
#include <ldns/ldns.h>
#include "lib/resolve.h" 
#include "lib/module.h"
#include "daemon/worker.h"
#include "lib/rplan.h"


// TODO remove later with Markus function
extern struct kr_context *the_resolver;

// TODO replace with Markus function, currently only for debugging purposes
void resolveQuestion(knot_dname_t *qname, ldns_rr_type rr_type, ldns_rr_class rr_class) {
    printf("[DEBUG] Starting resolveExample()\n");

    // create request
    struct kr_request req = {0};
    req.pool.ctx = mp_new(4096);

    if (!req.pool.ctx) {
        printf("[ERROR] Failed to create memory pool\n");
        return;
    }
    req.pool.alloc = (knot_mm_alloc_t)mp_alloc;

    // create packet and link it to request
    knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, &req.pool);
    if (!pkt) {
        printf("[ERROR] Failed to create packet\n");
        mp_delete(req.pool.ctx);
        return;
    }
    req.qsource.packet = pkt; 
    printf("[DEBUG] Packet created successfully\n");

    // add question-section to packet 
    // TODO use rr_type and rr_class
    int ret = knot_pkt_put_question(pkt, qname, rr_class, rr_type);
    if (ret != KNOT_EOK) {
        printf("[ERROR] Failed to put question in packet, error: %d\n", ret);
        return;
    }

    // start knot resolvers resolution process 
    printf("[DEBUG] Starting resolution process \n");
    int state = kr_resolve_begin(&req, the_resolver);
    if (state != KR_STATE_CONSUME) {
        printf("[ERROR] Failed resolution, state: %d\n", state);
        mp_delete(req.pool.ctx);
        return;
    }

    // state should be PRODUCE after consume - currently not working :( 
    state = kr_resolve_consume(&req, NULL, pkt);
    printf("[DEBUG] Consume state: %d\n", state);
    
    // Generate answer
    while (state == KR_STATE_PRODUCE) {
        state = kr_resolve_produce(&req, NULL, req.answer);
        while (state == KR_STATE_CONSUME){
            state = kr_resolve_consume(&req, NULL, req.answer);
        }
    }
    
    // kr_request_ensure_answer(&req);
    kr_resolve_finish(&req, state);

    // TODO imrpove output
    // print result
    printf("Response code: %d\n", req.answer->wire[3] & 0x0F); // lower 4 bits
    if (state == KR_STATE_DONE) {
        printf("\n=== Resolution Result ===\n");
        printf("Transaction ID: 0x%02x%02x\n", req.answer->wire[0], req.answer->wire[1]);
        printf("Flags: 0x%02x\n", req.answer->wire[2]);
        printf("Response code: %d\n", req.answer->wire[3] & 0x0F); // lower 4 bits
        
        const knot_pktsection_t *ans = knot_pkt_section(req.answer, KNOT_ANSWER);
        printf("\nAnswer section %d:\n", ans->count);
        for (uint16_t i = 0; i < ans->count; i++) {
            const knot_rrset_t *rr = knot_pkt_rr(ans, i);
            printf("Name: %s\n",rr->ttl);
            char buff[512] = {0};
            size_t buff_len = sizeof(buff);
            int ret = knot_rrset_txt_dump(rr, buff, &buff_len, &KNOT_DUMP_STYLE_DEFAULT);
            if (ret == 0) {
                printf("%s", buff);
            }
        }
    } else {
        printf("Final state: %d\n", state);
    }
    kr_resolve_finish(&req, state);
    mp_delete(req.pool.ctx);
    printf("[DEBUG] resolve completed\n");
}

static void handler_coap_request(coap_resource_t *resource, coap_session_t *session, const coap_pdu_t *receivedPdu, const coap_string_t *query, coap_pdu_t *response) {
    printf("\n--- New CoAP-Request ---\n");
    const uint8_t *buffer;
    size_t len, off, total;

    if (!coap_get_data_large(receivedPdu, &len, &buffer, &off, &total)) {
        printf("No response.\n");
        return;
    }

    // printf("PDU\n");
    // coap_show_pdu(LOG_INFO, receivedPdu);
    
    // convert pdu to ldns packet
    const uint16_t* data = (const uint16_t*)buffer;
    ldns_buffer *ldnsBuffer;
    ldns_pkt *pkt;
    ldnsBuffer = ldns_buffer_new(512);
    ldns_buffer_write(ldnsBuffer, data, len);
    ldns_buffer2pkt_wire(&pkt, ldnsBuffer);
    ldns_rr_list *rrList = ldns_pkt_question(pkt);
    
    // no question-section in packet -> nothing todo
    if(rrList->_rr_count <= 0){
        return;
    }
    
    // extract domain name, record/class type from question
    ldns_rr *question = ldns_rr_list_rr(rrList, 0);
    char* domain_str = ldns_rdf2str(ldns_rr_owner(question));
    ldns_rr_type rr_type = ldns_rr_get_type(question);
    ldns_rr_class rr_class = ldns_rr_get_class(question);
    
    printf("Domain: \n %s, Type: %d \n Class: %d \n", domain_str, rr_type, rr_class);

    
    knot_dname_t *qname = knot_dname_from_str_alloc(domain_str);
    if (!qname) {
        printf("[ERROR] Failed to allocate qname\n");
        free(domain_str); 
        return;
    }
    free(domain_str); 

    // resolve requested record and return resolved data to client
    resolveQuestion(qname, rr_type, rr_class);

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

/* Convenience macro to declare module ABI. */
KR_MODULE_EXPORT(coap)