#include "lib/module.h"

#include <lib/resolve.h>

#include <libknot/libknot.h>
#include <libknot/packet/pkt.h>
#include <libknot/dname.h>
#include <libknot/rrset.h>

int resolve() {
	struct kr_request request = {
		.pool = {
			.ctx = mp_new (4096),
			.alloc = (knot_mm_alloc_t) mp_alloc
		}
	};
	struct kr_context *ctx = mm_alloc(&request.pool, sizeof(*ctx));
	memset(ctx, 0, sizeof(*ctx));
	ctx->pool = &request.pool;

	knot_pkt_t *query = knot_pkt_new(NULL, 4096, &request.pool);
	knot_pkt_put_question(query, "agdsn.de", KNOT_CLASS_IN, KNOT_RRTYPE_A);

	// Setup and provide input query
	int state = kr_resolve_begin(&request, ctx);
	printf("%i", state);
	state = kr_resolve_consume(&request, NULL, query);

	// Generate answer
	while (state == KR_STATE_PRODUCE) {
		state = kr_resolve_produce(&request, NULL, query);
		while (state == KR_STATE_CONSUME) {
			state = kr_resolve_consume(&request, NULL, request.answer);
			knot_pkt_clear(request.answer);
		}
		knot_pkt_clear(query);
	}

	// "state" is either DONE or FAIL
	kr_resolve_finish(&request, state);
	return state;
}

KR_EXPORT int coap_init(struct kr_module *self)
{
	printf("%i", resolve());
	return kr_ok();
}

KR_EXPORT int coap_deinit(struct kr_module *self)
{
  	return kr_ok();
}

KR_MODULE_EXPORT(coap)

