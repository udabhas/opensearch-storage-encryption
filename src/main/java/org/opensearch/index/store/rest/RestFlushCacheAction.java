/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.rest;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.POST;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.store.CryptoDirectoryFactory;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

/**
 * Flush API for the storage-encryption plugin.
 *
 * <p>{@code POST /_plugins/_opensearch_storage_encryption/_flush_cache} synchronously clears ALL
 * node-level plugin caches (L2 block cache, L1 radix tables, per-shard encryption metadata/footer
 * cache, node FileChannel cache), then requests GC and polls the MemorySegmentPool's in-use buffer
 * count until it settles — so the next read is served cold (from disk + decrypted afresh).
 *
 * <p>Purpose: force a genuinely COLD cryptofs cache for benchmarking (cold-vs-cold search
 * comparisons vs mmapfs). NODE-SCOPED: runs on the node that receives the request; single-node
 * benchmark harness only. Returns a JSON body with before/after counters so the caller can VERIFY
 * the pool actually drained rather than trusting a fire-and-forget.
 */
public class RestFlushCacheAction extends BaseRestHandler {

    private static final String ACTION_NAME = "flush_cache_action";
    private static final String ROUTE_PATH = "/_plugins/_opensearch_storage_encryption/_flush_cache";

    @Override
    public String getName() {
        return ACTION_NAME;
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(POST, ROUTE_PATH));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        // Node-local, synchronous: do the flush and build the response directly. The flush blocks
        // (GC + poll, bounded ~10s) which is acceptable for a between-iterations admin call.
        final Map<String, Object> result = CryptoDirectoryFactory.flushAllCaches();
        return channel -> {
            XContentBuilder builder = channel.newBuilder();
            builder.startObject();
            builder.field("acknowledged", true);
            for (Map.Entry<String, Object> e : result.entrySet()) {
                builder.field(e.getKey(), e.getValue());
            }
            builder.endObject();
            channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));
        };
    }
}
