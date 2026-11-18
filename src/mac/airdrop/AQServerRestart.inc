/* A protocol switch reuses the receiver. Mavericks' AirDropUnpublished handler
 * deliberately ignores notifications from that same receiver, so a start while
 * its old CFHTTPServer is closing will never be retried by the native daemon.
 * Keep the restart pending until its publisher has been retired. */
static ptrdiff_t server_publisher_offset;
static NSHashTable *restarting_servers;
static void cancel_server_restart(id server) {
    [restarting_servers removeObject:server];
}
static void restart_server(id server) {
    [active_servers addObject:server];
    if(!restarting_servers) restarting_servers=[NSHashTable weakObjectsHashTable];
    [restarting_servers addObject:server];
    if(*(void **)((char *)(__bridge void *)server+server_publisher_offset)) {
        // A peer may still hold the stopped listener open. Preserve its drain
        // until shutdown completes, including when switching out of native mode.
        drain_after_stop(server);
        return;
    }
    cancel_server_restart(server);
    // Full start restores _startTime and native publication state. Calling
    // startHTTPServer directly after stop leaves publishedInfoChanged: disabled.
    SEL start=@selector(start);
    ((void (*)(id,SEL))[server methodForSelector:start])(server,start);
}
static void install_server_restart_observer(void) {
    [[NSNotificationCenter defaultCenter] addObserverForName:@"com.apple.sharingd.AirDropUnpublished"
        object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *note) {
        id server=note.object;
        if([restarting_servers containsObject:server] && [active_servers containsObject:server])
            restart_server(server);
    }];
}
